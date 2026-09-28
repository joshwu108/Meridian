package svid

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"log"
	"net/url"
	"time"
)

// Signer abstracts the CA issuance RPC. The production implementation calls
// the control-plane FetchSVID gRPC; tests and standalone mode use LocalSigner.
type Signer interface {
	// Sign validates the DER-encoded CSR and returns the signed leaf + chain.
	Sign(ctx context.Context, csrDER []byte, spiffeID string) ([]*x509.Certificate, error)
}

// rotateAt controls when rotation is scheduled: 2/3 of the remaining TTL,
// matching the architecture decision (D7 / subsystem-04 PKI-1).
const rotateFraction = 2.0 / 3.0

// nearExpiryFraction is the fail-closed window: when less than 1/6 of the
// total TTL remains the SVID is considered near-expired and new connections
// must be refused (CC-5).
const nearExpiryFraction = 1.0 / 6.0

// SVIDManager drives the SVID lifecycle for one workload identity:
//
//  1. Generate an ECDSA P-256 key.
//  2. Build a CSR with a single URI SAN equal to spiffeID.
//  3. Call Signer.Sign.
//  4. Store the result in *Store.
//  5. Sleep until 2/3 of the TTL has elapsed.
//  6. Repeat from 1 (make-before-break: the new cert is stored before the old
//     one expires, so no window exists where the proxy holds an expired cert).
//
// On a transient Sign failure the SVIDManager logs and retries after the
// remaining safe window. On ctx cancellation it returns nil.
// SVIDManager implements the Manager interface from doc.go.
type SVIDManager struct {
	spiffeID string
	signer   Signer
	store    *Store
	logf     func(string, ...any)
	nowFn    func() time.Time
	afterFn  func(time.Duration) <-chan time.Time
	forceCh  chan *rotateRequest
}

// rotateRequest is one ForceRotate call in flight; the rotation loop sends
// exactly one result on reply.
type rotateRequest struct {
	reply chan rotateResult
}

type rotateResult struct {
	expiry time.Time
	err    error
}

// Option configures a SVIDManager.
type Option func(*SVIDManager)

// WithLogf overrides the logger (default log.Printf).
func WithLogf(logf func(string, ...any)) Option {
	return func(m *SVIDManager) {
		if logf != nil {
			m.logf = logf
		}
	}
}

// withNow overrides the clock — for unit tests only.
func withNow(fn func() time.Time) Option {
	return func(m *SVIDManager) { m.nowFn = fn }
}

// withAfter overrides the rotation/backoff timer — for unit tests only (D7:
// paired with withNow so the whole lifecycle runs on a fake clock).
func withAfter(fn func(time.Duration) <-chan time.Time) Option {
	return func(m *SVIDManager) { m.afterFn = fn }
}

// NewManager constructs a Manager for spiffeID. Call Start to begin the
// lifecycle loop.
// compile-time proof that SVIDManager satisfies the Manager interface.
var _ Manager = (*SVIDManager)(nil)

// NewManager constructs a SVIDManager for spiffeID. Call Start to begin the
// lifecycle loop.
func NewManager(spiffeID string, signer Signer, store *Store, opts ...Option) *SVIDManager {
	m := &SVIDManager{
		spiffeID: spiffeID,
		signer:   signer,
		store:    store,
		logf:     log.Printf,
		nowFn:    time.Now,
		afterFn:  time.After,
		forceCh:  make(chan *rotateRequest),
	}
	for _, o := range opts {
		o(m)
	}
	return m
}

// Start issues the initial SVID (returning an error on failure — fail-closed
// on first issuance) and then runs the rotation loop until ctx is cancelled.
func (m *SVIDManager) Start(ctx context.Context) error {
	entry, err := m.issue(ctx)
	if err != nil {
		return fmt.Errorf("svid manager: initial issuance for %q: %w", m.spiffeID, err)
	}
	m.store.Set(entry)
	m.logf("svid: issued %q expires=%s", m.spiffeID, entry.ExpiresAt.Format(time.RFC3339))

	for {
		delay := m.nextRotateDelay(entry)
		var req *rotateRequest
		select {
		case <-ctx.Done():
			return nil
		case <-m.afterFn(delay):
		case req = <-m.forceCh:
		}

		next, err := m.issue(ctx)
		if err != nil {
			if req != nil {
				req.reply <- rotateResult{err: err}
			}
			m.logf("svid: rotation failed for %q: %v; will retry", m.spiffeID, err)
			// Back off by a small fixed window; the next iteration re-computes delay.
			select {
			case <-ctx.Done():
				return nil
			case <-m.afterFn(30 * time.Second):
			}
			continue
		}
		m.store.Set(next)
		m.logf("svid: rotated %q expires=%s", m.spiffeID, next.ExpiresAt.Format(time.RFC3339))
		if req != nil {
			req.reply <- rotateResult{expiry: next.ExpiresAt}
		}
		entry = next
	}
}

// ForceRotate asks the rotation loop to rotate NOW, bypassing the 2/3-TTL
// schedule, and returns the new SVID's expiry. It backs the agent admin
// POST /cert/rotate endpoint (meridian cert rotate). If the rotation loop is
// not running, it fails when ctx expires rather than rotating out-of-band —
// the loop stays the sole writer of the store.
func (m *SVIDManager) ForceRotate(ctx context.Context) (time.Time, error) {
	req := &rotateRequest{reply: make(chan rotateResult, 1)}
	select {
	case m.forceCh <- req:
	case <-ctx.Done():
		return time.Time{}, fmt.Errorf("svid: force rotate %q: rotation loop not accepting requests: %w", m.spiffeID, ctx.Err())
	}
	select {
	case res := <-req.reply:
		if res.err != nil {
			return time.Time{}, fmt.Errorf("svid: force rotate %q: %w", m.spiffeID, res.err)
		}
		return res.expiry, nil
	case <-ctx.Done():
		return time.Time{}, fmt.Errorf("svid: force rotate %q: %w", m.spiffeID, ctx.Err())
	}
}

// GetSVID returns the current SVID, failing closed when none has been issued
// yet or the current one is inside the near-expiry window (CC-5): callers are
// never handed a cert that could expire mid-handshake.
func (m *SVIDManager) GetSVID() (*Entry, error) {
	e := m.store.Current()
	if e == nil {
		return nil, fmt.Errorf("svid: no SVID issued yet for %q (fail closed)", m.spiffeID)
	}
	if m.NearExpiry() {
		return nil, fmt.Errorf("svid: SVID for %q is near expiry (expires %s); refusing to serve it (fail closed)",
			m.spiffeID, e.ExpiresAt.Format(time.RFC3339))
	}
	return e, nil
}

// Stop is a no-op; cancel the context passed to Start to stop the manager.
func (m *SVIDManager) Stop(_ context.Context) error { return nil }

// NearExpiry reports whether the current SVID has less than 1/6 of its
// lifetime remaining. Callers (the node proxy) should fail-close new
// connections when true, per CC-5.
func (m *SVIDManager) NearExpiry() bool {
	e := m.store.Current()
	if e == nil {
		return true
	}
	total := e.Leaf.NotAfter.Sub(e.Leaf.NotBefore)
	if total <= 0 {
		return true
	}
	remaining := e.ExpiresAt.Sub(m.nowFn())
	return remaining < time.Duration(float64(total)*nearExpiryFraction)
}

// nextRotateDelay returns how long to sleep before rotating entry.
// It is rotateFraction of the remaining TTL (bounded to zero).
func (m *SVIDManager) nextRotateDelay(e *Entry) time.Duration {
	remaining := e.ExpiresAt.Sub(m.nowFn())
	if remaining <= 0 {
		return 0
	}
	d := time.Duration(float64(remaining) * rotateFraction)
	if d < 0 {
		return 0
	}
	return d
}

// issue generates a fresh P-256 key, creates a CSR, and calls the Signer.
func (m *SVIDManager) issue(ctx context.Context) (*Entry, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate P-256 key: %w", err)
	}
	u, err := url.Parse(m.spiffeID)
	if err != nil {
		return nil, fmt.Errorf("parse SPIFFE ID %q: %w", m.spiffeID, err)
	}
	tmpl := &x509.CertificateRequest{
		URIs: []*url.URL{u},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}
	chain, err := m.signer.Sign(ctx, csrDER, m.spiffeID)
	if err != nil {
		return nil, err
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("signer returned empty chain")
	}
	leaf := chain[0]
	return &Entry{
		SpiffeID:  m.spiffeID,
		Leaf:      leaf,
		Key:       key,
		Chain:     chain,
		ExpiresAt: leaf.NotAfter,
	}, nil
}
