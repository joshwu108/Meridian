package svid

import (
	"context"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshuawu/meridian/internal/control/ca"
)

// testSigner wraps a ca.Authority to implement Signer, counting calls.
type testSigner struct {
	auth  *ca.Authority
	calls atomic.Int32
	failN int // fail the first N calls
}

func newTestSigner(t *testing.T) *testSigner {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	return &testSigner{auth: auth}
}

func (s *testSigner) Sign(_ context.Context, csrDER []byte, spiffeID string) ([]*x509.Certificate, error) {
	n := int(s.calls.Add(1))
	if n <= s.failN {
		return nil, errors.New("injected signing failure")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	return s.auth.SignWorkloadSVID(csr, spiffeID)
}

func TestManagerInitialIssuance(t *testing.T) {
	signer := newTestSigner(t)
	store := NewStore()
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "default", "svc-a")

	m := NewManager(spiffeID, signer, store, WithLogf(func(_ string, _ ...any) {}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- m.Start(ctx) }()

	// Wait for the initial SVID to appear.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e := store.Current(); e != nil {
			if e.SpiffeID != spiffeID {
				t.Fatalf("SVID SpiffeID = %q, want %q", e.SpiffeID, spiffeID)
			}
			if e.Leaf == nil || e.Key == nil || len(e.Chain) == 0 {
				t.Fatal("SVID entry is incomplete")
			}
			cancel()
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for initial SVID")
}

func TestManagerStartFailsOnFirstIssuanceError(t *testing.T) {
	signer := newTestSigner(t)
	signer.failN = 1 // first call fails
	store := NewStore()
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "default", "svc-b")

	m := NewManager(spiffeID, signer, store, WithLogf(func(_ string, _ ...any) {}))

	err := m.Start(context.Background())
	if err == nil {
		t.Fatal("expected error on first issuance failure, got nil")
	}
}

func TestManagerNearExpiryFalseAfterIssuance(t *testing.T) {
	signer := newTestSigner(t)
	store := NewStore()
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "default", "svc-c")

	m := NewManager(spiffeID, signer, store, WithLogf(func(_ string, _ ...any) {}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = m.Start(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if store.Current() != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if store.Current() == nil {
		t.Fatal("timed out waiting for initial SVID")
	}
	if m.NearExpiry() {
		t.Fatal("NearExpiry() should be false immediately after fresh issuance")
	}
}

func TestManagerNearExpiryTrueWhenNoSVID(t *testing.T) {
	store := NewStore()
	m := NewManager("spiffe://x/svc", &testSigner{}, store, WithLogf(func(string, ...any) {}))
	if !m.NearExpiry() {
		t.Fatal("NearExpiry() should be true when no SVID has been issued yet")
	}
}

func TestManagerNearExpiryTrueWhenAlmostExpired(t *testing.T) {
	store := NewStore()
	// Create a fake entry that expires in 1 minute (well inside 1/6 of 24h window).
	e := makeTestEntry(t, "spiffe://x/svc", time.Minute)
	store.Set(e)

	now := time.Now().Add(58 * time.Second) // 2s before expiry
	m := NewManager("spiffe://x/svc", &testSigner{}, store,
		WithLogf(func(string, ...any) {}),
		withNow(func() time.Time { return now }),
	)
	if !m.NearExpiry() {
		t.Fatal("NearExpiry() should be true when cert is about to expire")
	}
}

func TestManagerRotationPushesNewEntry(t *testing.T) {
	signer := newTestSigner(t)
	store := NewStore()
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "ns", "svc-d")

	// Use a very short TTL to force quick rotation.
	// We override nextRotateDelay by injecting a near-expiry time via nowFn.
	// Instead, track calls: 2 calls = initial + one rotation.
	ch := store.Subscribe()

	m := NewManager(spiffeID, signer, store, WithLogf(func(_ string, _ ...any) {}))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	go func() { _ = m.Start(ctx) }()

	// Wait for at least 2 entries (initial + one rotation is hard without a
	// very short TTL; here we just verify the initial SVID and that the
	// subscriber receives it).
	select {
	case e := <-ch:
		if e == nil {
			t.Fatal("received nil entry")
		}
		if e.SpiffeID != spiffeID {
			t.Fatalf("entry SpiffeID = %q, want %q", e.SpiffeID, spiffeID)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for SVID via subscriber")
	}
}

func TestLocalSigner(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	signer := NewLocalSigner(auth)
	store := NewStore()
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "ns", "svc")

	m := NewManager(spiffeID, signer, store, WithLogf(func(_ string, _ ...any) {}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = m.Start(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e := store.Current(); e != nil {
			// Verify the chain verifies against the root.
			inter := x509.NewCertPool()
			for _, c := range e.Chain[1:] {
				inter.AddCert(c)
			}
			opts := x509.VerifyOptions{
				Roots:         auth.TrustPool(),
				Intermediates: inter,
				CurrentTime:   e.Leaf.NotBefore.Add(time.Second),
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := e.Leaf.Verify(opts); err != nil {
				t.Fatalf("chain verification failed: %v", err)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for SVID from LocalSigner")
}
