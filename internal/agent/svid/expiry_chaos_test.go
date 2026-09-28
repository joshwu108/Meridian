package svid

// T1 cert-expiry chaos tests (no infra): drive the SVIDManager lifecycle with
// a fake clock (D7 nowFn + afterFn injection) and assert the fail-closed
// contracts — near-expiry refusal, rotation at 2/3 TTL, retry without serving
// a stale cert, and make-before-break atomicity.

import (
	"context"
	"crypto/x509"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/joshuawu/meridian/internal/control/ca"
)

// fakeClock is a deterministic clock: Now returns the frozen time, After
// registers a timer that fires when Advance moves the clock past it.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	timers []*fakeTimer
}

type fakeTimer struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &fakeTimer{at: c.now.Add(d), ch: make(chan time.Time, 1)}
	if d <= 0 {
		t.ch <- c.now
		return t.ch
	}
	c.timers = append(c.timers, t)
	return t.ch
}

// Advance moves the clock forward and fires every timer whose deadline passed.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	var pending []*fakeTimer
	for _, t := range c.timers {
		if t.at.After(c.now) {
			pending = append(pending, t)
			continue
		}
		t.ch <- c.now
	}
	c.timers = pending
}

func (c *fakeClock) pendingTimers() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.timers)
}

// waitFor polls cond on a real-time deadline (the fake clock never blocks it).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func quietLogf(string, ...any) {}

// startManager launches m.Start and waits for the initial SVID.
func startManager(t *testing.T, m *SVIDManager, store *Store) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = m.Start(ctx) }()
	waitFor(t, "initial SVID issuance", func() bool { return store.Current() != nil })
	return cancel
}

// TestNearExpiryFailsClosed: within 1 minute of expiry, GetSVID must return
// an error rather than the stale cert (CC-5 fail-closed).
func TestNearExpiryFailsClosed(t *testing.T) {
	clk := newFakeClock(time.Now())
	store := NewStore()
	store.Set(makeTestEntry(t, "spiffe://x/svc", 24*time.Hour))

	m := NewManager("spiffe://x/svc", &testSigner{}, store,
		WithLogf(quietLogf), withNow(clk.Now))

	if _, err := m.GetSVID(); err != nil {
		t.Fatalf("GetSVID() on a fresh 24h SVID: %v, want success", err)
	}

	clk.Advance(24*time.Hour - time.Minute) // 1 minute before expiry
	e, err := m.GetSVID()
	if err == nil {
		t.Fatalf("GetSVID() = entry expiring %s, want fail-closed error within 1m of expiry",
			e.ExpiresAt.Format(time.RFC3339))
	}
}

// TestRotationAt2_3TTL: with a 24h-TTL SVID, advancing the clock just past
// 16h (2/3 TTL) must trigger a rotation.
func TestRotationAt2_3TTL(t *testing.T) {
	signer := newTestSigner(t)
	store := NewStore()
	clk := newFakeClock(time.Now())
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "chaos", "rotate")

	m := NewManager(spiffeID, signer, store,
		WithLogf(quietLogf), withNow(clk.Now), withAfter(clk.After))
	startManager(t, m, store)
	first := store.Current()

	waitFor(t, "rotation timer to be armed", func() bool { return clk.pendingTimers() == 1 })
	clk.Advance(16*time.Hour + 10*time.Minute) // just past 2/3 of 24h

	waitFor(t, "rotation to complete", func() bool { return store.Current() != first })
	if got := signer.calls.Load(); got != 2 {
		t.Fatalf("signer calls = %d, want 2 (initial + one rotation)", got)
	}
}

// failFromSigner delegates to inner for the first (from-1) calls, then fails
// every subsequent call — a control plane that goes down after initial issuance.
type failFromSigner struct {
	inner Signer
	from  int32 // calls numbered >= from fail
	calls atomic.Int32
}

func (s *failFromSigner) Sign(ctx context.Context, csrDER []byte, spiffeID string) ([]*x509.Certificate, error) {
	if s.calls.Add(1) >= s.from {
		return nil, errors.New("injected: control plane down")
	}
	return s.inner.Sign(ctx, csrDER, spiffeID)
}

// TestControlPlaneDownDuringRotation: when every rotation attempt fails, the
// manager must keep retrying and must NOT serve the cert once it goes stale.
func TestControlPlaneDownDuringRotation(t *testing.T) {
	signer := &failFromSigner{inner: newTestSigner(t), from: 2}
	store := NewStore()
	clk := newFakeClock(time.Now())
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "chaos", "cp-down")

	m := NewManager(spiffeID, signer, store,
		WithLogf(quietLogf), withNow(clk.Now), withAfter(clk.After))
	startManager(t, m, store)

	// Trigger the scheduled rotation; it fails.
	waitFor(t, "rotation timer to be armed", func() bool { return clk.pendingTimers() == 1 })
	clk.Advance(16*time.Hour + 10*time.Minute)
	waitFor(t, "failed rotation attempt", func() bool { return signer.calls.Load() >= 2 })

	// The manager must arm a retry: a 30s backoff, then a re-computed
	// 2/3-of-remaining rotation delay (≈5h13m of the ~7h50m left).
	waitFor(t, "retry backoff timer to be armed", func() bool { return clk.pendingTimers() == 1 })
	clk.Advance(31 * time.Second)
	waitFor(t, "re-computed rotation timer to be armed", func() bool { return clk.pendingTimers() == 1 })
	clk.Advance(6 * time.Hour)
	waitFor(t, "rotation retry", func() bool { return signer.calls.Load() >= 3 })

	// Push the clock past the original cert's expiry: the stale cert must not
	// be served (fail closed), even though rotation never succeeded.
	clk.Advance(9 * time.Hour)
	e, err := m.GetSVID()
	if err == nil {
		t.Fatalf("GetSVID() served a cert expiring %s after clock passed expiry; want fail-closed error",
			e.ExpiresAt.Format(time.RFC3339))
	}
}

// gatedSigner blocks the second and later Sign calls until release is closed,
// holding a rotation "in flight" so the make-before-break window is observable.
type gatedSigner struct {
	inner   Signer
	calls   atomic.Int32
	entered chan struct{} // signalled when a gated call begins
	release chan struct{} // close to let gated calls proceed
}

func (s *gatedSigner) Sign(ctx context.Context, csrDER []byte, spiffeID string) ([]*x509.Certificate, error) {
	if s.calls.Add(1) >= 2 {
		select {
		case s.entered <- struct{}{}:
		default:
		}
		<-s.release
	}
	return s.inner.Sign(ctx, csrDER, spiffeID)
}

// TestMakeBeforeBreak: while rotation is in flight, GetSVID must keep
// returning the OLD (still valid) cert, then atomically switch to the new one.
func TestMakeBeforeBreak(t *testing.T) {
	signer := &gatedSigner{
		inner:   newTestSigner(t),
		entered: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	store := NewStore()
	clk := newFakeClock(time.Now())
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "chaos", "mbb")

	m := NewManager(spiffeID, signer, store,
		WithLogf(quietLogf), withNow(clk.Now), withAfter(clk.After))
	startManager(t, m, store)

	old, err := m.GetSVID()
	if err != nil {
		t.Fatalf("GetSVID() before rotation: %v", err)
	}

	// Kick off the rotation and hold the signer mid-flight.
	waitFor(t, "rotation timer to be armed", func() bool { return clk.pendingTimers() == 1 })
	clk.Advance(16*time.Hour + 10*time.Minute)
	select {
	case <-signer.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("rotation never reached the signer")
	}

	// Rotation in flight: the old cert must still be served.
	during, err := m.GetSVID()
	if err != nil {
		t.Fatalf("GetSVID() during rotation: %v, want old cert to remain available", err)
	}
	if during != old {
		t.Fatalf("GetSVID() during rotation returned a different entry; want the old cert until the new one is ready")
	}

	// Release the signer; the store must switch atomically to the new cert.
	close(signer.release)
	waitFor(t, "new SVID to be stored", func() bool { return store.Current() != old })

	fresh, err := m.GetSVID()
	if err != nil {
		t.Fatalf("GetSVID() after rotation: %v", err)
	}
	if fresh.Leaf.SerialNumber.Cmp(old.Leaf.SerialNumber) == 0 {
		t.Fatal("rotated SVID has the same serial as the old one; rotation did not mint a new cert")
	}
}

// TestForceRotateImmediate: ForceRotate bypasses the 2/3-TTL schedule, and
// reports the new expiry (backs POST /cert/rotate, Task 1).
func TestForceRotateImmediate(t *testing.T) {
	signer := newTestSigner(t)
	store := NewStore()
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "chaos", "force")

	m := NewManager(spiffeID, signer, store, WithLogf(quietLogf))
	startManager(t, m, store)
	first := store.Current()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	expiry, err := m.ForceRotate(ctx)
	if err != nil {
		t.Fatalf("ForceRotate: %v", err)
	}
	cur := store.Current()
	if cur == first {
		t.Fatal("ForceRotate returned but the store still holds the old SVID")
	}
	if !expiry.Equal(cur.ExpiresAt) {
		t.Fatalf("ForceRotate expiry = %s, want the stored SVID's expiry %s", expiry, cur.ExpiresAt)
	}
	if got := signer.calls.Load(); got != 2 {
		t.Fatalf("signer calls = %d, want 2 (initial + forced rotation)", got)
	}
}

// TestForceRotateWithoutLoop: with no rotation loop running, ForceRotate must
// fail once its context expires rather than hang or fabricate a rotation.
func TestForceRotateWithoutLoop(t *testing.T) {
	m := NewManager("spiffe://x/svc", &testSigner{}, NewStore(), WithLogf(quietLogf))

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := m.ForceRotate(ctx); err == nil {
		t.Fatal("ForceRotate succeeded with no rotation loop running; want error")
	}
}
