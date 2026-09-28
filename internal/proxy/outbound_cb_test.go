package proxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/joshuawu/meridian/pkg/wire"
)

// seqResolver returns original destinations from a queue, one per connection,
// so a single handler can be driven against multiple upstreams.
type seqResolver struct {
	mu    sync.Mutex
	queue []netip.AddrPort
}

func (r *seqResolver) Resolve(net.Conn) (netip.AddrPort, wire.IdentityID, wire.IdentityID, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.queue) == 0 {
		return netip.AddrPort{}, 0, 0, errors.New("seqResolver: queue empty")
	}
	dst := r.queue[0]
	r.queue = r.queue[1:]
	return dst, 0, 0, nil
}

func (d *fakeDialer) dialCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.dialed)
}

func waitForDialCount(t *testing.T, d *fakeDialer, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.dialCount() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("dial count = %d, want %d within timeout", d.dialCount(), want)
}

// TestCBForLazyPerUpstream verifies that cbFor lazily creates one breaker per
// upstream address, returns the same instance on repeat access, and copies the
// template's configuration.
func TestCBForLazyPerUpstream(t *testing.T) {
	h := NewOutboundHandler(
		newFakeListener(), &fakeResolver{}, &fakeDialer{},
		WithCircuitBreaker(NewCircuitBreaker(3, 5*time.Second)),
	)

	a := netip.MustParseAddr("10.0.0.5")
	b := netip.MustParseAddr("10.0.0.6")

	cbA := h.cbFor(a)
	if cbA == nil {
		t.Fatal("cbFor returned nil with a template configured")
	}
	if got := h.cbFor(a); got != cbA {
		t.Fatal("cbFor must return the same breaker for the same upstream")
	}
	cbB := h.cbFor(b)
	if cbB == cbA {
		t.Fatal("cbFor must return distinct breakers per upstream")
	}
	if cbA.Threshold != 3 || cbA.ResetAfter != 5*time.Second {
		t.Fatalf("breaker config = (%d, %s), want template (3, 5s)",
			cbA.Threshold, cbA.ResetAfter)
	}
}

// TestCBForNilWithoutTemplate verifies that without WithCircuitBreaker the
// handler performs no circuit breaking (cbFor returns nil).
func TestCBForNilWithoutTemplate(t *testing.T) {
	h := NewOutboundHandler(newFakeListener(), &fakeResolver{}, &fakeDialer{})
	if cb := h.cbFor(netip.MustParseAddr("10.0.0.5")); cb != nil {
		t.Fatalf("cbFor without template = %v, want nil", cb)
	}
}

// TestOutboundPerUpstreamCircuitIsolation verifies that a tripped circuit for
// upstream A does not block dials to upstream B, and that A stays blocked.
func TestOutboundPerUpstreamCircuitIsolation(t *testing.T) {
	upA := netip.MustParseAddrPort("10.0.0.5:8080")
	upB := netip.MustParseAddrPort("10.0.0.6:9090")
	resolver := &seqResolver{queue: []netip.AddrPort{upA, upA, upB}}
	dialer := &fakeDialer{dialErr: errors.New("connection refused")}

	ln := newFakeListener()
	h := NewOutboundHandler(ln, resolver, dialer,
		WithOutboundLogf(func(string, ...any) {}),
		WithCircuitBreaker(NewCircuitBreaker(1, time.Hour)), // 1 failure → open
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	inject := func() {
		client, server := net.Pipe()
		ln.inject(server)
		_ = client.Close()
	}

	// Conn 1 → A: dial fails, A's circuit opens.
	inject()
	waitForDialCount(t, dialer, 1)

	// Conn 2 → A: circuit open, must NOT dial.
	inject()
	time.Sleep(100 * time.Millisecond)
	if got := dialer.dialCount(); got != 1 {
		t.Fatalf("dial count after open circuit = %d, want 1 (A blocked)", got)
	}

	// Conn 3 → B: independent circuit, dial proceeds.
	inject()
	waitForDialCount(t, dialer, 2)
	want := netip.AddrPortFrom(upB.Addr(), RemoteProxyPort)
	if got := dialer.lastDialed(); got != want {
		t.Fatalf("dialed %s, want %s (upstream B)", got, want)
	}

	states := h.CircuitStates()
	if states[upA.Addr()] != CBOpen {
		t.Fatalf("A state = %s, want open", states[upA.Addr()])
	}
	if states[upB.Addr()] != CBOpen {
		t.Fatalf("B state = %s, want open (its dial also failed)", states[upB.Addr()])
	}
}
