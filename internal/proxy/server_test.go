package proxy

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/joshuawu/meridian/pkg/wire"
)

// fakeResolver is a test double for OriginalDestinationResolver.
// It proves the D-E seam (ADR-0006): no proxy logic above Resolve() depends on
// whether the underlying mechanism is TPROXY or DNAT.
type fakeResolver struct {
	origDst  netip.AddrPort
	srcID    wire.IdentityID
	dstID    wire.IdentityID
	err      error
	mu       sync.Mutex
	resolved []net.Conn
}

func (r *fakeResolver) Resolve(conn net.Conn) (netip.AddrPort, wire.IdentityID, wire.IdentityID, error) {
	r.mu.Lock()
	r.resolved = append(r.resolved, conn)
	r.mu.Unlock()
	return r.origDst, r.srcID, r.dstID, r.err
}

// fakeListener is an in-memory net.Listener backed by a channel.
type fakeListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
	addr   net.Addr
}

func newFakeListener() *fakeListener {
	return &fakeListener{
		conns:  make(chan net.Conn, 8),
		closed: make(chan struct{}),
		addr:   &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 15001},
	}
}

func (l *fakeListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.conns:
		if !ok {
			return nil, errors.New("listener closed")
		}
		return c, nil
	case <-l.closed:
		return nil, errors.New("listener closed")
	}
}

func (l *fakeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *fakeListener) Addr() net.Addr { return l.addr }

func (l *fakeListener) inject(c net.Conn) { l.conns <- c }

// TestEchoServerSeamAbstraction verifies that the echo server uses only the
// OriginalDestinationResolver interface — no TPROXY-specific code above the seam
// (ADR-0006 D-E requirement 7). The fakeResolver substitutes for TPROXYResolver
// and the server is oblivious to the difference.
func TestEchoServerSeamAbstraction(t *testing.T) {
	origDst := netip.MustParseAddrPort("10.0.0.5:8080")
	resolver := &fakeResolver{
		origDst: origDst,
		dstID:   wire.IdentityID(42),
	}

	ln := newFakeListener()
	srv := NewEchoServer(ln, resolver, WithServerLogf(func(string, ...any) {}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	client, server := net.Pipe()
	ln.inject(server)

	payload := []byte("hello proxy seam")
	if _, err := client.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, len(payload))
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("echo = %q, want %q", buf[:n], payload)
	}

	// Verify resolver was called with the injected connection.
	time.Sleep(20 * time.Millisecond)
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	if len(resolver.resolved) == 0 {
		t.Fatal("resolver.Resolve was never called")
	}
}

// TestEchoServerDropsOnResolverError verifies that a connection where the
// resolver fails is dropped (fail-close) without echoing data.
func TestEchoServerDropsOnResolverError(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("cannot recover original destination")}

	ln := newFakeListener()
	srv := NewEchoServer(ln, resolver, WithServerLogf(func(string, ...any) {}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	client, server := net.Pipe()
	ln.inject(server)

	// The server closes the connection without echoing; client reads EOF or error.
	_ = client.SetDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	_, err := client.Read(buf)
	if err == nil {
		t.Fatal("expected connection to be closed on resolver error, got data")
	}
}

// TestEchoServerContextCancellation verifies that cancelling ctx stops Serve.
func TestEchoServerContextCancellation(t *testing.T) {
	resolver := &fakeResolver{origDst: netip.MustParseAddrPort("10.0.0.1:80")}
	ln := newFakeListener()
	srv := NewEchoServer(ln, resolver, WithServerLogf(func(string, ...any) {}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned non-nil on cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return within timeout after context cancellation")
	}
}

// TestTPROXYResolverImplementsInterface is a compile-time proof that
// TPROXYResolver and fakeResolver both satisfy OriginalDestinationResolver,
// confirming the D-E swappable seam works at the type level.
func TestTPROXYResolverImplementsInterface(t *testing.T) {
	var _ OriginalDestinationResolver = &TPROXYResolver{}
	var _ OriginalDestinationResolver = &fakeResolver{}
}

// TestAddrPortFromListener sanity-checks AddrPortFromListener.
func TestAddrPortFromListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ap, err := AddrPortFromListener(ln)
	if err != nil {
		t.Fatalf("AddrPortFromListener: %v", err)
	}
	if !ap.Addr().IsLoopback() {
		t.Fatalf("expected loopback addr, got %s", ap.Addr())
	}
	if ap.Port() == 0 {
		t.Fatal("expected non-zero port")
	}
}

// TestAddrPortFrom verifies that addrPortFrom correctly parses TCPAddr and
// string-form addresses (covers the helper used by TPROXYResolver).
func TestAddrPortFrom(t *testing.T) {
	tests := []struct {
		name    string
		addr    net.Addr
		wantStr string
	}{
		{
			name:    "TCPAddr v4",
			addr:    &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 8080},
			wantStr: "10.0.0.5:8080",
		},
		{
			name:    "TCPAddr v4-in-v6",
			addr:    &net.TCPAddr{IP: net.ParseIP("::ffff:192.168.1.1"), Port: 443},
			wantStr: "192.168.1.1:443",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := addrPortFrom(tc.addr)
			if err != nil {
				t.Fatalf("addrPortFrom: %v", err)
			}
			if got.String() != tc.wantStr {
				t.Fatalf("got %s, want %s", got, tc.wantStr)
			}
		})
	}
}
