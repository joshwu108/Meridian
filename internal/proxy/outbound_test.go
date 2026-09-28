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

// fakeDialer implements OutboundDialer with a configurable response.
type fakeDialer struct {
	mu       sync.Mutex
	dialed   []netip.AddrPort
	dialConn net.Conn // if set, returned on Dial; otherwise uses a pipe
	dialErr  error
}

func (d *fakeDialer) Dial(_ context.Context, addr netip.AddrPort) (net.Conn, error) {
	d.mu.Lock()
	d.dialed = append(d.dialed, addr)
	d.mu.Unlock()
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	if d.dialConn != nil {
		return d.dialConn, nil
	}
	// Return a pipe so the handler can stream.
	client, server := net.Pipe()
	_ = server // server end: close immediately to signal EOF upstream
	go func() { _ = server.Close() }()
	return client, nil
}

func (d *fakeDialer) lastDialed() netip.AddrPort {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.dialed) == 0 {
		return netip.AddrPort{}
	}
	return d.dialed[len(d.dialed)-1]
}

// TestOutboundHandlerDialsRemoteProxy verifies that the outbound handler dials
// origDst.IP:15008 (the remote proxy port), not the original service port.
func TestOutboundHandlerDialsRemoteProxy(t *testing.T) {
	origDst := netip.MustParseAddrPort("10.0.0.5:8080")
	resolver := &fakeResolver{origDst: origDst, dstID: wire.IdentityID(42)}
	dialer := &fakeDialer{}

	ln := newFakeListener()
	h := NewOutboundHandler(ln, resolver, dialer, WithOutboundLogf(func(string, ...any) {}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	client, server := net.Pipe()
	ln.inject(server)

	// Write some data then close; the handler will copy it upstream.
	_, _ = client.Write([]byte("ping"))
	_ = client.Close()

	// Wait for the dialer to be called.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if dialer.lastDialed() != (netip.AddrPort{}) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if dialer.lastDialed() == (netip.AddrPort{}) {
		t.Fatal("dialer was not called within timeout")
	}

	got := dialer.lastDialed()
	want := netip.AddrPortFrom(origDst.Addr(), RemoteProxyPort)
	if got != want {
		t.Fatalf("dialed %s, want %s (origDst.IP:15008)", got, want)
	}
}

// TestOutboundHandlerDropsOnDialError verifies that a dial failure drops the
// connection.
func TestOutboundHandlerDropsOnDialError(t *testing.T) {
	resolver := &fakeResolver{origDst: netip.MustParseAddrPort("10.0.0.5:8080")}
	dialer := &fakeDialer{dialErr: errors.New("connection refused")}

	ln := newFakeListener()
	h := NewOutboundHandler(ln, resolver, dialer, WithOutboundLogf(func(string, ...any) {}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	client, server := net.Pipe()
	ln.inject(server)

	// Server should close the connection after dial failure.
	_ = client.SetDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	_, err := client.Read(buf)
	if err == nil {
		t.Fatal("expected connection closed on dial error, got data")
	}
}

// TestOutboundHandlerDropsOnResolveError verifies fail-close when orig_dst
// cannot be recovered.
func TestOutboundHandlerDropsOnResolveError(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("orig_dst unavailable")}
	dialer := &fakeDialer{}

	ln := newFakeListener()
	h := NewOutboundHandler(ln, resolver, dialer, WithOutboundLogf(func(string, ...any) {}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	client, server := net.Pipe()
	ln.inject(server)

	_ = client.SetDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 64)
	_, err := client.Read(buf)
	if err == nil {
		t.Fatal("expected connection closed on resolver error")
	}
}

// TestOutboundHandlerContextCancellation verifies Serve returns on ctx cancel.
func TestOutboundHandlerContextCancellation(t *testing.T) {
	resolver := &fakeResolver{origDst: netip.MustParseAddrPort("10.0.0.1:80")}
	dialer := &fakeDialer{}
	ln := newFakeListener()
	h := NewOutboundHandler(ln, resolver, dialer, WithOutboundLogf(func(string, ...any) {}))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned non-nil: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop")
	}
}

// TestOutboundHandlerBidirectionalStream verifies that data flows in both
// directions between the client and the (fake) upstream.
func TestOutboundHandlerBidirectionalStream(t *testing.T) {
	origDst := netip.MustParseAddrPort("10.0.0.5:8080")
	resolver := &fakeResolver{origDst: origDst}

	// Set up the fake upstream as a pipe.
	upstreamClient, upstreamServer := net.Pipe()
	dialer := &fakeDialer{dialConn: upstreamServer}

	ln := newFakeListener()
	h := NewOutboundHandler(ln, resolver, dialer, WithOutboundLogf(func(string, ...any) {}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	// Client side.
	client, server := net.Pipe()
	ln.inject(server)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))

	// Send from client → should appear on upstreamClient.
	payload := []byte("hello upstream")
	_, _ = client.Write(payload)

	buf := make([]byte, len(payload))
	_ = upstreamClient.SetDeadline(time.Now().Add(2 * time.Second))
	n, err := upstreamClient.Read(buf)
	if err != nil {
		t.Fatalf("read from upstream: %v", err)
	}
	if string(buf[:n]) != string(payload) {
		t.Fatalf("upstream got %q, want %q", buf[:n], payload)
	}

	// Echo back from upstream → should appear on client.
	reply := []byte("pong")
	_, _ = upstreamClient.Write(reply)

	rbuf := make([]byte, len(reply))
	n2, err := client.Read(rbuf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(rbuf[:n2]) != string(reply) {
		t.Fatalf("client got %q, want %q", rbuf[:n2], reply)
	}
}

// TestMTLSDialerImplementsInterface is a compile-time check.
func TestMTLSDialerImplementsInterface(t *testing.T) {
	var _ OutboundDialer = &MTLSDialer{}
	var _ OutboundDialer = &fakeDialer{}
}
