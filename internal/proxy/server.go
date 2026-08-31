package proxy

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strings"
)

// Listener abstracts net.Listener so the echo server can be tested without
// opening real sockets.
type Listener interface {
	Accept() (net.Conn, error)
	Close() error
	Addr() net.Addr
}

// ServerOption configures an echoServer.
type ServerOption func(*echoServer)

// WithServerLogf overrides the logger.
func WithServerLogf(logf func(string, ...any)) ServerOption {
	return func(s *echoServer) { s.logf = logf }
}

// echoServer is the P4.1 no-TLS echo prototype (ADR-0006 testing requirement 1).
// It accepts connections on an IP_TRANSPARENT listener, recovers the original
// destination via OriginalDestinationResolver, logs it, and echoes all bytes
// back to the client. Phase 4.2 replaces the echo loop with mTLS tunneling.
type echoServer struct {
	listener Listener
	resolver OriginalDestinationResolver
	logf     func(string, ...any)
}

// NewEchoServer returns a Server that accepts on listener and uses resolver to
// recover original destinations (P4.1 gate). It implements the Server interface
// defined in doc.go.
func NewEchoServer(listener Listener, resolver OriginalDestinationResolver, opts ...ServerOption) Server {
	s := &echoServer{
		listener: listener,
		resolver: resolver,
		logf:     log.Printf,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Serve accepts connections and echoes them until ctx is cancelled.
func (s *echoServer) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logf("proxy echo: accept: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *echoServer) handleConn(conn net.Conn) {
	defer conn.Close()

	origDst, _, dstID, err := s.resolver.Resolve(conn)
	if err != nil {
		s.logf("proxy echo: resolve orig-dst: %v", err)
		// Fail-close: if we can't recover the destination the connection is
		// indeterminate. Drop it rather than proxying blindly.
		return
	}
	s.logf("proxy echo: accepted conn src=%s orig_dst=%s dst_identity=%d",
		conn.RemoteAddr(), origDst, dstID)

	if _, err := io.Copy(conn, conn); err != nil && !isClosedErr(err) {
		s.logf("proxy echo: copy: %v", err)
	}
}

func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "connection reset by peer") ||
		strings.Contains(s, "broken pipe")
}

// ListenTransparent opens an IP_TRANSPARENT TCP listener on addr.
// On Linux this sets SO_REUSEADDR + IP_TRANSPARENT; the latter allows the
// listener to accept connections whose destination address is not locally
// assigned (TPROXY-steered connections). On other platforms it falls back to
// a regular listener for unit-test compatibility.
func ListenTransparent(ctx context.Context, addr string) (net.Listener, error) {
	lc := transparentListenConfig()
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: listen transparent %q: %w", addr, err)
	}
	return ln, nil
}

// AddrPortFromListener returns the bound address of ln as netip.AddrPort.
func AddrPortFromListener(ln net.Listener) (netip.AddrPort, error) {
	return netip.ParseAddrPort(ln.Addr().String())
}
