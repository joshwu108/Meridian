package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"

	"github.com/joshuawu/meridian/internal/agent/workloadapi"
)

// RemoteProxyPort is the inbound mTLS port on the destination node proxy.
// A connection from :15001 always dials remote:15008.
const RemoteProxyPort = 15008

// OutboundDialer dials the destination node proxy's :15008 inbound mTLS port.
// Abstracted as an interface so tests can substitute a fake dialer.
type OutboundDialer interface {
	Dial(ctx context.Context, addr netip.AddrPort) (net.Conn, error)
}

// MTLSDialer implements OutboundDialer using mTLS (SPIFFE SVIDs).
type MTLSDialer struct {
	certSource workloadapi.CertSource
	trustPool  *x509.CertPool
}

// NewMTLSDialer returns a dialer that presents the local SVID and verifies the
// remote peer against trustPool.
func NewMTLSDialer(certSource workloadapi.CertSource, trustPool *x509.CertPool) *MTLSDialer {
	return &MTLSDialer{certSource: certSource, trustPool: trustPool}
}

// Dial opens a mTLS connection to addr (the remote node proxy's :15008).
func (d *MTLSDialer) Dial(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	cfg := d.certSource.TLSConfig(d.trustPool)
	cfg.InsecureSkipVerify = false
	cfg.ServerName = addr.Addr().String() // SNI = remote node IP

	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr.String())
	if err != nil {
		return nil, fmt.Errorf("outbound dial %s: %w", addr, err)
	}
	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("outbound mTLS handshake %s: %w", addr, err)
	}
	return tlsConn, nil
}

// OutboundHandler accepts redirected outbound connections on :15001
// (IP_TRANSPARENT), recovers the original destination via resolver, and
// tunnels the flow through the destination node's proxy via mTLS (P4.4).
//
// Flow:
//
//	pod → [TPROXY redirect] → :15001 (IP_TRANSPARENT)
//	    → recover orig_dst (getsockname)
//	    → circuit-breaker check (P5.2)
//	    → mTLS dial remote:15008
//	    → verify peer SPIFFE ID (shortcoming #5)
//	    → bidirectional copy
type OutboundHandler struct {
	listener Listener
	resolver OriginalDestinationResolver
	dialer   OutboundDialer
	cb       *CircuitBreaker // nil = no circuit breaking
	logf     func(string, ...any)
}

// OutboundOption configures an OutboundHandler.
type OutboundOption func(*OutboundHandler)

// WithOutboundLogf overrides the logger.
func WithOutboundLogf(logf func(string, ...any)) OutboundOption {
	return func(h *OutboundHandler) { h.logf = logf }
}

// WithCircuitBreaker attaches a circuit breaker that gates every upstream dial.
func WithCircuitBreaker(cb *CircuitBreaker) OutboundOption {
	return func(h *OutboundHandler) { h.cb = cb }
}

// NewOutboundHandler constructs the :15001 outbound intercept handler.
func NewOutboundHandler(listener Listener, resolver OriginalDestinationResolver, dialer OutboundDialer, opts ...OutboundOption) *OutboundHandler {
	h := &OutboundHandler{
		listener: listener,
		resolver: resolver,
		dialer:   dialer,
		logf:     log.Printf,
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// Serve accepts connections and handles them until ctx is cancelled.
func (h *OutboundHandler) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = h.listener.Close()
	}()
	for {
		conn, err := h.listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			h.logf("proxy outbound: accept: %v", err)
			continue
		}
		go h.handle(ctx, conn)
	}
}

func (h *OutboundHandler) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Recover original destination from the transparent connection.
	origDst, _, dstID, err := h.resolver.Resolve(conn)
	if err != nil {
		h.logf("proxy outbound: resolve orig_dst: %v", err)
		return
	}

	// Circuit breaker check (P5.2) before paying the dial cost.
	if h.cb != nil {
		if err := h.cb.Allow(); err != nil {
			h.logf("proxy outbound: circuit open for orig_dst=%s: %v", origDst, err)
			return
		}
	}

	// Dial the destination node proxy at origDst.IP:15008.
	remoteProxy := netip.AddrPortFrom(origDst.Addr(), RemoteProxyPort)
	upstream, err := h.dialer.Dial(ctx, remoteProxy)
	if err != nil {
		h.logf("proxy outbound: dial remote proxy %s (orig_dst %s, dst_id %d): %v",
			remoteProxy, origDst, dstID, err)
		if h.cb != nil {
			h.cb.RecordFailure()
		}
		return
	}
	defer upstream.Close()

	// Verify the remote proxy's SPIFFE ID (shortcoming #5): the peer must
	// present a valid SPIFFE cert. We log the peer ID for audit; a future
	// revision should cross-check against the expected dst_identity.
	if tlsUpstream, ok := upstream.(*tls.Conn); ok {
		state := tlsUpstream.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			if peerID, err := SPIFFEIDFromCert(state.PeerCertificates[0]); err == nil {
				h.logf("proxy outbound: remote proxy SPIFFE ID=%s dst_id=%d", peerID, dstID)
			} else {
				h.logf("proxy outbound: remote proxy sent non-SPIFFE cert: %v", err)
				if h.cb != nil {
					h.cb.RecordFailure()
				}
				return
			}
		}
	}

	h.logf("proxy outbound: tunneling src=%s orig_dst=%s dst_id=%d via %s",
		conn.RemoteAddr(), origDst, dstID, remoteProxy)

	// Bidirectional copy — the remote proxy reads from the upstream direction
	// and forwards to the application; we forward the pod's bytes upstream.
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(upstream, conn); errc <- e }()
	go func() { _, e := io.Copy(conn, upstream); errc <- e }()
	copyErr := <-errc
	if h.cb != nil {
		if copyErr != nil && !isClosedErr(copyErr) {
			h.cb.RecordFailure()
		} else {
			h.cb.RecordSuccess()
		}
	}
}
