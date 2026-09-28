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
	"strconv"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/joshuawu/meridian/internal/agent/workloadapi"
	"github.com/joshuawu/meridian/pkg/wire"
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
	listener     Listener
	resolver     OriginalDestinationResolver
	dialer       OutboundDialer
	spiffeLookup SpiffeIDLookup // nil = no peer identity cross-check
	metrics      *ProxyMetrics  // nil = no metrics
	tracer       trace.Tracer   // nil = no tracing (P5.4)
	logf         func(string, ...any)

	// Per-upstream circuit breakers (P5.2): one failing node must not open
	// the circuit for all destinations. cbTemplate holds the config; nil =
	// disabled.
	cbTemplate *CircuitBreaker
	cbMu       sync.Mutex
	cbs        map[netip.Addr]*CircuitBreaker
}

// OutboundOption configures an OutboundHandler.
type OutboundOption func(*OutboundHandler)

// WithOutboundLogf overrides the logger.
func WithOutboundLogf(logf func(string, ...any)) OutboundOption {
	return func(h *OutboundHandler) { h.logf = logf }
}

// WithOutboundSpiffeIDLookup enables the peer identity cross-check
// (shortcoming #5): after the mTLS handshake the remote proxy's SPIFFE URI is
// compared against the URI registered for the flow's dst_identity, and the
// connection is closed on mismatch.
func WithOutboundSpiffeIDLookup(l SpiffeIDLookup) OutboundOption {
	return func(h *OutboundHandler) { h.spiffeLookup = l }
}

// WithOutboundMetrics attaches Prometheus metrics to the outbound handler.
func WithOutboundMetrics(m *ProxyMetrics) OutboundOption {
	return func(h *OutboundHandler) { h.metrics = m }
}

// WithOutboundTracer records one span per tunneled connection (P5.4).
func WithOutboundTracer(t trace.Tracer) OutboundOption {
	return func(h *OutboundHandler) { h.tracer = t }
}

// WithCircuitBreaker enables per-upstream circuit breaking. The passed
// breaker is a config template: each upstream address lazily gets its own
// breaker with the same Threshold/ResetAfter.
func WithCircuitBreaker(cb *CircuitBreaker) OutboundOption {
	return func(h *OutboundHandler) { h.cbTemplate = cb }
}

// cbFor returns the breaker for an upstream address, creating it from the
// template on first access; nil when circuit breaking is disabled.
func (h *OutboundHandler) cbFor(addr netip.Addr) *CircuitBreaker {
	if h.cbTemplate == nil {
		return nil
	}
	h.cbMu.Lock()
	defer h.cbMu.Unlock()
	if h.cbs == nil {
		h.cbs = make(map[netip.Addr]*CircuitBreaker)
	}
	cb, ok := h.cbs[addr]
	if !ok {
		cb = NewCircuitBreaker(h.cbTemplate.Threshold, h.cbTemplate.ResetAfter)
		h.cbs[addr] = cb
	}
	return cb
}

// CircuitStates returns the state of every per-upstream breaker for the
// admin surface (shortcoming #7).
func (h *OutboundHandler) CircuitStates() map[netip.Addr]CBState {
	h.cbMu.Lock()
	defer h.cbMu.Unlock()
	states := make(map[netip.Addr]CBState, len(h.cbs))
	for addr, cb := range h.cbs {
		states[addr] = cb.State()
	}
	return states
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
	start := time.Now()
	defer conn.Close()

	// One span per connection (P5.4).
	ctx, span := startConnSpan(ctx, h.tracer, "meridian.proxy.outbound")
	var srcID, dstID wire.IdentityID
	var dstPort uint16
	verdict := "deny" // fail-closed default
	defer func() { span.end(srcID, dstID, dstPort, verdict) }()

	// Recover original destination from the transparent connection.
	origDst, srcID, dstID, err := h.resolver.Resolve(conn)
	if err != nil {
		h.logf("proxy outbound: resolve orig_dst: %v", err)
		return
	}
	dstPort = origDst.Port()

	// Circuit breaker check (P5.2) before paying the dial cost.
	cb := h.cbFor(origDst.Addr())
	if cb != nil {
		if err := cb.Allow(); err != nil {
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
		if cb != nil {
			cb.RecordFailure()
		}
		return
	}
	defer upstream.Close()

	// Verify the remote proxy's SPIFFE ID (shortcoming #5): the peer must
	// present a valid SPIFFE cert, and — when the resolver knows the expected
	// URI for dst_identity — that cert's URI SAN must match it exactly.
	if tlsUpstream, ok := upstream.(*tls.Conn); ok {
		state := tlsUpstream.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			peerID, err := SPIFFEIDFromCert(state.PeerCertificates[0])
			if err != nil {
				h.logf("proxy outbound: remote proxy sent non-SPIFFE cert: %v", err)
				if cb != nil {
					cb.RecordFailure()
				}
				return
			}
			if h.spiffeLookup != nil {
				if expected, known := h.spiffeLookup.LookupID(dstID); known && expected != peerID {
					h.logf("proxy outbound: peer identity mismatch: dst_id=%d expects %s, peer presented %s — closing",
						dstID, expected, peerID)
					h.metrics.RecordRequest("outbound", "peer-mismatch",
						"0", strconv.FormatUint(uint64(dstID), 10), time.Since(start))
					if cb != nil {
						cb.RecordFailure()
					}
					return
				}
			}
			h.logf("proxy outbound: remote proxy SPIFFE ID=%s dst_id=%d", peerID, dstID)
		}
	}

	h.logf("proxy outbound: tunneling src=%s orig_dst=%s dst_id=%d via %s",
		conn.RemoteAddr(), origDst, dstID, remoteProxy)

	// Bidirectional copy — the remote proxy reads from the upstream direction
	// and forwards to the application; we forward the pod's bytes upstream,
	// injecting a traceparent header into HTTP/1.1 requests when tracing is on.
	verdict = "allow"
	downstream := injectTraceparent(conn, span.traceparent())
	errc := make(chan error, 2)
	go func() { _, e := io.Copy(upstream, downstream); errc <- e }()
	go func() { _, e := io.Copy(conn, upstream); errc <- e }()
	copyErr := <-errc
	if cb != nil {
		if copyErr != nil && !isClosedErr(copyErr) {
			cb.RecordFailure()
		} else {
			cb.RecordSuccess()
		}
	}
}
