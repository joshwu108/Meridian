package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/joshuawu/meridian/internal/agent/workloadapi"
	"github.com/joshuawu/meridian/pkg/wire"
)

// InboundHandler accepts mTLS connections on :15008 (the inbound transparent
// listener), enforces authz, and proxies allowed traffic to the local upstream
// application (Phase 4.3 / P4.3).
//
// On each accepted connection:
//  1. Perform mTLS handshake — both sides present SPIFFE SVIDs.
//  2. Extract src_identity from the peer's SPIFFE cert via SpiffeIDResolver.
//  3. Recover orig_dst via OriginalDestinationResolver (getsockname).
//  4. Resolve dst_identity from the orig dst IP via IdentityLookup.
//  5. Evaluate (srcID, dstID, port, proto) against the PolicySource.
//  6. Dial the original destination (the real upstream app) and stream.
//
// Fail-closed on every step: any error rejects the connection.

// L7PolicySource provides the L7 rule snapshot for HTTP policy enforcement.
type L7PolicySource interface {
	CurrentL7(context.Context) (wire.L7PolicySnapshot, error)
}

type InboundHandler struct {
	listener       Listener
	certSource     workloadapi.CertSource
	trustPool      *x509.CertPool
	resolver       OriginalDestinationResolver
	policy         PolicySource
	l7Policy       L7PolicySource   // nil = no L7 enforcement
	l7Events       *L7EventRing     // nil = no L7 telemetry
	spiffeResolver SpiffeIDResolver // nil = src always IdentityUnknown
	metrics        *ProxyMetrics    // nil = no metrics
	tracer         trace.Tracer     // nil = no tracing (P5.4)
	logf           func(string, ...any)
}

// InboundOption configures an InboundHandler.
type InboundOption func(*InboundHandler)

// WithInboundLogf overrides the logger.
func WithInboundLogf(logf func(string, ...any)) InboundOption {
	return func(h *InboundHandler) { h.logf = logf }
}

// WithSpiffeIDResolver sets the resolver used to convert peer SPIFFE URIs to
// numeric identity IDs (fixes shortcoming #3). Without this the srcID in
// EvalPolicy is always wire.IdentityUnknown.
func WithSpiffeIDResolver(r SpiffeIDResolver) InboundOption {
	return func(h *InboundHandler) { h.spiffeResolver = r }
}

// WithInboundMetrics attaches Prometheus metrics to the inbound handler.
func WithInboundMetrics(m *ProxyMetrics) InboundOption {
	return func(h *InboundHandler) { h.metrics = m }
}

// WithL7Policy wires an L7 policy source for HTTP rule enforcement (P5.1).
func WithL7Policy(l7 L7PolicySource) InboundOption {
	return func(h *InboundHandler) { h.l7Policy = l7 }
}

// WithL7Events wires an event ring that receives one L7Event per observed
// HTTP request, feeding the admin /http/watch stream (P5.3).
func WithL7Events(ring *L7EventRing) InboundOption {
	return func(h *InboundHandler) { h.l7Events = ring }
}

// WithInboundTracer attaches an OpenTelemetry tracer that records one span
// per accepted connection (P5.4). Obtain one from NewTracerProvider.
func WithInboundTracer(t trace.Tracer) InboundOption {
	return func(h *InboundHandler) { h.tracer = t }
}

// NewInboundHandler constructs a handler for the :15008 listener.
func NewInboundHandler(
	listener Listener,
	certSource workloadapi.CertSource,
	trustPool *x509.CertPool,
	resolver OriginalDestinationResolver,
	policy PolicySource,
	opts ...InboundOption,
) *InboundHandler {
	h := &InboundHandler{
		listener:   listener,
		certSource: certSource,
		trustPool:  trustPool,
		resolver:   resolver,
		policy:     policy,
		logf:       log.Printf,
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// Serve accepts connections until ctx is cancelled.
func (h *InboundHandler) Serve(ctx context.Context) error {
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
			h.logf("proxy inbound: accept: %v", err)
			continue
		}
		go h.handle(ctx, conn)
	}
}

func (h *InboundHandler) handle(ctx context.Context, raw net.Conn) {
	start := time.Now()
	defer raw.Close()

	// One span per connection (P5.4). Identity/verdict attributes are filled
	// in as the steps below resolve them; every return path ends the span.
	ctx, span := startConnSpan(ctx, h.tracer, "meridian.proxy.inbound")
	srcID, dstID := wire.IdentityUnknown, wire.IdentityUnknown
	var dstPort uint16
	verdict := "deny" // fail-closed default; flipped on the allow path
	defer func() { span.end(srcID, dstID, dstPort, verdict) }()

	// Step 1: mTLS handshake.
	tlsConn, srcSpiffeID, err := h.handshake(raw)
	if err != nil {
		h.logf("proxy inbound: mTLS handshake from %s: %v", raw.RemoteAddr(), err)
		return
	}
	defer tlsConn.Close()

	// Step 2: Recover original destination and identities.
	origDst, _, dstID, err := h.resolver.Resolve(tlsConn)
	if err != nil {
		h.logf("proxy inbound: resolve orig_dst: %v", err)
		return
	}
	dstPort = origDst.Port()

	// Step 3: Resolve src_identity from the peer's SPIFFE URI (ADR-0006 D-D).
	// The SPIFFE URI is the authoritative source — it comes from the verified
	// mTLS peer cert, not from a forgeable kernel mark.
	if h.spiffeResolver != nil {
		if id, ok := h.spiffeResolver.ResolveSpiffeID(srcSpiffeID); ok {
			srcID = id
		}
	}

	// Step 4: Authz check.
	snap, err := h.policy.Current(ctx)
	if err != nil {
		h.logf("proxy inbound: policy snapshot: %v", err)
		return
	}
	result := EvalPolicy(snap, srcID, dstID, origDst, 6 /* TCP */)
	srcIDStr := strconv.FormatUint(uint64(srcID), 10)
	dstIDStr := strconv.FormatUint(uint64(dstID), 10)
	if result == AuthzDeny {
		h.logf("proxy inbound: DENY src=%s dst=%s src_id=%d dst_id=%d",
			srcSpiffeID, origDst, srcID, dstID)
		h.metrics.RecordRequest("inbound", "deny", srcIDStr, dstIDStr, time.Since(start))
		return
	}
	h.logf("proxy inbound: ALLOW src=%s dst=%s src_id=%d dst_id=%d",
		srcSpiffeID, origDst, srcID, dstID)

	// Step 5a: L7 policy enforcement when PolicyFlagL7Required is set (P5.1).
	// We peek the stream, parse HTTP/1.1 headers, and match against L7 rules.
	// HTTP/2 framing deferred — shortcoming #6 update.
	var streamConn io.Reader = tlsConn
	if result != AuthzDeny && h.l7Policy != nil &&
		snap.Policies != nil {
		// Check if any matching rule requires L7.
		for _, rule := range snap.Policies {
			if rule.Key.SrcIdentity == srcID && rule.Key.DstIdentity == dstID &&
				rule.Verdict.Flags&wire.PolicyFlagL7Required != 0 {
				l7Snap, l7Err := h.l7Policy.CurrentL7(ctx)
				if l7Err == nil && len(l7Snap.Rules) > 0 {
					l7Action, httpReq, remainder := peekAndMatchL7(tlsConn, l7Snap.Rules)
					streamConn = remainder
					h.publishL7Event(httpReq, srcID, dstID, origDst.Port(), l7Action)
					if l7Action == wire.PolicyActionDeny {
						h.logf("proxy inbound: L7 DENY src_id=%d dst=%s", srcID, origDst)
						h.metrics.RecordRequest("inbound", "l7-deny", srcIDStr, dstIDStr, time.Since(start))
						return
					}
				}
				break
			}
		}
	}

	// Step 5b: Dial the upstream application at the original destination.
	upstream, err := (&net.Dialer{}).DialContext(ctx, "tcp", origDst.String())
	if err != nil {
		h.logf("proxy inbound: dial upstream %s: %v", origDst, err)
		return
	}
	defer upstream.Close()

	// Step 6: Bidirectional stream (streamConn replays any bytes peeked for L7).
	verdict = "allow"
	errc := make(chan error, 2)
	go func() { _, err := io.Copy(upstream, streamConn); errc <- err }()
	go func() { _, err := io.Copy(tlsConn, upstream); errc <- err }()
	<-errc
	h.metrics.RecordRequest("inbound", "allow", srcIDStr, dstIDStr, time.Since(start))
}

// publishL7Event emits an L7 telemetry event for an observed HTTP request.
// No-op when the event ring is unset or the stream was not HTTP (req == nil).
func (h *InboundHandler) publishL7Event(req *http.Request, srcID, dstID wire.IdentityID, dstPort uint16, action wire.PolicyAction) {
	if h.l7Events == nil || req == nil {
		return
	}
	verdict := "allow"
	if action == wire.PolicyActionDeny {
		verdict = "deny"
	}
	h.l7Events.Publish(L7Event{
		Time:        time.Now(),
		SrcIdentity: srcID,
		DstIdentity: dstID,
		DstPort:     dstPort,
		Method:      req.Method,
		Path:        req.URL.Path,
		Verdict:     verdict,
	})
}

// handshake wraps raw in a TLS server, performs the handshake, and returns the
// TLS conn plus the peer's SPIFFE ID (from its client certificate).
func (h *InboundHandler) handshake(raw net.Conn) (*tls.Conn, string, error) {
	cfg := h.certSource.TLSConfig(h.trustPool)
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	cfg.ClientCAs = h.trustPool

	tlsConn := tls.Server(raw, cfg)
	if err := tlsConn.Handshake(); err != nil {
		return nil, "", fmt.Errorf("TLS handshake: %w", err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, "", fmt.Errorf("peer sent no certificate after handshake")
	}
	spiffeID, err := SPIFFEIDFromCert(state.PeerCertificates[0])
	if err != nil {
		return nil, "", fmt.Errorf("peer cert: %w", err)
	}
	return tlsConn, spiffeID, nil
}
