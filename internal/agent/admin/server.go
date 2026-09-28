// Package admin implements the local admin HTTP/JSON server for the agent
// (Phase 6 CLI backing). It serves status, map dump, and health endpoints
// on a loopback address (default :9902). The admin surface is intentionally
// minimal and never exposed beyond the node.
package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// StatusSource provides agent runtime status for the /status endpoint.
type StatusSource interface {
	Status() any
}

// FlowSource provides a subscription channel for flow events (telemetry).
// Each call to Subscribe returns a channel that receives JSON-encoded flow
// event lines for the /flows/watch SSE stream.
type FlowSource interface {
	Subscribe() <-chan string
}

// MapDumper returns a JSON-encodable snapshot of the current identity and
// policy map contents for the /maps/dump endpoint.
type MapDumper interface {
	Dump() any
}

// CertRotator triggers an immediate SVID rotation, bypassing the 2/3-TTL
// schedule, and returns the new certificate's expiry. The agent wires the
// svid.SVIDManager here; the /cert/rotate endpoint (meridian cert rotate)
// calls it.
type CertRotator interface {
	ForceRotate(ctx context.Context) (time.Time, error)
}

// httpServer implements Server as an HTTP server.
type httpServer struct {
	addr        string
	status      StatusSource
	flowSource  FlowSource
	httpEvents  FlowSource // L7 event stream for /http/watch (P5.3)
	mapDumper   MapDumper
	certRotator CertRotator
	logf        func(string, ...any)
	srv         *http.Server
}

// Option configures an admin server.
type Option func(*httpServer)

// WithLogf overrides the logger.
func WithLogf(logf func(string, ...any)) Option {
	return func(s *httpServer) { s.logf = logf }
}

// WithFlowSource attaches a FlowSource for the /flows/watch SSE endpoint.
func WithFlowSource(fs FlowSource) Option {
	return func(s *httpServer) { s.flowSource = fs }
}

// WithMapDumper attaches a MapDumper for the /maps/dump endpoint.
func WithMapDumper(md MapDumper) Option {
	return func(s *httpServer) { s.mapDumper = md }
}

// WithHTTPEventSource attaches the L7 event source for the /http/watch SSE
// endpoint (meridian http watch, P5.3). The proxy's L7EventRing satisfies
// this interface.
func WithHTTPEventSource(src FlowSource) Option {
	return func(s *httpServer) { s.httpEvents = src }
}

// WithCertRotator attaches the SVID rotator for the POST /cert/rotate
// endpoint (meridian cert rotate).
func WithCertRotator(cr CertRotator) Option {
	return func(s *httpServer) { s.certRotator = cr }
}

// NewServer returns an admin HTTP server listening on addr.
// statusSource may be nil (the /status endpoint returns an empty object).
func NewServer(addr string, statusSource StatusSource, opts ...Option) Server {
	s := &httpServer{
		addr:   addr,
		status: statusSource,
		logf:   log.Printf,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// Serve starts the admin HTTP server and blocks until ctx is cancelled.
func (s *httpServer) Serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/flows/watch", s.handleFlowsWatch)
	mux.HandleFunc("/http/watch", s.handleHTTPWatch)
	mux.HandleFunc("/maps/dump", s.handleMapsDump)
	mux.HandleFunc("/cert/rotate", s.handleCertRotate)

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("admin: listen %q: %w", s.addr, err)
	}

	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutCtx)
	}()

	s.logf("admin: serving on %s", ln.Addr())
	if err := s.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("admin: serve: %w", err)
	}
	return nil
}

func (s *httpServer) handleStatus(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var payload any = map[string]string{"status": "ok"}
	if s.status != nil {
		payload = s.status.Status()
	}
	if err := json.NewEncoder(w).Encode(map[string]any{
		"success": true,
		"data":    payload,
	}); err != nil {
		s.logf("admin: encode status: %v", err)
	}
}

func (s *httpServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte("ok\n"))
}

// handleFlowsWatch serves a Server-Sent Events stream of flow events.
// Consumers (meridian flows watch) read this line by line.
// Currently returns a placeholder — the real implementation wires the
// telemetry.Consumer fan-out channel via a FlowSource interface (Phase 5/6).
func (s *httpServer) handleFlowsWatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	if s.flowSource == nil {
		_, _ = fmt.Fprintf(w, "event: error\ndata: flow source not configured\n\n")
		flusher.Flush()
		return
	}
	ch := s.flowSource.Subscribe()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", ev)
			flusher.Flush()
		}
	}
}

// handleHTTPWatch serves a Server-Sent Events stream of L7 (HTTP) events for
// `meridian http watch`. Returns 501 when no L7 event source is wired — the
// CLI turns that into a "pending Phase 5 wiring" message.
func (s *httpServer) handleHTTPWatch(w http.ResponseWriter, r *http.Request) {
	if s.httpEvents == nil {
		http.Error(w, "L7 event stream not configured", http.StatusNotImplemented)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	ch := s.httpEvents.Subscribe()
	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			_, _ = fmt.Fprintf(w, "data: %s\n\n", ev)
			flusher.Flush()
		}
	}
}

// handleCertRotate triggers an immediate SVID rotation via the wired
// CertRotator (POST /cert/rotate, backing `meridian cert rotate`) and replies
// with the new certificate's expiry.
func (s *httpServer) handleCertRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed; use POST", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if s.certRotator == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		s.encodeEnvelope(w, map[string]any{
			"success": false,
			"error":   "cert rotator not configured (agent started without an SVID manager)",
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	expiry, err := s.certRotator.ForceRotate(ctx)
	if err != nil {
		s.logf("admin: cert rotate failed: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		s.encodeEnvelope(w, map[string]any{
			"success": false,
			"error":   fmt.Sprintf("rotate: %v", err),
		})
		return
	}
	s.encodeEnvelope(w, map[string]any{
		"success": true,
		"data":    map[string]string{"expires_at": expiry.UTC().Format(time.RFC3339)},
	})
}

// encodeEnvelope writes a JSON envelope, logging (not masking) encode errors.
func (s *httpServer) encodeEnvelope(w http.ResponseWriter, envelope map[string]any) {
	if err := json.NewEncoder(w).Encode(envelope); err != nil {
		s.logf("admin: encode response: %v", err)
	}
}

// handleMapsDump returns a JSON snapshot of identity and policy maps for CLI
// debugging. The real implementation reads from the datapath maps; this
// delegates to MapDumper if configured, otherwise returns a placeholder.
func (s *httpServer) handleMapsDump(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.mapDumper == nil {
		if err := json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]any{"identities": []any{}, "policies": []any{}},
		}); err != nil {
			s.logf("admin: encode map dump: %v", err)
		}
		return
	}
	dump := s.mapDumper.Dump()
	if err := json.NewEncoder(w).Encode(map[string]any{"success": true, "data": dump}); err != nil {
		s.logf("admin: encode map dump: %v", err)
	}
}
