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

// httpServer implements Server as an HTTP server.
type httpServer struct {
	addr       string
	status     StatusSource
	flowSource FlowSource
	mapDumper  MapDumper
	logf       func(string, ...any)
	srv        *http.Server
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
	mux.HandleFunc("/maps/dump", s.handleMapsDump)

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
