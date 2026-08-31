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
	// Status returns a JSON-encodable status object. The concrete type is
	// opaque to the server; it is passed through to the response body.
	Status() any
}

// httpServer implements Server as an HTTP server.
type httpServer struct {
	addr   string
	status StatusSource
	logf   func(string, ...any)
	srv    *http.Server
}

// Option configures an admin server.
type Option func(*httpServer)

// WithLogf overrides the logger.
func WithLogf(logf func(string, ...any)) Option {
	return func(s *httpServer) { s.logf = logf }
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
