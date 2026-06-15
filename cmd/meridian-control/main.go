// Command meridian-control runs the Meridian control-plane REST surface (CP-1,
// MER-53): an in-memory policy/identity store fronted by the admin REST API.
// The ADS gRPC server (MER-54) and durable storage land in later tickets.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/internal/control/rest"
	"github.com/joshuawu/meridian/internal/control/store"
)

const (
	defaultListen   = ":8080"
	readTimeout     = 10 * time.Second
	writeTimeout    = 10 * time.Second
	idleTimeout     = 60 * time.Second
	shutdownTimeout = 5 * time.Second
)

func main() {
	listen := flag.String("listen", defaultListen, "address for the control-plane REST server to listen on")
	flag.Parse()

	if err := run(*listen); err != nil {
		log.Fatalf("meridian-control: %v", err)
	}
}

func run(listen string) error {
	srv := rest.NewServer(store.NewMemory(), identity.NewRegistry())

	httpServer := &http.Server{
		Addr:         listen,
		Handler:      srv.Handler(),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("meridian-control: REST listening on %s", listen)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Printf("meridian-control: shutdown signal received, draining")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return <-errCh
}
