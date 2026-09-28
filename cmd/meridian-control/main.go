// Command meridian-control runs the Meridian control plane:
//   - REST API (CP-1): policy/identity CRUD
//   - ADS gRPC server (CP-3): pushes compiled policy to agents
//   - CA issuance (PKI-3): POST /svid/sign for workload SVID issuance
//
// Standalone mode (--standalone, default): generates an ephemeral CA and
// serves both REST and ADS over plain HTTP/gRPC (dev/test).
//
// Production mode: loads CA from --ca-cert / --ca-key and enables mTLS on
// the ADS gRPC port using --tls-cert / --tls-key.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"

	"github.com/joshuawu/meridian/internal/control/ads"
	"github.com/joshuawu/meridian/internal/control/ca"
	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/internal/control/k8s"
	"github.com/joshuawu/meridian/internal/control/rest"
	"github.com/joshuawu/meridian/internal/control/store"
)

const (
	defaultRESTAddr    = ":8080"
	defaultADSAddr     = ":9443"
	defaultWebhookAddr = ":9443"
	readTimeout     = 10 * time.Second
	writeTimeout    = 30 * time.Second
	idleTimeout     = 60 * time.Second
	shutdownTimeout = 5 * time.Second
)

func main() {
	restAddr := flag.String("listen", defaultRESTAddr, "REST API listen address")
	adsAddr := flag.String("ads-addr", defaultADSAddr, "ADS gRPC listen address")
	standalone := flag.Bool("standalone", true, "generate ephemeral CA (dev mode)")
	caCertFile := flag.String("ca-cert", "", "intermediate CA certificate PEM file")
	caKeyFile := flag.String("ca-key", "", "intermediate CA private key PEM file")
	rootCertFile := flag.String("root-cert", "", "root CA certificate PEM file")
	tlsCertFile := flag.String("tls-cert", "", "ADS gRPC server certificate PEM")
	tlsKeyFile := flag.String("tls-key", "", "ADS gRPC server private key PEM")
	trustDomain := flag.String("trust-domain", "cluster.local", "SPIFFE trust domain")
	webhookAddr := flag.String("webhook-addr", defaultWebhookAddr, "admission webhook listen address")
	webhookCert := flag.String("webhook-cert", "", "admission webhook TLS certificate PEM")
	webhookKey := flag.String("webhook-key", "", "admission webhook TLS private key PEM")
	flag.Parse()

	if err := run(runConfig{
		restAddr:        *restAddr,
		adsAddr:         *adsAddr,
		standalone:      *standalone,
		caCertFile:      *caCertFile,
		caKeyFile:       *caKeyFile,
		rootCertFile:    *rootCertFile,
		tlsCertFile:     *tlsCertFile,
		tlsKeyFile:      *tlsKeyFile,
		trustDomain:     *trustDomain,
		webhookAddr:     *webhookAddr,
		webhookCertFile: *webhookCert,
		webhookKeyFile:  *webhookKey,
	}); err != nil {
		log.Fatalf("meridian-control: %v", err)
	}
}

type runConfig struct {
	restAddr     string
	adsAddr      string
	standalone   bool
	caCertFile   string
	caKeyFile    string
	rootCertFile string
	tlsCertFile  string
	tlsKeyFile   string
	trustDomain  string

	webhookAddr     string
	webhookCertFile string
	webhookKeyFile  string
}

func run(cfg runConfig) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Set up the CA authority.
	var auth *ca.Authority
	if cfg.standalone {
		var err error
		auth, err = ca.NewTestAuthority("cluster.local")
		if err != nil {
			return fmt.Errorf("generate dev CA: %w", err)
		}
		log.Printf("meridian-control: using ephemeral dev CA (trust domain: cluster.local)")
	} else {
		if cfg.caCertFile == "" || cfg.caKeyFile == "" || cfg.rootCertFile == "" {
			return fmt.Errorf("production mode requires --ca-cert, --ca-key, --root-cert")
		}
		var err error
		auth, err = loadCA(cfg.rootCertFile, cfg.caCertFile, cfg.caKeyFile, cfg.trustDomain)
		if err != nil {
			return fmt.Errorf("load CA: %w", err)
		}
		log.Printf("meridian-control: loaded CA from %s", cfg.caCertFile)
	}

	// Shared store and identity registry.
	st := store.NewMemory()
	reg := identity.NewRegistry()

	// REST server (CP-1) with CA issuance (PKI-3).
	restSrv := rest.NewServer(st, reg).WithCA(auth)
	httpServer := &http.Server{
		Addr:         cfg.restAddr,
		Handler:      restSrv.Handler(),
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}
	restErrCh := make(chan error, 1)
	go func() {
		log.Printf("meridian-control: REST + PKI listening on %s", cfg.restAddr)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			restErrCh <- err
		}
		restErrCh <- nil
	}()

	// Validating admission webhook (CP-5 / Phase 7). Only started when both
	// TLS flags are set — the apiserver requires HTTPS, so there is no plain
	// mode. Absent flags mean the deployment does not use the webhook.
	var webhookServer *http.Server
	webhookErrCh := make(chan error, 1)
	switch {
	case cfg.webhookCertFile != "" && cfg.webhookKeyFile != "":
		mux := http.NewServeMux()
		mux.Handle(k8s.ValidatePath, k8s.NewValidationWebhook())
		webhookServer = &http.Server{
			Addr:         cfg.webhookAddr,
			Handler:      mux,
			TLSConfig:    &tls.Config{MinVersion: tls.VersionTLS12},
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			IdleTimeout:  idleTimeout,
		}
		go func() {
			log.Printf("meridian-control: admission webhook listening on %s%s",
				cfg.webhookAddr, k8s.ValidatePath)
			err := webhookServer.ListenAndServeTLS(cfg.webhookCertFile, cfg.webhookKeyFile)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				webhookErrCh <- fmt.Errorf("admission webhook: %w", err)
			}
			webhookErrCh <- nil
		}()
	case cfg.webhookCertFile != "" || cfg.webhookKeyFile != "":
		return fmt.Errorf("admission webhook requires both --webhook-cert and --webhook-key")
	}

	// ADS gRPC server (CP-3).
	var grpcOpts []grpc.ServerOption
	if cfg.tlsCertFile != "" && cfg.tlsKeyFile != "" {
		serverCert, err := tls.LoadX509KeyPair(cfg.tlsCertFile, cfg.tlsKeyFile)
		if err != nil {
			return fmt.Errorf("load ADS TLS cert: %w", err)
		}
		grpcOpts = append(grpcOpts, ads.ServerTLSOption(auth, []tls.Certificate{serverCert}))
		log.Printf("meridian-control: ADS gRPC with mTLS on %s", cfg.adsAddr)
	} else {
		log.Printf("meridian-control: ADS gRPC (plain, no mTLS) on %s", cfg.adsAddr)
	}

	grpcServer := grpc.NewServer(grpcOpts...)
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(grpcServer, ads.NewServer(st))

	adsLn, err := net.Listen("tcp", cfg.adsAddr)
	if err != nil {
		return fmt.Errorf("ADS gRPC listen %s: %w", cfg.adsAddr, err)
	}
	adsErrCh := make(chan error, 1)
	go func() {
		if err := grpcServer.Serve(adsLn); err != nil {
			adsErrCh <- err
		}
		adsErrCh <- nil
	}()

	// Wait for shutdown signal or a server error.
	select {
	case err := <-restErrCh:
		if err != nil {
			return err
		}
	case err := <-adsErrCh:
		if err != nil {
			return err
		}
	case err := <-webhookErrCh:
		if err != nil {
			return err
		}
	case <-ctx.Done():
		log.Printf("meridian-control: shutdown signal received, draining")
	}

	grpcServer.GracefulStop()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if webhookServer != nil {
		if err := webhookServer.Shutdown(shutdownCtx); err != nil {
			return err
		}
	}
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		return err
	}
	return nil
}

// loadCA loads the Root + Intermediate CA from PEM files.
func loadCA(rootCertFile, interCertFile, interKeyFile, trustDomain string) (*ca.Authority, error) {
	rootPEM, err := readFile(rootCertFile)
	if err != nil {
		return nil, err
	}
	interPEM, err := readFile(interCertFile)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readFile(interKeyFile)
	if err != nil {
		return nil, err
	}
	rootCert, err := ca.DecodeCertPEM(rootPEM)
	if err != nil {
		return nil, fmt.Errorf("root cert: %w", err)
	}
	interCert, err := ca.DecodeCertPEM(interPEM)
	if err != nil {
		return nil, fmt.Errorf("intermediate cert: %w", err)
	}
	interKey, err := ca.DecodeKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("intermediate key: %w", err)
	}
	return ca.New(rootCert, interCert, interKey, trustDomain), nil
}

func readFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return data, nil
}
