// Package workloadapi implements a minimal SPIFFE-compatible Workload API
// server for Phase 4 (PKI-4). It serves the current node SVID and root bundle
// to subscribers over a Unix domain socket using a simple newline-delimited
// PEM protocol. This intentionally avoids the go-spiffe gRPC proto dependency
// until that toolchain is provisioned; the seam is the CertSource interface,
// which the proxy and any go-spiffe client consume.
//
// Protocol: on connect the server immediately sends the current bundle (PEM
// blocks delimited by a single "---\n" line), then sends an update on every
// SVID rotation. The connection is read-only from the client's perspective
// (clients may close the connection to unsubscribe).
package workloadapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/joshuawu/meridian/internal/agent/svid"
	"github.com/joshuawu/meridian/internal/control/ca"
)

// CertSource is the read interface the node proxy uses to obtain a live
// *tls.Config updated on SVID rotation. The production implementation is
// backed by a *svid.Store; tests may inject a fake.
type CertSource interface {
	// TLSConfig returns a *tls.Config whose GetCertificate/GetClientCertificate
	// callbacks always return the latest SVID. Each call returns a new config;
	// the callbacks share the underlying store reference so they stay live.
	TLSConfig(trustPool *x509.CertPool) *tls.Config
}

// storeSource implements CertSource backed by an *svid.Store.
type storeSource struct {
	store *svid.Store
}

// NewCertSource wraps store as a CertSource.
func NewCertSource(store *svid.Store) CertSource {
	return &storeSource{store: store}
}

func (s *storeSource) TLSConfig(trustPool *x509.CertPool) *tls.Config {
	getCert := func() (*tls.Certificate, error) {
		e := s.store.Current()
		if e == nil {
			return nil, fmt.Errorf("workloadapi: no SVID available yet")
		}
		var certDER [][]byte
		for _, c := range e.Chain {
			certDER = append(certDER, c.Raw)
		}
		return &tls.Certificate{
			Certificate: certDER,
			PrivateKey:  e.Key,
			Leaf:        e.Leaf,
		}, nil
	}
	return &tls.Config{
		ClientCAs:  trustPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return getCert()
		},
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return getCert()
		},
	}
}

// socketServer is a minimal Workload API server. It listens on a Unix domain
// socket and pushes PEM bundles to each connected subscriber. It implements
// the Server interface from doc.go.
type socketServer struct {
	socketPath string
	store      *svid.Store
	trustPool  *x509.CertPool
	rootCert   *x509.Certificate
	logf       func(string, ...any)

	mu   sync.Mutex
	subs map[net.Conn]chan struct{}
}

// compile-time proof.
var _ Server = (*socketServer)(nil)

// NewServer returns a Server that will listen on socketPath. store must already
// hold (or eventually hold) the workload SVID; trustPool is the root CA pool
// to include in the bundle.
func NewServer(socketPath string, store *svid.Store, auth *ca.Authority) Server {
	return &socketServer{
		socketPath: socketPath,
		store:      store,
		trustPool:  auth.TrustPool(),
		rootCert:   auth.RootCert(),
		logf:       log.Printf,
		subs:       make(map[net.Conn]chan struct{}),
	}
}

// Serve listens on the Unix socket until ctx is cancelled.
func (s *socketServer) Serve(ctx context.Context) error {
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("workloadapi: listen %q: %w", s.socketPath, err)
	}
	defer func() { _ = ln.Close() }()

	// Close the listener when ctx is done so Accept unblocks.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	// Subscribe to SVID rotations and fan out to all connected clients.
	rotations := s.store.Subscribe()
	go s.broadcastRotations(ctx, rotations)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			s.logf("workloadapi: accept: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

// handleConn sends the current bundle and then waits for a rotation signal.
func (s *socketServer) handleConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	notify := make(chan struct{}, 1)
	s.mu.Lock()
	s.subs[conn] = notify
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subs, conn)
		s.mu.Unlock()
	}()

	// Send initial bundle immediately.
	if err := s.sendBundle(conn); err != nil {
		return
	}

	// Re-send on every rotation.
	for range notify {
		if err := s.sendBundle(conn); err != nil {
			return
		}
	}
}

func (s *socketServer) broadcastRotations(ctx context.Context, rotations <-chan *svid.Entry) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-rotations:
			if !ok {
				return
			}
			s.mu.Lock()
			for _, ch := range s.subs {
				select {
				case ch <- struct{}{}:
				default:
				}
			}
			s.mu.Unlock()
		}
	}
}

// sendBundle writes the current SVID leaf + chain + root as PEM blocks
// separated by a "---\n" sentinel.
func (s *socketServer) sendBundle(conn net.Conn) error {
	e := s.store.Current()
	if e == nil {
		return nil // not yet issued; client will receive the next rotation
	}

	var payload []byte
	// Leaf cert.
	payload = append(payload, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: e.Leaf.Raw,
	})...)
	// Intermediate chain.
	for _, c := range e.Chain[1:] {
		payload = append(payload, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})...)
	}
	// Root CA (trust anchor).
	if s.rootCert != nil {
		payload = append(payload, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: s.rootCert.Raw,
		})...)
	}
	// Sentinel to mark end of one bundle.
	payload = append(payload, []byte("---\n")...)

	_, err := conn.Write(payload)
	return err
}
