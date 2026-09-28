// Package workloadapi implements the SPIFFE Workload API server for Phase 4
// (PKI-4). It serves the current node SVID and root trust bundle to workloads
// over a Unix domain socket using the standard SPIFFE Workload API gRPC
// contract, so any conformant client — in particular go-spiffe's X509Source —
// can consume it directly. X.509 responses stream: each subscriber receives
// the current material on connect and an update on every SVID rotation. JWT
// SVIDs are not issued by Meridian and those RPCs return Unimplemented.
//
// The CertSource seam is unchanged: the node proxy keeps obtaining live
// *tls.Config values backed by the same SVIDStore, without dialing the socket.
package workloadapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/joshuawu/meridian/internal/agent/svid"
	"github.com/joshuawu/meridian/internal/control/ca"
)

// securityHeader is the metadata key every Workload API request must carry
// (SPIFFE Workload API spec §4: clients set workload.spiffe.io = true).
const securityHeader = "workload.spiffe.io"

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

// grpcServer serves the SPIFFE Workload API over a Unix domain socket. It
// implements the Server interface from doc.go and the SpiffeWorkloadAPI gRPC
// service backed by the SVIDStore.
type grpcServer struct {
	workload.UnimplementedSpiffeWorkloadAPIServer

	socketPath string
	store      *svid.Store
	rootCert   *x509.Certificate
	logf       func(string, ...any)
}

// compile-time proof.
var _ Server = (*grpcServer)(nil)
var _ workload.SpiffeWorkloadAPIServer = (*grpcServer)(nil)

// NewServer returns a Server that will listen on socketPath. store must already
// hold (or eventually hold) the workload SVID; auth provides the root trust
// anchor served as the X.509 bundle.
func NewServer(socketPath string, store *svid.Store, auth *ca.Authority) Server {
	return &grpcServer{
		socketPath: socketPath,
		store:      store,
		rootCert:   auth.RootCert(),
		logf:       log.Printf,
	}
}

// Serve listens on the Unix socket until ctx is cancelled.
func (s *grpcServer) Serve(ctx context.Context) error {
	ln, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("workloadapi: listen %q: %w", s.socketPath, err)
	}

	gs := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(gs, s)

	// Stop the gRPC server (which closes the listener) when ctx is done.
	go func() {
		<-ctx.Done()
		gs.Stop()
	}()

	if err := gs.Serve(ln); err != nil && ctx.Err() == nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("workloadapi: serve: %w", err)
	}
	return nil
}

// FetchX509SVID streams the current SVID immediately and an update on every
// rotation, until the client disconnects or the server stops.
func (s *grpcServer) FetchX509SVID(_ *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := requireSecurityHeader(stream.Context()); err != nil {
		return err
	}
	rotations := s.store.Subscribe()
	defer s.store.Unsubscribe(rotations)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case e, ok := <-rotations:
			if !ok {
				return nil
			}
			resp, err := s.svidResponse(e)
			if err != nil {
				s.logf("workloadapi: build X509SVID response: %v", err)
				return status.Error(codes.Internal, "failed to marshal SVID")
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}

// FetchX509Bundles streams the trust bundle keyed by the local trust domain.
// The trust domain is derived from the SVID's SPIFFE ID, so the first send
// waits until the store holds an entry; re-sent on every rotation thereafter.
func (s *grpcServer) FetchX509Bundles(_ *workload.X509BundlesRequest, stream workload.SpiffeWorkloadAPI_FetchX509BundlesServer) error {
	if err := requireSecurityHeader(stream.Context()); err != nil {
		return err
	}
	rotations := s.store.Subscribe()
	defer s.store.Unsubscribe(rotations)

	for {
		select {
		case <-stream.Context().Done():
			return nil
		case e, ok := <-rotations:
			if !ok {
				return nil
			}
			resp, err := s.bundlesResponse(e)
			if err != nil {
				s.logf("workloadapi: build X509Bundles response: %v", err)
				return status.Error(codes.Internal, "failed to marshal trust bundle")
			}
			if err := stream.Send(resp); err != nil {
				return err
			}
		}
	}
}

// svidResponse marshals one store entry into the wire response: the chain as
// concatenated DER, the key as PKCS#8 DER, and the root cert as the bundle.
func (s *grpcServer) svidResponse(e *svid.Entry) (*workload.X509SVIDResponse, error) {
	var chainDER []byte
	for _, c := range e.Chain {
		chainDER = append(chainDER, c.Raw...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(e.Key)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	if s.rootCert == nil {
		return nil, fmt.Errorf("no root certificate configured")
	}
	return &workload.X509SVIDResponse{
		Svids: []*workload.X509SVID{{
			SpiffeId:    e.SpiffeID,
			X509Svid:    chainDER,
			X509SvidKey: keyDER,
			Bundle:      s.rootCert.Raw,
		}},
	}, nil
}

// bundlesResponse maps the local trust domain (from the entry's SPIFFE ID) to
// the root trust anchor DER.
func (s *grpcServer) bundlesResponse(e *svid.Entry) (*workload.X509BundlesResponse, error) {
	id, err := spiffeid.FromString(e.SpiffeID)
	if err != nil {
		return nil, fmt.Errorf("parse SVID SPIFFE ID %q: %w", e.SpiffeID, err)
	}
	if s.rootCert == nil {
		return nil, fmt.Errorf("no root certificate configured")
	}
	return &workload.X509BundlesResponse{
		Bundles: map[string][]byte{
			id.TrustDomain().IDString(): s.rootCert.Raw,
		},
	}, nil
}

// requireSecurityHeader enforces the SPIFFE Workload API security header on
// every request (fail-closed: absent header → InvalidArgument).
func requireSecurityHeader(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok || len(md.Get(securityHeader)) == 0 {
		return status.Error(codes.InvalidArgument, "security header missing from request")
	}
	return nil
}
