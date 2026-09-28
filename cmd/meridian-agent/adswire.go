package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/joshuawu/meridian/internal/agent/xds"
	"github.com/joshuawu/meridian/internal/control/ca"
	"github.com/joshuawu/meridian/internal/proxy"
	"github.com/joshuawu/meridian/pkg/wire"
)

// newPostApply returns the xds post-apply hook that refreshes the proxy's
// SPIFFE ID resolver from the client's full applied identity set after every
// ACKed snapshot. applied must return the client's last-applied identities
// (xds.Client.Applied); the CommitPlan itself carries only the delta, and the
// resolver replaces its whole table on each refresh.
func newPostApply(applied func() []wire.Identity, res *proxy.MapSpiffeIDResolver) xds.PostApplyFunc {
	return func(wire.CommitPlan) {
		res.Update(applied())
	}
}

// adsDialOption returns the gRPC transport credentials for the ADS stream.
// With bootstrap credential files it dials mTLS, presenting the node cert and
// verifying the server against the bootstrap chain (CC-4); without them it
// dials insecurely (dev/standalone against a plaintext control plane).
func adsDialOption(bootstrapCertPath, bootstrapKeyPath string) (grpc.DialOption, error) {
	if bootstrapCertPath == "" {
		return grpc.WithTransportCredentials(insecure.NewCredentials()), nil
	}
	boot, err := ca.LoadBootstrapFiles(bootstrapCertPath, bootstrapKeyPath)
	if err != nil {
		return nil, fmt.Errorf("ads dial: load bootstrap: %w", err)
	}
	tlsCert, err := boot.TLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("ads dial: bootstrap tls cert: %w", err)
	}
	trustPool := x509.NewCertPool()
	for _, c := range boot.Chain {
		trustPool.AddCert(c)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      trustPool,
		MinVersion:   tls.VersionTLS13,
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(cfg)), nil
}
