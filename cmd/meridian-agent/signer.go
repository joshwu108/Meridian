package main

import (
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/joshuawu/meridian/internal/agent/svid"
	"github.com/joshuawu/meridian/internal/control/ca"
)

// newRemoteSigner builds the production SVID signer used when the agent is
// pointed at a control plane (--control-addr): it loads the node bootstrap
// credential (CC-4), presents it as the mTLS client certificate, and posts
// CSRs to the control plane's POST /svid/sign endpoint (PKI-3).
//
// The server is verified against the bootstrap certificate chain for now; the
// full trust-bundle distribution RPC arrives in Phase 7.
func newRemoteSigner(controlAddr, bootstrapCertPath, bootstrapKeyPath string) (svid.Signer, error) {
	if controlAddr == "" {
		return nil, fmt.Errorf("remote signer: control address is empty")
	}
	boot, err := ca.LoadBootstrapFiles(bootstrapCertPath, bootstrapKeyPath)
	if err != nil {
		return nil, fmt.Errorf("remote signer: load bootstrap: %w", err)
	}
	tlsCert, err := boot.TLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("remote signer: bootstrap tls cert: %w", err)
	}
	trustPool := x509.NewCertPool()
	for _, c := range boot.Chain {
		trustPool.AddCert(c)
	}
	endpoint := strings.TrimSuffix(controlAddr, "/") + "/svid/sign"
	return svid.NewRemoteSigner(endpoint, tlsCert, trustPool), nil
}
