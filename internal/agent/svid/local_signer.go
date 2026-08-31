package svid

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/joshuawu/meridian/internal/control/ca"
)

// LocalSigner implements Signer using an in-process CA authority. It is used
// in standalone mode (dev, single-host testing) where control plane and agent
// share the same process. The production Signer calls the control-plane
// FetchSVID gRPC over node-cert mTLS.
type LocalSigner struct {
	auth *ca.Authority
}

// NewLocalSigner wraps auth as a Signer.
func NewLocalSigner(auth *ca.Authority) *LocalSigner {
	return &LocalSigner{auth: auth}
}

// Sign validates the DER-encoded CSR and signs a workload SVID via the local CA.
func (s *LocalSigner) Sign(_ context.Context, csrDER []byte, spiffeID string) ([]*x509.Certificate, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("local signer: parse CSR: %w", err)
	}
	chain, err := s.auth.SignWorkloadSVID(csr, spiffeID)
	if err != nil {
		return nil, fmt.Errorf("local signer: sign workload SVID: %w", err)
	}
	return chain, nil
}
