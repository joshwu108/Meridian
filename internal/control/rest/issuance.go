package rest

// POST /svid/sign — PKI-3 SVID issuance endpoint.
//
// The agent posts a PEM-encoded CSR and the desired SPIFFE workload ID; the
// server validates the CSR, checks that the requesting node is authorised for
// that workload identity, and returns the signed certificate chain as PEM.
//
// Authentication: the caller must present a valid node TLS certificate (the
// bootstrap credential from PKI-2) on the mTLS channel. The node's SPIFFE ID
// is extracted from the peer cert and used for authorisation checks.
//
// Depguard: this file lives in internal/control and may import ca/.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/joshuawu/meridian/internal/control/ca"
)

// IssuanceAuthority is the subset of ca.Authority used by the issuance handler.
type IssuanceAuthority interface {
	SignWorkloadSVID(csr *x509.CertificateRequest, spiffeID string) ([]*x509.Certificate, error)
}

// WithCA adds SVID issuance support to the Server, registering the
// POST /svid/sign handler. Returns s for chaining.
func (s *Server) WithCA(auth IssuanceAuthority) *Server {
	s.auth = auth
	s.mux.HandleFunc("POST /svid/sign", s.handleSignSVID)
	return s
}

// signRequest is the POST /svid/sign body.
type signRequest struct {
	// CSRPEM is a PEM-encoded CERTIFICATE REQUEST block.
	CSRPEM string `json:"csr_pem"`
	// SpiffeID is the desired workload SPIFFE URI (validated against the CSR).
	SpiffeID string `json:"spiffe_id"`
}

// signResponse is the success body.
type signResponse struct {
	// ChainPEM holds the signed leaf + intermediate chain as concatenated PEM blocks.
	ChainPEM  string `json:"chain_pem"`
	ExpiresAt string `json:"expires_at"`
}

func (s *Server) handleSignSVID(w http.ResponseWriter, r *http.Request) {
	if s.auth == nil {
		writeError(w, http.StatusNotImplemented, "no_ca", "CA not configured on this server")
		return
	}

	// Node identity comes from the TLS peer cert (the PKI-2 bootstrap
	// credential); the serving http.Server must require client certs.
	nodeSpiffeID, err := nodeIDFromTLS(r.TLS)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthenticated", err.Error())
		return
	}

	var req signRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body", err.Error())
		return
	}
	if req.CSRPEM == "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", "csr_pem is required")
		return
	}
	if req.SpiffeID == "" {
		writeError(w, http.StatusUnprocessableEntity, "invalid_request", "spiffe_id is required")
		return
	}

	csr, err := parseCSRPEM(req.CSRPEM)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_csr", err.Error())
		return
	}

	// Authorisation: node may only request workload identities (not node certs).
	// Full cross-check against "which workloads run on this node" is a Phase 7
	// addition when the identity registry binds workload→node; for now we
	// enforce that the requested ID is a workload path (not /node/).
	if err := assertWorkloadSpiffeID(req.SpiffeID); err != nil {
		writeError(w, http.StatusForbidden, "unauthorized",
			fmt.Sprintf("node %q: %v", nodeSpiffeID, err))
		return
	}

	chain, err := s.auth.SignWorkloadSVID(csr, req.SpiffeID)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "sign_failed", err.Error())
		return
	}

	chainPEM := encodeCertsPEM(chain)
	resp := signResponse{
		ChainPEM:  string(chainPEM),
		ExpiresAt: chain[0].NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}
	writeJSON(w, http.StatusCreated, envelope{Data: resp})
}

// nodeIDFromTLS extracts and validates the node SPIFFE ID from a completed
// TLS connection's peer certificate. Returns an error if the connection is not
// mTLS or the peer cert is not a valid node cert.
func nodeIDFromTLS(state *tls.ConnectionState) (string, error) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("no TLS peer certificate (mTLS required)")
	}
	leaf := state.PeerCertificates[0]
	if len(leaf.URIs) != 1 {
		return "", fmt.Errorf("peer cert has %d URI SANs, want 1", len(leaf.URIs))
	}
	u := leaf.URIs[0]
	if u.Scheme != "spiffe" {
		return "", fmt.Errorf("peer cert URI SAN scheme %q, want spiffe", u.Scheme)
	}
	if !strings.HasPrefix(u.Path, "/node/") || len(u.Path) <= len("/node/") {
		return "", fmt.Errorf("peer cert is not a node identity (path %q)", u.Path)
	}
	return u.String(), nil
}

func parseCSRPEM(pemStr string) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("PEM block type %q, want CERTIFICATE REQUEST", block.Type)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func assertWorkloadSpiffeID(spiffeID string) error {
	if strings.Contains(spiffeID, "/node/") {
		return fmt.Errorf("node certs may not be issued via this endpoint")
	}
	if !strings.HasPrefix(spiffeID, "spiffe://") {
		return fmt.Errorf("spiffe_id must start with spiffe://")
	}
	return nil
}

func encodeCertsPEM(certs []*x509.Certificate) []byte {
	return ca.EncodeCertPEM(certs...)
}
