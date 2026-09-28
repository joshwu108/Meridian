package ca

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// Bootstrap holds the two-tier node identity credential (CC-4 / MER-75):
// a node certificate (P-384, 7d TTL) distinct from workload SVIDs (P-256, 24h).
// This credential authenticates the agent↔control channel (ADS + SVID issuance).
//
// Standalone mode: operator provisions bootstrap.crt / bootstrap.key out-of-band
// (PRD §8 config). K8s TokenReview bootstrap is deferred to Phase 7 (PKI-2b).
type Bootstrap struct {
	// Cert is the node leaf certificate.
	Cert *x509.Certificate
	// Key is the node private key.
	Key *ecdsa.PrivateKey
	// Chain is the full certificate chain (leaf + intermediate).
	Chain []*x509.Certificate
	// NodeSpiffeID is the SPIFFE ID extracted from Cert's URI SAN.
	// Format: spiffe://<trust-domain>/node/<node-id>
	NodeSpiffeID string
}

// LoadBootstrapFiles loads the node bootstrap credential from PEM files on disk.
// certFile must contain the leaf certificate (and optionally intermediate
// certificates as additional PEM blocks); keyFile must be an EC PRIVATE KEY.
// Fails closed: a cert with a non-node URI SAN, missing key match, or no
// CERTIFICATE block is returned as an error, never silently accepted.
func LoadBootstrapFiles(certFile, keyFile string) (*Bootstrap, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read cert %q: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: read key %q: %w", keyFile, err)
	}
	return LoadBootstrap(certPEM, keyPEM)
}

// LoadBootstrap parses PEM-encoded certificate bytes (one or more CERTIFICATE
// blocks) and a single EC PRIVATE KEY block into a Bootstrap.
func LoadBootstrap(certPEM, keyPEM []byte) (*Bootstrap, error) {
	certs, err := parseCertChainPEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: parse certs: %w", err)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("bootstrap: no CERTIFICATE blocks in PEM")
	}
	leaf := certs[0]

	key, err := DecodeKeyPEM(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: parse key: %w", err)
	}

	// Verify the key matches the certificate's public key.
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("bootstrap: leaf cert public key is not ECDSA")
	}
	if !leafPub.Equal(&key.PublicKey) {
		return nil, fmt.Errorf("bootstrap: private key does not match certificate public key")
	}

	nodeSpiffeID, err := extractNodeSPIFFEID(leaf)
	if err != nil {
		return nil, err
	}

	return &Bootstrap{
		Cert:         leaf,
		Key:          key,
		Chain:        certs,
		NodeSpiffeID: nodeSpiffeID,
	}, nil
}

// Save writes the credential to PEM files on disk: the full certificate
// chain to certFile (0644) and the private key to keyFile (0600). It is the
// persistence counterpart of LoadBootstrapFiles, used by the token-bootstrap
// path (PKI-2b) so RemoteSigner can reload the credential on later starts.
// The key is written first: a cert without a key is useless but harmless,
// while the reverse could leave a stale cert paired with a missing key.
func (b *Bootstrap) Save(certFile, keyFile string) error {
	keyPEM, err := EncodeKeyPEM(b.Key)
	if err != nil {
		return fmt.Errorf("bootstrap: encode key: %w", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return fmt.Errorf("bootstrap: write key %q: %w", keyFile, err)
	}
	// WriteFile's mode applies only on creation; a pre-existing key file keeps
	// its old (possibly looser) mode, so enforce 0600 explicitly.
	if err := os.Chmod(keyFile, 0o600); err != nil {
		return fmt.Errorf("bootstrap: chmod key %q: %w", keyFile, err)
	}
	if err := os.WriteFile(certFile, EncodeCertPEM(b.Chain...), 0o644); err != nil {
		return fmt.Errorf("bootstrap: write cert %q: %w", certFile, err)
	}
	return nil
}

// TLSCertificate returns a tls.Certificate suitable for tls.Config.Certificates.
func (b *Bootstrap) TLSCertificate() (tls.Certificate, error) {
	certPEM := EncodeCertPEM(b.Chain...)
	keyPEM, err := EncodeKeyPEM(b.Key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("bootstrap: encode key: %w", err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// IssueBootstrap generates a new node bootstrap credential from auth for
// nodeID. Used in standalone mode when the control plane mints the initial
// node credential in-process (the operator alternative is external bootstrap
// files loaded via LoadBootstrapFiles).
func IssueBootstrap(auth *Authority, nodeID string) (*Bootstrap, error) {
	nodeSpiffeID := NodeSPIFFEID(auth.TrustDomain(), nodeID)
	nodeKey, csr, err := GenerateNodeCSR(nodeSpiffeID)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: generate node CSR for %q: %w", nodeID, err)
	}
	chain, err := auth.SignNodeCert(csr, nodeSpiffeID)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: sign node cert for %q: %w", nodeID, err)
	}
	return &Bootstrap{
		Cert:         chain[0],
		Key:          nodeKey,
		Chain:        chain,
		NodeSpiffeID: nodeSpiffeID,
	}, nil
}

// extractNodeSPIFFEID extracts and validates the SPIFFE node identity from cert.
// The cert must have exactly one URI SAN with scheme "spiffe" and path
// /node/<id> — any other shape is a configuration error (fail-closed).
func extractNodeSPIFFEID(cert *x509.Certificate) (string, error) {
	if len(cert.URIs) != 1 {
		return "", fmt.Errorf("bootstrap: node cert must have exactly 1 URI SAN, got %d", len(cert.URIs))
	}
	u := cert.URIs[0]
	if u.Scheme != "spiffe" {
		return "", fmt.Errorf("bootstrap: node cert URI SAN scheme must be \"spiffe\", got %q", u.Scheme)
	}
	if !strings.HasPrefix(u.Path, "/node/") || len(u.Path) <= len("/node/") {
		return "", fmt.Errorf("bootstrap: node cert URI SAN path must be /node/<id>, got %q", u.Path)
	}
	return u.String(), nil
}

// parseCertChainPEM decodes all CERTIFICATE PEM blocks from pemBytes.
// Returns an error only if pemBytes is non-empty and contains no CERTIFICATE
// blocks (to distinguish "empty file" from "wrong format").
func parseCertChainPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate DER: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
