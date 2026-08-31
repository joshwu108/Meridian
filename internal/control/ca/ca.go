// Package ca implements the Meridian CA hierarchy for PKI-1 (MER-74):
// an offline-style self-signed Root (P-384) and an in-process Intermediate
// (P-384) that signs workload SVIDs (ECDSA P-256, 24h TTL) and node
// certificates (ECDSA P-384, 7d TTL). All CSRs are validated fail-closed:
// wrong key curve, missing or extra SANs, and SPIFFE ID mismatches are typed
// errors, never silently ignored.
//
// Dependencies: stdlib crypto/x509, crypto/ecdsa only — no go-spiffe runtime
// dep in Phase 3. go-spiffe (Workload API) is a Phase-4 addition (PKI-3/4).
//
// Depguard: internal/control/ca is governed by the control-no-dataplane rule;
// it must not import bpf/ or internal/agent.
package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Certificate TTLs (Architecture D7: clock-skew buffer added as backdate).
const (
	RootTTL         = 10 * 365 * 24 * time.Hour
	IntermediateTTL = 365 * 24 * time.Hour
	// SVIDTTL is the workload SVID lifetime (PRD §4.5 / subsystem-04 PKI-1).
	SVIDTTL = 24 * time.Hour
	// NodeCertTTL is the node bootstrap credential lifetime (CC-4 / MER-75).
	NodeCertTTL = 7 * 24 * time.Hour
	// clockSkew is backdated from notBefore to absorb peer clock drift.
	clockSkew = 5 * time.Minute
)

// CSRValidationError is returned for any CSR that fails fail-closed validation:
// wrong key curve, disallowed SAN type, SPIFFE ID mismatch, or invalid URI.
type CSRValidationError struct {
	Reason string
}

func (e *CSRValidationError) Error() string {
	return "ca: CSR validation: " + e.Reason
}

// AuthorizationError is returned when a node is not permitted to request an
// SVID for the given workload identity (issuance authorization, PKI-1 spec §3).
type AuthorizationError struct {
	NodeID   string
	SpiffeID string
	Reason   string
}

func (e *AuthorizationError) Error() string {
	return fmt.Sprintf("ca: authorization denied: node %q cannot request SVID %q: %s",
		e.NodeID, e.SpiffeID, e.Reason)
}

// Authority holds the CA hierarchy: a Root (offline-style, present as trust
// anchor only) and an in-process Intermediate that performs signing.
// All methods are safe for concurrent use (no mutable state after construction).
type Authority struct {
	rootCert  *x509.Certificate
	interCert *x509.Certificate
	interKey  *ecdsa.PrivateKey
	trustPool *x509.CertPool // Root only; callers build inter pool from chain
	td        string         // SPIFFE trust domain, e.g. "cluster.local"
}

// New constructs an Authority from an already-generated Root and Intermediate.
// interKey is the Intermediate's private signing key; it never leaves this
// process (Architecture §4 / subsystem-04 risk #2).
func New(rootCert, interCert *x509.Certificate, interKey *ecdsa.PrivateKey, trustDomain string) *Authority {
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	return &Authority{
		rootCert:  rootCert,
		interCert: interCert,
		interKey:  interKey,
		trustPool: pool,
		td:        trustDomain,
	}
}

// NewTestAuthority generates an ephemeral Root + Intermediate CA suitable for
// unit tests and integration test fixtures. The keys are generated in-process;
// do NOT use this for production bootstrapping.
func NewTestAuthority(trustDomain string) (*Authority, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate root key: %w", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: "Meridian Test Root CA"},
		NotBefore:             time.Now().Add(-clockSkew),
		NotAfter:              time.Now().Add(RootTTL),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("ca: create root cert: %w", err)
	}
	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse root cert: %w", err)
	}

	interKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ca: generate intermediate key: %w", err)
	}
	interTmpl := &x509.Certificate{
		SerialNumber:          mustSerial(),
		Subject:               pkix.Name{CommonName: "Meridian Test Intermediate CA"},
		NotBefore:             time.Now().Add(-clockSkew),
		NotAfter:              time.Now().Add(IntermediateTTL),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	if err != nil {
		return nil, fmt.Errorf("ca: create intermediate cert: %w", err)
	}
	interCert, err := x509.ParseCertificate(interDER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse intermediate cert: %w", err)
	}

	return New(rootCert, interCert, interKey, trustDomain), nil
}

// SignWorkloadSVID validates csr against spiffeID and issues a SVID with a
// 24h TTL, signed by the Intermediate. The CSR MUST use a P-256 key and
// carry exactly one URI SAN equal to spiffeID.
//
// Returns the leaf cert + intermediate chain (caller appends root trust bundle
// as needed). Returns *CSRValidationError on any CSR violation — fail-closed.
func (a *Authority) SignWorkloadSVID(csr *x509.CertificateRequest, spiffeID string) ([]*x509.Certificate, error) {
	if err := a.validateWorkloadCSR(csr, spiffeID); err != nil {
		return nil, err
	}
	leaf, err := a.sign(csr, spiffeID, SVIDTTL)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{leaf, a.interCert}, nil
}

// SignNodeCert validates csr against nodeSpiffeID and issues a node credential
// with a 7d TTL, signed by the Intermediate. The CSR MUST use a P-384 key
// (node identity — CC-4 two-tier scheme). Returns *CSRValidationError on violation.
func (a *Authority) SignNodeCert(csr *x509.CertificateRequest, nodeSpiffeID string) ([]*x509.Certificate, error) {
	if err := a.validateNodeCSR(csr, nodeSpiffeID); err != nil {
		return nil, err
	}
	leaf, err := a.sign(csr, nodeSpiffeID, NodeCertTTL)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{leaf, a.interCert}, nil
}

// TrustPool returns a certificate pool containing the Root CA certificate,
// suitable for TLS config and chain verification.
func (a *Authority) TrustPool() *x509.CertPool { return a.trustPool }

// RootCert returns the Root CA certificate.
func (a *Authority) RootCert() *x509.Certificate { return a.rootCert }

// IntermediateCert returns the Intermediate CA certificate.
func (a *Authority) IntermediateCert() *x509.Certificate { return a.interCert }

// TrustDomain returns the SPIFFE trust domain string (e.g. "cluster.local").
func (a *Authority) TrustDomain() string { return a.td }

// NodeSPIFFEID constructs the canonical node SPIFFE ID for the given node ID.
// Format: spiffe://<trustDomain>/node/<nodeID>.
func NodeSPIFFEID(trustDomain, nodeID string) string {
	return fmt.Sprintf("spiffe://%s/node/%s", trustDomain, nodeID)
}

// WorkloadSPIFFEID constructs a workload SPIFFE ID for the given namespace and name.
// Format: spiffe://<trustDomain>/<namespace>/<name>.
func WorkloadSPIFFEID(trustDomain, namespace, name string) string {
	return fmt.Sprintf("spiffe://%s/%s/%s", trustDomain, namespace, name)
}

// EncodeCertPEM PEM-encodes one or more certificates.
func EncodeCertPEM(certs ...*x509.Certificate) []byte {
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: c.Raw,
		})...)
	}
	return out
}

// EncodeKeyPEM PEM-encodes an ECDSA private key (EC PRIVATE KEY block).
func EncodeKeyPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("ca: marshal EC key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// DecodeCertPEM parses the first CERTIFICATE PEM block.
func DecodeCertPEM(pemBytes []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("ca: no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// DecodeKeyPEM parses an EC PRIVATE KEY PEM block.
func DecodeKeyPEM(pemBytes []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("ca: no PEM block found")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parse EC key: %w", err)
	}
	return key, nil
}

// GenerateCSR generates a P-256 ECDSA key and a CSR for spiffeID. Intended
// for workload SVID requests (PKI-3, agent keygen phase).
func GenerateCSR(spiffeID string) (*ecdsa.PrivateKey, *x509.CertificateRequest, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate P-256 key: %w", err)
	}
	csr, err := buildCSR(key, spiffeID)
	if err != nil {
		return nil, nil, err
	}
	return key, csr, nil
}

// GenerateNodeCSR generates a P-384 ECDSA key and a CSR for nodeSpiffeID.
// Intended for node bootstrap credential requests (CC-4 / MER-75).
func GenerateNodeCSR(nodeSpiffeID string) (*ecdsa.PrivateKey, *x509.CertificateRequest, error) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate P-384 node key: %w", err)
	}
	csr, err := buildCSR(key, nodeSpiffeID)
	if err != nil {
		return nil, nil, err
	}
	return key, csr, nil
}

// ---- internal helpers ----

func (a *Authority) validateWorkloadCSR(csr *x509.CertificateRequest, spiffeID string) error {
	if err := csr.CheckSignature(); err != nil {
		return &CSRValidationError{Reason: fmt.Sprintf("signature invalid: %v", err)}
	}
	pk, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return &CSRValidationError{Reason: "workload key must be ECDSA"}
	}
	if pk.Curve != elliptic.P256() {
		return &CSRValidationError{Reason: "workload key must be P-256"}
	}
	return a.validateSPIFFESAN(csr, spiffeID)
}

func (a *Authority) validateNodeCSR(csr *x509.CertificateRequest, nodeSpiffeID string) error {
	if err := csr.CheckSignature(); err != nil {
		return &CSRValidationError{Reason: fmt.Sprintf("signature invalid: %v", err)}
	}
	pk, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return &CSRValidationError{Reason: "node key must be ECDSA"}
	}
	if pk.Curve != elliptic.P384() {
		return &CSRValidationError{Reason: "node key must be P-384"}
	}
	return a.validateSPIFFESAN(csr, nodeSpiffeID)
}

// validateSPIFFESAN enforces the SPIFFE CSR contract:
//   - no DNS, IP, or email SANs
//   - exactly one URI SAN, equal to wantSpiffeID
//   - URI scheme "spiffe", authority == a.td, non-empty path
func (a *Authority) validateSPIFFESAN(csr *x509.CertificateRequest, wantSpiffeID string) error {
	if len(csr.DNSNames) > 0 {
		return &CSRValidationError{Reason: "DNS SANs not allowed in SPIFFE CSR"}
	}
	if len(csr.IPAddresses) > 0 {
		return &CSRValidationError{Reason: "IP SANs not allowed in SPIFFE CSR"}
	}
	if len(csr.EmailAddresses) > 0 {
		return &CSRValidationError{Reason: "email SANs not allowed in SPIFFE CSR"}
	}
	if len(csr.URIs) != 1 {
		return &CSRValidationError{Reason: fmt.Sprintf("expected exactly 1 URI SAN, got %d", len(csr.URIs))}
	}
	got := csr.URIs[0].String()
	if got != wantSpiffeID {
		return &CSRValidationError{Reason: fmt.Sprintf("URI SAN %q does not match expected %q", got, wantSpiffeID)}
	}
	u := csr.URIs[0]
	if u.Scheme != "spiffe" {
		return &CSRValidationError{Reason: fmt.Sprintf("URI SAN scheme must be \"spiffe\", got %q", u.Scheme)}
	}
	if u.Host != a.td {
		return &CSRValidationError{Reason: fmt.Sprintf("URI SAN trust domain %q does not match %q", u.Host, a.td)}
	}
	if !strings.HasPrefix(u.Path, "/") || len(u.Path) < 2 {
		return &CSRValidationError{Reason: "URI SAN path must be non-empty"}
	}
	return nil
}

// sign issues a leaf certificate for spiffeID signed by the Intermediate.
func (a *Authority) sign(csr *x509.CertificateRequest, spiffeID string, ttl time.Duration) (*x509.Certificate, error) {
	spiffeURI, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("ca: parse SPIFFE ID %q: %w", spiffeID, err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: mustSerial(),
		Subject:      pkix.Name{CommonName: spiffeID},
		URIs:         []*url.URL{spiffeURI},
		NotBefore:    now.Add(-clockSkew),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.interCert, csr.PublicKey, a.interKey)
	if err != nil {
		return nil, fmt.Errorf("ca: sign certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// mustSerial generates a random 128-bit certificate serial number.
// Panics only on cryptographic hardware failure (should never happen in
// practice; the stdlib documents it can fail only on exhaustion).
func mustSerial() *big.Int {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("ca: generate serial: %v", err))
	}
	return new(big.Int).SetBytes(b)
}

// buildCSR creates and signs a CertificateRequest containing exactly one URI
// SAN equal to spiffeID, using key. No DNS/IP/email SANs are added.
func buildCSR(key *ecdsa.PrivateKey, spiffeID string) (*x509.CertificateRequest, error) {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("ca: parse SPIFFE ID for CSR: %w", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: spiffeID},
		URIs:    []*url.URL{u},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, fmt.Errorf("ca: create CSR: %w", err)
	}
	return x509.ParseCertificateRequest(der)
}
