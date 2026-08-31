package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/joshuawu/meridian/internal/control/ca"
)

const testTD = "cluster.local"

// TestCAPrimitivesGate_MER74 is the armed gate for MER-74 (PKI-1 CA primitives).
//
// Covers:
//   - NewTestAuthority creates a Root+Intermediate that signs valid chains
//   - Workload SVIDs (P-256, 24h) verify against the root trust pool
//   - Node certs (P-384, 7d) verify against the root trust pool
//   - Wrong-curve workload CSR (P-384) → CSRValidationError
//   - Wrong-curve node CSR (P-256) → CSRValidationError
//   - Extra DNS SAN → CSRValidationError
//   - Extra IP SAN → CSRValidationError
//   - SPIFFE ID mismatch → CSRValidationError
//   - Wrong trust domain → CSRValidationError
//   - Non-spiffe URI scheme → CSRValidationError
//   - No URI SAN → CSRValidationError
//   - PEM encode/decode round-trips for keys and certs
func TestCAPrimitivesGate_MER74(t *testing.T) {
	auth, err := ca.NewTestAuthority(testTD)
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}

	t.Run("workload_svid_chain_verifies", func(t *testing.T) {
		spiffeID := ca.WorkloadSPIFFEID(testTD, "default", "svc-a")
		_, csr, err := ca.GenerateCSR(spiffeID)
		if err != nil {
			t.Fatalf("GenerateCSR: %v", err)
		}
		chain, err := auth.SignWorkloadSVID(csr, spiffeID)
		if err != nil {
			t.Fatalf("SignWorkloadSVID: %v", err)
		}
		if len(chain) < 2 {
			t.Fatalf("chain length %d, want >= 2", len(chain))
		}
		verifyChain(t, chain, auth.TrustPool(), x509.ExtKeyUsageServerAuth)

		leaf := chain[0]
		if len(leaf.URIs) != 1 || leaf.URIs[0].String() != spiffeID {
			t.Fatalf("leaf URIs = %v, want [%s]", leaf.URIs, spiffeID)
		}
		// TTL check: allow 1 minute tolerance for the clockSkew backdate.
		if leaf.NotAfter.Sub(leaf.NotBefore) < ca.SVIDTTL-time.Minute {
			t.Fatalf("SVID TTL too short: notBefore=%v notAfter=%v", leaf.NotBefore, leaf.NotAfter)
		}
	})

	t.Run("node_cert_chain_verifies", func(t *testing.T) {
		nodeID := ca.NodeSPIFFEID(testTD, "node-42")
		_, csr, err := ca.GenerateNodeCSR(nodeID)
		if err != nil {
			t.Fatalf("GenerateNodeCSR: %v", err)
		}
		chain, err := auth.SignNodeCert(csr, nodeID)
		if err != nil {
			t.Fatalf("SignNodeCert: %v", err)
		}
		if len(chain) < 2 {
			t.Fatalf("chain length %d, want >= 2", len(chain))
		}
		verifyChain(t, chain, auth.TrustPool(), x509.ExtKeyUsageClientAuth)

		leaf := chain[0]
		if leaf.NotAfter.Sub(leaf.NotBefore) < ca.NodeCertTTL-time.Minute {
			t.Fatalf("node cert TTL too short: notBefore=%v notAfter=%v", leaf.NotBefore, leaf.NotAfter)
		}
	})

	t.Run("wrong_curve_workload_p384_rejected", func(t *testing.T) {
		// P-384 key for a workload CSR must be rejected (workloads must use P-256).
		key384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey P-384: %v", err)
		}
		spiffeID := ca.WorkloadSPIFFEID(testTD, "ns", "svc-b")
		csr := makeBareCSR(t, key384, spiffeID)
		_, err = auth.SignWorkloadSVID(csr, spiffeID)
		assertCSRValidationError(t, err)
	})

	t.Run("wrong_curve_node_p256_rejected", func(t *testing.T) {
		// P-256 key for a node CSR must be rejected (nodes must use P-384).
		key256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey P-256: %v", err)
		}
		nodeID := ca.NodeSPIFFEID(testTD, "node-x")
		csr := makeBareCSR(t, key256, nodeID)
		_, err = auth.SignNodeCert(csr, nodeID)
		assertCSRValidationError(t, err)
	})

	t.Run("extra_dns_san_rejected", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		spiffeID := ca.WorkloadSPIFFEID(testTD, "ns", "svc-c")
		u, _ := url.Parse(spiffeID)
		csr := makeBareCSRWithExtra(t, key, u, []string{"evil.example.com"}, nil)
		_, err = auth.SignWorkloadSVID(csr, spiffeID)
		assertCSRValidationError(t, err)
	})

	t.Run("extra_ip_san_rejected", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		spiffeID := ca.WorkloadSPIFFEID(testTD, "ns", "svc-d")
		u, _ := url.Parse(spiffeID)
		csr := makeBareCSRWithExtra(t, key, u, nil, []net.IP{net.ParseIP("192.0.2.1")})
		_, err = auth.SignWorkloadSVID(csr, spiffeID)
		assertCSRValidationError(t, err)
	})

	t.Run("spiffe_id_mismatch_rejected", func(t *testing.T) {
		// CSR carries svc-e but caller requests svc-f — must be rejected.
		spiffeInCSR := ca.WorkloadSPIFFEID(testTD, "ns", "svc-e")
		_, csr, err := ca.GenerateCSR(spiffeInCSR)
		if err != nil {
			t.Fatalf("GenerateCSR: %v", err)
		}
		spiffeWant := ca.WorkloadSPIFFEID(testTD, "ns", "svc-f")
		_, err = auth.SignWorkloadSVID(csr, spiffeWant)
		assertCSRValidationError(t, err)
	})

	t.Run("wrong_trust_domain_rejected", func(t *testing.T) {
		badID := "spiffe://attacker.example/ns/svc-g"
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		csr := makeBareCSR(t, key, badID)
		_, err = auth.SignWorkloadSVID(csr, badID)
		assertCSRValidationError(t, err)
	})

	t.Run("non_spiffe_scheme_rejected", func(t *testing.T) {
		badID := "https://cluster.local/ns/svc-h"
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		csr := makeBareCSR(t, key, badID)
		_, err = auth.SignWorkloadSVID(csr, badID)
		assertCSRValidationError(t, err)
	})

	t.Run("no_uri_san_rejected", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		tmpl := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "no-san"}}
		der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
		if err != nil {
			t.Fatalf("CreateCertificateRequest: %v", err)
		}
		csr, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatalf("ParseCertificateRequest: %v", err)
		}
		spiffeID := ca.WorkloadSPIFFEID(testTD, "ns", "svc-i")
		_, err = auth.SignWorkloadSVID(csr, spiffeID)
		assertCSRValidationError(t, err)
	})

	t.Run("pem_round_trip_key", func(t *testing.T) {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		keyPEM, err := ca.EncodeKeyPEM(key)
		if err != nil {
			t.Fatalf("EncodeKeyPEM: %v", err)
		}
		parsed, err := ca.DecodeKeyPEM(keyPEM)
		if err != nil {
			t.Fatalf("DecodeKeyPEM: %v", err)
		}
		if !parsed.Equal(key) {
			t.Fatal("round-tripped key does not match original")
		}
	})

	t.Run("pem_round_trip_cert", func(t *testing.T) {
		certPEM := ca.EncodeCertPEM(auth.RootCert())
		parsedCert, err := ca.DecodeCertPEM(certPEM)
		if err != nil {
			t.Fatalf("DecodeCertPEM: %v", err)
		}
		if !parsedCert.Equal(auth.RootCert()) {
			t.Fatal("round-tripped cert does not match original")
		}
	})
}

// ---- helpers ----

// verifyChain checks that chain[0] verifies against pool with the given EKU,
// using chain[1:] as intermediates.
func verifyChain(t *testing.T, chain []*x509.Certificate, pool *x509.CertPool, eku x509.ExtKeyUsage) {
	t.Helper()
	inter := x509.NewCertPool()
	for _, c := range chain[1:] {
		inter.AddCert(c)
	}
	opts := x509.VerifyOptions{
		Roots:         pool,
		Intermediates: inter,
		CurrentTime:   chain[0].NotBefore.Add(time.Second),
		KeyUsages:     []x509.ExtKeyUsage{eku},
	}
	if _, err := chain[0].Verify(opts); err != nil {
		t.Fatalf("chain verification failed: %v", err)
	}
}

// assertCSRValidationError asserts that err is non-nil and is a *ca.CSRValidationError.
func assertCSRValidationError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("expected CSRValidationError, got nil")
	}
	var valErr *ca.CSRValidationError
	if !errors.As(err, &valErr) {
		t.Fatalf("expected *ca.CSRValidationError, got %T: %v", err, err)
	}
}

// makeBareCSR builds a CSR with exactly one URI SAN == spiffeID using key.
// Used to inject arbitrary key curves without going through GenerateCSR.
func makeBareCSR(t *testing.T, key *ecdsa.PrivateKey, spiffeID string) *x509.CertificateRequest {
	t.Helper()
	u, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", spiffeID, err)
	}
	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: spiffeID},
		URIs:    []*url.URL{u},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	return csr
}

// makeBareCSRWithExtra builds a CSR with extra DNS/IP SANs alongside a URI SAN.
func makeBareCSRWithExtra(t *testing.T, key *ecdsa.PrivateKey, uri *url.URL, dns []string, ips []net.IP) *x509.CertificateRequest {
	t.Helper()
	tmpl := &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "extra-san"},
		URIs:        []*url.URL{uri},
		DNSNames:    dns,
		IPAddresses: ips,
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	return csr
}
