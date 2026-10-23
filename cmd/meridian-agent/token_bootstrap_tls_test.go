// TLS coverage for the token-bootstrap channel.
//
// The bootstrap RPC cannot use mTLS (it exists to obtain the node cert), so
// one-way TLS against a pre-distributed root is the only thing standing
// between the SA token and a passive eavesdropper. These tests pin that
// behaviour: with the right CA bundle the dial succeeds, with the wrong one
// the handshake fails closed, and the bundle-less dev path stays insecure on
// purpose.
//
// No build tag: pure Go, runs on any OS (T1).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/joshuawu/meridian/internal/control/ca"
)

// countingValidator records how many times the control plane was asked to
// redeem a token, so a test can assert the token never left the agent.
type countingValidator struct {
	stubValidator
	calls atomic.Int64
}

func (c *countingValidator) ValidateToken(ctx context.Context, token, audience string) (string, error) {
	c.calls.Add(1)
	return c.stubValidator.ValidateToken(ctx, token, audience)
}

// newSelfSignedServerCert returns a self-signed TLS server certificate valid
// for 127.0.0.1 together with its PEM encoding, which doubles as the root CA
// bundle a client pins it with (the cert is its own trust anchor).
func newSelfSignedServerCert(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "meridian-control-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign server cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse server cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert},
		ca.EncodeCertPEM(cert)
}

// startTLSTokenBootstrapServer runs a real ca.BootstrapServer behind one-way
// TLS on a loopback listener. It returns the dial address and the path to a
// PEM bundle holding the server's own (self-signed) root.
func startTLSTokenBootstrapServer(t *testing.T, validator ca.TokenValidator) (addr, caBundlePath string) {
	t.Helper()
	auth, err := ca.NewTestAuthority(testTrustDomain)
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	serverCert, caPEM := newSelfSignedServerCert(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{serverCert},
		MinVersion:   tls.VersionTLS13,
	})))
	ca.NewBootstrapServer(auth, validator, "meridian-bootstrap").Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String(), writeCABundle(t, caPEM)
}

// writeCABundle writes a PEM bundle to a temp file and returns its path.
func writeCABundle(t *testing.T, pemBytes []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatalf("write CA bundle: %v", err)
	}
	return path
}

// TestBootstrapFromTokenTLSWithMatchingCABundle: the production path — the
// pinned root matches the server, so the token is only ever spent over an
// authenticated channel.
func TestBootstrapFromTokenTLSWithMatchingCABundle(t *testing.T) {
	addr, caBundlePath := startTLSTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken)

	boot, err := bootstrapFromToken(testCtx(t), addr, caBundlePath, tokenPath, testTrustDomain, testNodeID)
	if err != nil {
		t.Fatalf("bootstrapFromToken over TLS with matching CA bundle: %v", err)
	}
	if want := ca.NodeSPIFFEID(testTrustDomain, testNodeID); boot.NodeSpiffeID != want {
		t.Errorf("NodeSpiffeID = %q, want %q", boot.NodeSpiffeID, want)
	}
	if boot.Key == nil {
		t.Error("Bootstrap.Key is nil — private key must be generated client-side")
	}
}

// TestBootstrapFromTokenTLSWrongCABundle: a MITM presenting a cert from
// another CA must be rejected by the handshake, before the token is sent.
func TestBootstrapFromTokenTLSWrongCABundle(t *testing.T) {
	validator := &countingValidator{stubValidator: stubValidator{token: testToken, nodeID: testNodeID}}
	addr, _ := startTLSTokenBootstrapServer(t, validator)
	tokenPath := writeTokenFile(t, testToken)

	// A bundle pinning an unrelated self-signed root.
	_, otherPEM := newSelfSignedServerCert(t)
	wrongBundle := writeCABundle(t, otherPEM)

	_, err := bootstrapFromToken(testCtx(t), addr, wrongBundle, tokenPath, testTrustDomain, testNodeID)
	if err == nil {
		t.Fatal("bootstrapFromToken succeeded against a server the CA bundle does not anchor")
	}
	if !strings.Contains(err.Error(), "tls: failed to verify certificate") {
		t.Errorf("err = %v, want a TLS verification failure", err)
	}
	// The point of pinning a root: the bearer token must not reach a peer the
	// bundle does not anchor, so the RPC must die in the handshake.
	if n := validator.calls.Load(); n != 0 {
		t.Errorf("control plane saw %d token redemption(s) despite a failed handshake, want 0", n)
	}
}

// TestBootstrapFromTokenTLSServerWithoutCABundle: an insecure client cannot
// talk to the TLS-only control plane, so a forgotten --bootstrap-ca-bundle
// fails loudly at startup instead of silently downgrading.
func TestBootstrapFromTokenTLSServerWithoutCABundle(t *testing.T) {
	addr, _ := startTLSTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken)

	if _, err := bootstrapFromToken(testCtx(t), addr, "", tokenPath, testTrustDomain, testNodeID); err == nil {
		t.Fatal("insecure dial to a TLS-only bootstrap server succeeded")
	}
}

// TestBootstrapFromTokenUnreadableCABundle: a missing or malformed bundle is a
// configuration error — fail closed rather than fall back to insecure.
func TestBootstrapFromTokenUnreadableCABundle(t *testing.T) {
	addr, _ := startTLSTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken)

	t.Run("missing_file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "absent.pem")
		if _, err := bootstrapFromToken(testCtx(t), addr, missing, tokenPath, testTrustDomain, testNodeID); err == nil {
			t.Fatal("expected error for missing CA bundle, got nil")
		}
	})
	t.Run("no_pem_certificates", func(t *testing.T) {
		junk := writeCABundle(t, []byte("not a certificate\n"))
		if _, err := bootstrapFromToken(testCtx(t), addr, junk, tokenPath, testTrustDomain, testNodeID); err == nil {
			t.Fatal("expected error for a bundle with no PEM certificates, got nil")
		}
	})
}

// TestBootstrapTransportCreds checks the credential selection in isolation:
// no bundle = insecure (dev), bundle = TLS, bad bundle = error.
func TestBootstrapTransportCreds(t *testing.T) {
	t.Run("no_bundle_is_insecure", func(t *testing.T) {
		creds, err := bootstrapTransportCreds("")
		if err != nil {
			t.Fatalf("bootstrapTransportCreds(\"\"): %v", err)
		}
		if got := creds.Info().SecurityProtocol; got != "insecure" {
			t.Errorf("SecurityProtocol = %q, want %q", got, "insecure")
		}
	})
	t.Run("bundle_is_tls", func(t *testing.T) {
		_, caPEM := newSelfSignedServerCert(t)
		creds, err := bootstrapTransportCreds(writeCABundle(t, caPEM))
		if err != nil {
			t.Fatalf("bootstrapTransportCreds with bundle: %v", err)
		}
		if got := creds.Info().SecurityProtocol; got != "tls" {
			t.Errorf("SecurityProtocol = %q, want %q", got, "tls")
		}
	})
	t.Run("empty_pem_rejected", func(t *testing.T) {
		if _, err := bootstrapTransportCreds(writeCABundle(t, nil)); err == nil {
			t.Fatal("expected error for an empty CA bundle, got nil")
		}
	})
}

// TestObtainNodeBootstrapOverTLS covers the startup path end to end: first
// boot dials the TLS control plane and persists the credential, and the
// restart reuses it without dialing at all (unreachable addr).
func TestObtainNodeBootstrapOverTLS(t *testing.T) {
	addr, caBundlePath := startTLSTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bootstrap.crt")
	keyPath := filepath.Join(dir, "bootstrap.key")

	first, err := obtainNodeBootstrap(testCtx(t), addr, caBundlePath, tokenPath,
		testTrustDomain, testNodeID, certPath, keyPath)
	if err != nil {
		t.Fatalf("obtainNodeBootstrap over TLS (first boot): %v", err)
	}

	second, err := obtainNodeBootstrap(testCtx(t), "127.0.0.1:1", caBundlePath, tokenPath,
		testTrustDomain, testNodeID, certPath, keyPath)
	if err != nil {
		t.Fatalf("obtainNodeBootstrap over TLS (restart): %v", err)
	}
	if second.Cert.SerialNumber.Cmp(first.Cert.SerialNumber) != 0 {
		t.Error("restart minted a new credential instead of reusing the persisted one")
	}
}
