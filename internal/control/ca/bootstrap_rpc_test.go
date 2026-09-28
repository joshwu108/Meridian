package ca

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// fakeValidator accepts exactly one token and maps it to a node ID.
type fakeValidator struct {
	token    string
	nodeID   string
	audience string
}

func (f *fakeValidator) ValidateToken(_ context.Context, token, audience string) (string, error) {
	if audience != f.audience {
		return "", fmt.Errorf("audience %q not accepted", audience)
	}
	if token != f.token {
		return "", fmt.Errorf("token rejected")
	}
	return f.nodeID, nil
}

// startBootstrapServer runs a BootstrapServer on a loopback listener and
// returns a connected client conn. Cleanup stops both.
func startBootstrapServer(t *testing.T, auth *Authority, validator TokenValidator) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	NewBootstrapServer(auth, validator, testAudience).Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestBootstrapWithTokenIssuesNodeCert(t *testing.T) {
	auth, err := NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("test authority: %v", err)
	}
	conn := startBootstrapServer(t, auth,
		&fakeValidator{token: "good-token", nodeID: "worker-1", audience: testAudience})

	nodeSpiffeID := NodeSPIFFEID("cluster.local", "worker-1")
	key, csr, err := GenerateNodeCSR(nodeSpiffeID)
	if err != nil {
		t.Fatalf("generate node CSR: %v", err)
	}
	csrPEM := encodeCSRPEMForTest(t, csr)

	resp, err := BootstrapWithToken(context.Background(), conn, "good-token", csrPEM)
	if err != nil {
		t.Fatalf("BootstrapWithToken: %v", err)
	}
	if resp.NodeSpiffeID != nodeSpiffeID {
		t.Fatalf("NodeSpiffeID = %q, want %q", resp.NodeSpiffeID, nodeSpiffeID)
	}
	if time.Until(resp.ExpiresAt) <= 0 {
		t.Fatalf("ExpiresAt %v is not in the future", resp.ExpiresAt)
	}

	// The returned chain must load as a Bootstrap with the client's own key
	// and verify against the authority's trust pool.
	keyPEM, err := EncodeKeyPEM(key)
	if err != nil {
		t.Fatalf("encode key: %v", err)
	}
	b, err := LoadBootstrap([]byte(resp.CertChainPEM), keyPEM)
	if err != nil {
		t.Fatalf("returned chain unusable as bootstrap: %v", err)
	}
	if b.NodeSpiffeID != nodeSpiffeID {
		t.Fatalf("bootstrap SPIFFE ID = %q, want %q", b.NodeSpiffeID, nodeSpiffeID)
	}
	inter := x509.NewCertPool()
	for _, c := range b.Chain[1:] {
		inter.AddCert(c)
	}
	if _, err := b.Cert.Verify(x509.VerifyOptions{
		Roots:         auth.TrustPool(),
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("issued cert does not verify against authority roots: %v", err)
	}
}

func TestBootstrapWithTokenRejectsBadToken(t *testing.T) {
	auth, err := NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("test authority: %v", err)
	}
	conn := startBootstrapServer(t, auth,
		&fakeValidator{token: "good-token", nodeID: "worker-1", audience: testAudience})

	_, csr, err := GenerateNodeCSR(NodeSPIFFEID("cluster.local", "worker-1"))
	if err != nil {
		t.Fatalf("generate node CSR: %v", err)
	}
	_, err = BootstrapWithToken(context.Background(), conn, "stolen-token",
		encodeCSRPEMForTest(t, csr))
	if err == nil {
		t.Fatalf("bad token accepted, want PermissionDenied")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied (err: %v)", status.Code(err), err)
	}
}

func TestBootstrapWithTokenRejectsCSRForOtherNode(t *testing.T) {
	auth, err := NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("test authority: %v", err)
	}
	conn := startBootstrapServer(t, auth,
		&fakeValidator{token: "good-token", nodeID: "worker-1", audience: testAudience})

	// Token authenticates worker-1 but the CSR claims worker-2: the server
	// must refuse to sign (fail closed, no cross-node issuance).
	_, csr, err := GenerateNodeCSR(NodeSPIFFEID("cluster.local", "worker-2"))
	if err != nil {
		t.Fatalf("generate node CSR: %v", err)
	}
	_, err = BootstrapWithToken(context.Background(), conn, "good-token",
		encodeCSRPEMForTest(t, csr))
	if err == nil {
		t.Fatalf("CSR for another node accepted, want error")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("status = %v, want PermissionDenied (err: %v)", status.Code(err), err)
	}
}

func TestBootstrapWithTokenRejectsMalformedRequest(t *testing.T) {
	auth, err := NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("test authority: %v", err)
	}
	conn := startBootstrapServer(t, auth,
		&fakeValidator{token: "good-token", nodeID: "worker-1", audience: testAudience})

	tests := []struct {
		name   string
		token  string
		csrPEM string
	}{
		{"empty token", "", "-----BEGIN CERTIFICATE REQUEST-----"},
		{"empty csr", "good-token", ""},
		{"garbage csr", "good-token", "not a pem block"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := BootstrapWithToken(context.Background(), conn, tt.token, tt.csrPEM)
			if err == nil {
				t.Fatalf("malformed request accepted, want InvalidArgument")
			}
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("status = %v, want InvalidArgument (err: %v)", status.Code(err), err)
			}
		})
	}
}

func encodeCSRPEMForTest(t *testing.T, csr *x509.CertificateRequest) string {
	t.Helper()
	pemBytes := EncodeCSRPEM(csr)
	if len(pemBytes) == 0 {
		t.Fatalf("EncodeCSRPEM returned empty output")
	}
	return string(pemBytes)
}
