package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/joshuawu/meridian/internal/control/ca"
)

const (
	testTrustDomain = "cluster.local"
	testNodeID      = "node-a"
	testToken       = "projected-sa-token"
)

// stubValidator accepts exactly one token and binds it to nodeID (the
// TokenReview seam — the real TokenReviewAuthenticator talks to an apiserver).
type stubValidator struct {
	token  string
	nodeID string
}

func (s *stubValidator) ValidateToken(_ context.Context, token, _ string) (string, error) {
	if token != s.token {
		return "", fmt.Errorf("token rejected")
	}
	return s.nodeID, nil
}

// startTokenBootstrapServer runs a real ca.BootstrapServer on a loopback
// listener and returns its dial address. Cleanup stops the server.
func startTokenBootstrapServer(t *testing.T, validator ca.TokenValidator) string {
	t.Helper()
	auth, err := ca.NewTestAuthority(testTrustDomain)
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer()
	ca.NewBootstrapServer(auth, validator, "meridian-bootstrap").Register(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

// writeTokenFile writes token to a file in a temp dir and returns its path.
func writeTokenFile(t *testing.T, token string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestBootstrapFromTokenIssuesNodeCredential(t *testing.T) {
	addr := startTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken)

	boot, err := bootstrapFromToken(testCtx(t), addr, tokenPath, testTrustDomain, testNodeID)
	if err != nil {
		t.Fatalf("bootstrapFromToken: %v", err)
	}
	wantID := ca.NodeSPIFFEID(testTrustDomain, testNodeID)
	if boot.NodeSpiffeID != wantID {
		t.Errorf("NodeSpiffeID = %q, want %q", boot.NodeSpiffeID, wantID)
	}
	if boot.Key == nil {
		t.Fatal("Bootstrap.Key is nil — private key must be generated client-side")
	}
	if len(boot.Chain) == 0 {
		t.Fatal("Bootstrap.Chain is empty")
	}
	// LoadBootstrap inside the helper already verifies key↔cert match; double
	// check the leaf really carries our public key (key never left the agent).
	leafPub, ok := boot.Cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !leafPub.Equal(boot.Key.Public()) {
		t.Error("leaf certificate public key does not match generated private key")
	}
}

func TestBootstrapFromTokenTrimsTokenWhitespace(t *testing.T) {
	addr := startTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken+"\n")

	if _, err := bootstrapFromToken(testCtx(t), addr, tokenPath, testTrustDomain, testNodeID); err != nil {
		t.Fatalf("bootstrapFromToken with trailing newline: %v", err)
	}
}

func TestBootstrapFromTokenStripsURLScheme(t *testing.T) {
	addr := startTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken)

	// Operators may reuse the REST-style --control-addr value (https://host:port);
	// the helper must accept it as a gRPC target.
	if _, err := bootstrapFromToken(testCtx(t), "https://"+addr, tokenPath, testTrustDomain, testNodeID); err != nil {
		t.Fatalf("bootstrapFromToken with https:// prefix: %v", err)
	}
}

func TestBootstrapFromTokenRejectedToken(t *testing.T) {
	addr := startTokenBootstrapServer(t, &stubValidator{token: "other-token", nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken)

	_, err := bootstrapFromToken(testCtx(t), addr, tokenPath, testTrustDomain, testNodeID)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err = %v, want PermissionDenied", err)
	}
}

func TestBootstrapFromTokenMissingTokenFile(t *testing.T) {
	addr := startTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})

	if _, err := bootstrapFromToken(testCtx(t), addr, filepath.Join(t.TempDir(), "absent"), testTrustDomain, testNodeID); err == nil {
		t.Fatal("expected error for missing token file, got nil")
	}
}

func TestBootstrapFromTokenEmptyTokenFile(t *testing.T) {
	addr := startTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, "  \n")

	if _, err := bootstrapFromToken(testCtx(t), addr, tokenPath, testTrustDomain, testNodeID); err == nil {
		t.Fatal("expected error for empty token file, got nil")
	}
}

// TestObtainNodeBootstrapReusesPersistedCredential proves a restart does not
// re-spend the SA token: with a valid credential on disk, obtainNodeBootstrap
// must not dial the control plane at all (the addr here is unreachable and
// the token file does not exist).
func TestObtainNodeBootstrapReusesPersistedCredential(t *testing.T) {
	auth, err := ca.NewTestAuthority(testTrustDomain)
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	seeded, err := ca.IssueBootstrap(auth, testNodeID)
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bootstrap.crt")
	keyPath := filepath.Join(dir, "bootstrap.key")
	if err := seeded.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	boot, err := obtainNodeBootstrap(testCtx(t), "127.0.0.1:1",
		filepath.Join(dir, "no-token"), testTrustDomain, testNodeID, certPath, keyPath)
	if err != nil {
		t.Fatalf("obtainNodeBootstrap with persisted credential: %v", err)
	}
	if boot.NodeSpiffeID != seeded.NodeSpiffeID {
		t.Errorf("NodeSpiffeID = %q, want persisted %q", boot.NodeSpiffeID, seeded.NodeSpiffeID)
	}
	if boot.Cert.SerialNumber.Cmp(seeded.Cert.SerialNumber) != 0 {
		t.Error("returned credential is not the persisted one (serial mismatch)")
	}
}

// TestObtainNodeBootstrapBootstrapsWhenMissing covers the first boot: nothing
// on disk → RPC issues a credential and persists it; a second call must then
// reuse it without dialing (unreachable addr).
func TestObtainNodeBootstrapBootstrapsWhenMissing(t *testing.T) {
	addr := startTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken)
	dir := filepath.Join(t.TempDir(), "meridian") // exercises MkdirAll
	certPath := filepath.Join(dir, "bootstrap.crt")
	keyPath := filepath.Join(dir, "bootstrap.key")

	first, err := obtainNodeBootstrap(testCtx(t), addr, tokenPath, testTrustDomain, testNodeID, certPath, keyPath)
	if err != nil {
		t.Fatalf("obtainNodeBootstrap (first boot): %v", err)
	}
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("credential not persisted: %v", err)
	}

	second, err := obtainNodeBootstrap(testCtx(t), "127.0.0.1:1", tokenPath, testTrustDomain, testNodeID, certPath, keyPath)
	if err != nil {
		t.Fatalf("obtainNodeBootstrap (restart): %v", err)
	}
	if second.Cert.SerialNumber.Cmp(first.Cert.SerialNumber) != 0 {
		t.Error("restart minted a new credential instead of reusing the persisted one")
	}
}

// TestObtainNodeBootstrapReplacesCorruptCredential: unusable files on disk
// must fall through to a fresh token bootstrap, not fail startup.
func TestObtainNodeBootstrapReplacesCorruptCredential(t *testing.T) {
	addr := startTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "bootstrap.crt")
	keyPath := filepath.Join(dir, "bootstrap.key")
	if err := os.WriteFile(certPath, []byte("not a cert"), 0o644); err != nil {
		t.Fatalf("seed corrupt cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatalf("seed corrupt key: %v", err)
	}

	boot, err := obtainNodeBootstrap(testCtx(t), addr, tokenPath, testTrustDomain, testNodeID, certPath, keyPath)
	if err != nil {
		t.Fatalf("obtainNodeBootstrap with corrupt files: %v", err)
	}
	if want := ca.NodeSPIFFEID(testTrustDomain, testNodeID); boot.NodeSpiffeID != want {
		t.Errorf("NodeSpiffeID = %q, want %q", boot.NodeSpiffeID, want)
	}
	if _, err := ca.LoadBootstrapFiles(certPath, keyPath); err != nil {
		t.Errorf("corrupt files not replaced with usable credential: %v", err)
	}
}

func TestBootstrapNodeID(t *testing.T) {
	t.Run("node_name_env_wins", func(t *testing.T) {
		t.Setenv("NODE_NAME", "kubelet-node-name")
		id, err := bootstrapNodeID()
		if err != nil {
			t.Fatalf("bootstrapNodeID: %v", err)
		}
		if id != "kubelet-node-name" {
			t.Errorf("nodeID = %q, want NODE_NAME value", id)
		}
	})
	t.Run("hostname_fallback", func(t *testing.T) {
		t.Setenv("NODE_NAME", "")
		hostname, err := os.Hostname()
		if err != nil {
			t.Fatalf("os.Hostname: %v", err)
		}
		id, err := bootstrapNodeID()
		if err != nil {
			t.Fatalf("bootstrapNodeID: %v", err)
		}
		if id != hostname {
			t.Errorf("nodeID = %q, want hostname %q", id, hostname)
		}
	})
}

// TestBootstrapFromTokenSaveRoundTrip covers the startPhase4 handoff: the
// freshly obtained bootstrap is persisted and reloaded the way newRemoteSigner
// consumes it (LoadBootstrapFiles).
func TestBootstrapFromTokenSaveRoundTrip(t *testing.T) {
	addr := startTokenBootstrapServer(t, &stubValidator{token: testToken, nodeID: testNodeID})
	tokenPath := writeTokenFile(t, testToken)

	boot, err := bootstrapFromToken(testCtx(t), addr, tokenPath, testTrustDomain, testNodeID)
	if err != nil {
		t.Fatalf("bootstrapFromToken: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "bootstrap.crt")
	keyPath := filepath.Join(dir, "bootstrap.key")
	if err := boot.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := ca.LoadBootstrapFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadBootstrapFiles after Save: %v", err)
	}
	if reloaded.NodeSpiffeID != boot.NodeSpiffeID {
		t.Errorf("reloaded NodeSpiffeID = %q, want %q", reloaded.NodeSpiffeID, boot.NodeSpiffeID)
	}
}
