package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joshuawu/meridian/internal/control/ca"
)

// writeBootstrapFiles mints a node bootstrap credential and writes it to PEM
// files in a temp dir, returning the cert and key paths.
func writeBootstrapFiles(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	boot, err := ca.IssueBootstrap(auth, "test-node")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}
	keyPEM, err := ca.EncodeKeyPEM(boot.Key)
	if err != nil {
		t.Fatalf("EncodeKeyPEM: %v", err)
	}
	dir := t.TempDir()
	certPath = filepath.Join(dir, "bootstrap.crt")
	keyPath = filepath.Join(dir, "bootstrap.key")
	if err := os.WriteFile(certPath, ca.EncodeCertPEM(boot.Chain...), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func TestNewRemoteSignerFromBootstrapFiles(t *testing.T) {
	certPath, keyPath := writeBootstrapFiles(t)

	signer, err := newRemoteSigner("https://control.example:9443", certPath, keyPath)
	if err != nil {
		t.Fatalf("newRemoteSigner: %v", err)
	}
	if signer == nil {
		t.Fatal("newRemoteSigner returned nil Signer")
	}
}

func TestNewRemoteSignerMissingCertFile(t *testing.T) {
	_, keyPath := writeBootstrapFiles(t)

	if _, err := newRemoteSigner("https://control.example:9443", "/nonexistent/bootstrap.crt", keyPath); err == nil {
		t.Fatal("expected error for missing bootstrap cert file, got nil")
	}
}

func TestNewRemoteSignerMissingKeyFile(t *testing.T) {
	certPath, _ := writeBootstrapFiles(t)

	if _, err := newRemoteSigner("https://control.example:9443", certPath, "/nonexistent/bootstrap.key"); err == nil {
		t.Fatal("expected error for missing bootstrap key file, got nil")
	}
}

func TestNewRemoteSignerEmptyControlAddr(t *testing.T) {
	certPath, keyPath := writeBootstrapFiles(t)

	if _, err := newRemoteSigner("", certPath, keyPath); err == nil {
		t.Fatal("expected error for empty control address, got nil")
	}
}
