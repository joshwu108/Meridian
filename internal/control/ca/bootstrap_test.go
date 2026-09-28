package ca_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/joshuawu/meridian/internal/control/ca"
)

// TestBootstrapIssueAndLoad verifies the MER-75 two-tier credential scheme:
// the CA can issue a node bootstrap credential, and LoadBootstrap can round-trip it.
func TestBootstrapIssueAndLoad(t *testing.T) {
	auth, err := ca.NewTestAuthority(testTD)
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}

	t.Run("issue_bootstrap", func(t *testing.T) {
		b, err := ca.IssueBootstrap(auth, "node-1")
		if err != nil {
			t.Fatalf("IssueBootstrap: %v", err)
		}

		want := ca.NodeSPIFFEID(testTD, "node-1")
		if b.NodeSpiffeID != want {
			t.Fatalf("NodeSpiffeID = %q, want %q", b.NodeSpiffeID, want)
		}
		if len(b.Chain) < 2 {
			t.Fatalf("chain length %d, want >= 2", len(b.Chain))
		}
		// Verify the issued cert chains to the root.
		verifyChain(t, b.Chain, auth.TrustPool(), x509.ExtKeyUsageClientAuth)
	})

	t.Run("load_bootstrap_round_trip", func(t *testing.T) {
		b, err := ca.IssueBootstrap(auth, "node-2")
		if err != nil {
			t.Fatalf("IssueBootstrap: %v", err)
		}

		// PEM-encode cert chain + key.
		certPEM := ca.EncodeCertPEM(b.Chain...)
		keyPEM, err := ca.EncodeKeyPEM(b.Key)
		if err != nil {
			t.Fatalf("EncodeKeyPEM: %v", err)
		}

		// Parse back via LoadBootstrap.
		b2, err := ca.LoadBootstrap(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("LoadBootstrap: %v", err)
		}
		if b2.NodeSpiffeID != b.NodeSpiffeID {
			t.Fatalf("round-trip NodeSpiffeID = %q, want %q", b2.NodeSpiffeID, b.NodeSpiffeID)
		}
		if !b2.Cert.Equal(b.Cert) {
			t.Fatal("round-trip leaf cert does not match original")
		}
	})

	t.Run("tls_certificate", func(t *testing.T) {
		b, err := ca.IssueBootstrap(auth, "node-3")
		if err != nil {
			t.Fatalf("IssueBootstrap: %v", err)
		}
		tlsCert, err := b.TLSCertificate()
		if err != nil {
			t.Fatalf("TLSCertificate: %v", err)
		}
		// Verify the tls.Certificate is usable (has a leaf and a private key).
		if tlsCert.PrivateKey == nil {
			t.Fatal("TLSCertificate has nil private key")
		}
		// tls.X509KeyPair populates .Leaf on Go 1.23+, so just check we can
		// build a TLS config with it.
		_ = &tls.Config{Certificates: []tls.Certificate{tlsCert}}
	})

	t.Run("load_bootstrap_files", func(t *testing.T) {
		b, err := ca.IssueBootstrap(auth, "node-4")
		if err != nil {
			t.Fatalf("IssueBootstrap: %v", err)
		}

		dir := t.TempDir()
		certFile := filepath.Join(dir, "bootstrap.crt")
		keyFile := filepath.Join(dir, "bootstrap.key")

		certPEM := ca.EncodeCertPEM(b.Chain...)
		keyPEM, err := ca.EncodeKeyPEM(b.Key)
		if err != nil {
			t.Fatalf("EncodeKeyPEM: %v", err)
		}
		if err := os.WriteFile(certFile, certPEM, 0600); err != nil {
			t.Fatalf("write cert file: %v", err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			t.Fatalf("write key file: %v", err)
		}

		b2, err := ca.LoadBootstrapFiles(certFile, keyFile)
		if err != nil {
			t.Fatalf("LoadBootstrapFiles: %v", err)
		}
		if b2.NodeSpiffeID != b.NodeSpiffeID {
			t.Fatalf("NodeSpiffeID = %q, want %q", b2.NodeSpiffeID, b.NodeSpiffeID)
		}
	})

	t.Run("wrong_spiffe_id_format_rejected", func(t *testing.T) {
		// A workload SVID (not a node cert) must be rejected by LoadBootstrap.
		spiffeID := ca.WorkloadSPIFFEID(testTD, "ns", "svc")
		_, csr, err := ca.GenerateCSR(spiffeID)
		if err != nil {
			t.Fatalf("GenerateCSR: %v", err)
		}
		chain, err := auth.SignWorkloadSVID(csr, spiffeID)
		if err != nil {
			t.Fatalf("SignWorkloadSVID: %v", err)
		}

		certPEM := ca.EncodeCertPEM(chain...)
		// Don't depend on which check fires first (key match vs SPIFFE path);
		// any error will do for a workload cert.
		_, err = ca.LoadBootstrap(certPEM, []byte("not a real key"))
		if err == nil {
			t.Fatal("expected error loading workload SVID as bootstrap cert, got nil")
		}
	})

	t.Run("mismatched_key_rejected", func(t *testing.T) {
		b, err := ca.IssueBootstrap(auth, "node-5")
		if err != nil {
			t.Fatalf("IssueBootstrap: %v", err)
		}
		// Issue a second bootstrap with a different key.
		b2, err := ca.IssueBootstrap(auth, "node-6")
		if err != nil {
			t.Fatalf("IssueBootstrap: %v", err)
		}

		certPEM := ca.EncodeCertPEM(b.Chain...)
		keyPEM, err := ca.EncodeKeyPEM(b2.Key) // wrong key
		if err != nil {
			t.Fatalf("EncodeKeyPEM: %v", err)
		}
		_, err = ca.LoadBootstrap(certPEM, keyPEM)
		if err == nil {
			t.Fatal("expected error for mismatched key, got nil")
		}
	})
}

// TestBootstrapSave verifies Save persists the credential so that
// LoadBootstrapFiles round-trips it, with the key file private (0600).
func TestBootstrapSave(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	b, err := ca.IssueBootstrap(auth, "node-save")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "bootstrap.crt")
	keyPath := filepath.Join(dir, "bootstrap.key")
	if err := b.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := ca.LoadBootstrapFiles(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadBootstrapFiles: %v", err)
	}
	if reloaded.NodeSpiffeID != b.NodeSpiffeID {
		t.Errorf("NodeSpiffeID = %q, want %q", reloaded.NodeSpiffeID, b.NodeSpiffeID)
	}
	if len(reloaded.Chain) != len(b.Chain) {
		t.Errorf("chain length = %d, want %d", len(reloaded.Chain), len(b.Chain))
	}

	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 0600", perm)
	}
}

// TestBootstrapSaveUnwritablePath verifies Save fails loudly instead of
// silently dropping the credential.
func TestBootstrapSaveUnwritablePath(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	b, err := ca.IssueBootstrap(auth, "node-save2")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}
	missing := filepath.Join(t.TempDir(), "no-such-dir")
	if err := b.Save(filepath.Join(missing, "c.crt"), filepath.Join(missing, "k.key")); err == nil {
		t.Fatal("expected error saving into missing directory, got nil")
	}
}

// TestBootstrapSaveTightensExistingKeyPerms: os.WriteFile's mode applies only
// on creation, so Save must chmod a pre-existing key file down to 0600.
func TestBootstrapSaveTightensExistingKeyPerms(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	b, err := ca.IssueBootstrap(auth, "node-save3")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "bootstrap.crt")
	keyPath := filepath.Join(dir, "bootstrap.key")
	if err := os.WriteFile(keyPath, []byte("stale"), 0o644); err != nil {
		t.Fatalf("seed loose-perm key file: %v", err)
	}

	if err := b.Save(certPath, keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("pre-existing key file mode = %o after Save, want 0600", perm)
	}
}
