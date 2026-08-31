package workloadapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joshuawu/meridian/internal/agent/svid"
	"github.com/joshuawu/meridian/internal/control/ca"
)

// shortTempSocket creates a temp directory with a short path and returns the
// socket path. macOS limits Unix socket paths to 104 bytes; t.TempDir() can
// produce paths exceeding that. Using /tmp directly keeps paths short.
func shortTempSocket(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "mwkld")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, name)
}

func makeEntry(t *testing.T, auth *ca.Authority) *svid.Entry {
	t.Helper()
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "ns", "svc")
	key, csr, err := ca.GenerateCSR(spiffeID)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	chain, err := auth.SignWorkloadSVID(csr, spiffeID)
	if err != nil {
		t.Fatalf("SignWorkloadSVID: %v", err)
	}
	return &svid.Entry{
		SpiffeID:  spiffeID,
		Leaf:      chain[0],
		Key:       key,
		Chain:     chain,
		ExpiresAt: chain[0].NotAfter,
	}
}

func TestServerSendsInitialBundle(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()
	entry := makeEntry(t, auth)
	store.Set(entry)

	socketPath := shortTempSocket(t, "w.sock")

	srv := NewServer(socketPath, store, auth)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan struct{})
	go func() {
		// Signal readiness after a short delay (listener is up).
		time.AfterFunc(50*time.Millisecond, func() { close(ready) })
		_ = srv.Serve(ctx)
	}()
	<-ready

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Read until the sentinel.
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, err := conn.Read(tmp)
		buf.Write(tmp[:n])
		if bytes.Contains(buf.Bytes(), []byte("---\n")) {
			break
		}
		if err != nil {
			if err != io.EOF {
				t.Fatalf("read: %v", err)
			}
			break
		}
	}

	// Must contain the leaf cert PEM.
	if !bytes.Contains(buf.Bytes(), []byte("-----BEGIN CERTIFICATE-----")) {
		t.Fatal("bundle contains no CERTIFICATE PEM block")
	}
	// Must contain the root cert.
	certCount := bytes.Count(buf.Bytes(), []byte("-----BEGIN CERTIFICATE-----"))
	if certCount < 2 {
		t.Fatalf("expected >= 2 CERTIFICATE blocks (leaf + root), got %d", certCount)
	}
}

func TestServerSendsRotationToSubscriber(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()

	socketPath := shortTempSocket(t, "w.sock")

	srv := NewServer(socketPath, store, auth)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(50 * time.Millisecond) // wait for listener

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))

	// Send the initial SVID now (subscriber should get it via rotation).
	store.Set(makeEntry(t, auth))

	var buf bytes.Buffer
	tmp := make([]byte, 8192)
	for {
		n, readErr := conn.Read(tmp)
		buf.Write(tmp[:n])
		if bytes.Contains(buf.Bytes(), []byte("---\n")) {
			break
		}
		if readErr != nil {
			t.Fatalf("read: %v", readErr)
		}
	}
	if !bytes.Contains(buf.Bytes(), []byte("-----BEGIN CERTIFICATE-----")) {
		t.Fatal("received no CERTIFICATE PEM block after SVID set")
	}
}

func TestCertSourceNilBeforeSVID(t *testing.T) {
	store := svid.NewStore()
	src := NewCertSource(store)

	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	cfg := src.TLSConfig(auth.TrustPool())
	// GetCertificate should fail when no SVID is set.
	_, err = cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err == nil {
		t.Fatal("expected error from GetCertificate when no SVID, got nil")
	}
}

func TestCertSourceReturnsTLSCert(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()
	store.Set(makeEntry(t, auth))

	src := NewCertSource(store)
	cfg := src.TLSConfig(auth.TrustPool())

	tlsCert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if tlsCert == nil || tlsCert.PrivateKey == nil {
		t.Fatal("GetCertificate returned nil or missing private key")
	}
}

func TestCertSourceClientCertificate(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()
	store.Set(makeEntry(t, auth))

	src := NewCertSource(store)
	cfg := src.TLSConfig(auth.TrustPool())

	tlsCert, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{})
	if err != nil {
		t.Fatalf("GetClientCertificate: %v", err)
	}
	if tlsCert == nil {
		t.Fatal("GetClientCertificate returned nil")
	}
}

func TestCertSourceUpdatesTLSCertOnRotation(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()
	e1 := makeEntry(t, auth)
	store.Set(e1)

	src := NewCertSource(store)
	cfg := src.TLSConfig(auth.TrustPool())

	cert1, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("first GetCertificate: %v", err)
	}

	// Rotate: issue a new SVID (different key, different serial).
	e2 := makeEntry(t, auth)
	store.Set(e2)

	cert2, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("second GetCertificate: %v", err)
	}
	// Verify the cert returned is from the new entry (check leaf serial).
	leaf1, _ := x509.ParseCertificate(cert1.Certificate[0])
	leaf2, _ := x509.ParseCertificate(cert2.Certificate[0])
	// Verify different serials OR different raw certs — proves rotation happened.
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 &&
		string(cert1.Certificate[0]) == string(cert2.Certificate[0]) {
		t.Fatal("GetCertificate returned same cert after rotation")
	}
}

// TestBundleParseRoundTrip verifies the PEM payload sent by the server can be
// parsed back into certificates.
func TestBundleParseRoundTrip(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()
	entry := makeEntry(t, auth)
	store.Set(entry)

	socketPath := shortTempSocket(t, "w2.sock")
	srv := NewServer(socketPath, store, auth)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	rawPEM, err := io.ReadAll(conn)
	if err != nil && err != io.EOF {
		// May receive partial data; ignore EOF after sentinel.
	}
	// Strip sentinel.
	rawPEM = bytes.TrimSuffix(bytes.TrimRight(rawPEM, "\n"), []byte("---"))
	rawPEM = bytes.TrimSpace(rawPEM)

	// Parse all certs.
	var certs []*x509.Certificate
	rest := rawPEM
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			t.Fatalf("parse certificate: %v", parseErr)
		}
		certs = append(certs, c)
	}
	if len(certs) < 2 {
		t.Fatalf("expected >= 2 certs (leaf + root), got %d", len(certs))
	}

}
