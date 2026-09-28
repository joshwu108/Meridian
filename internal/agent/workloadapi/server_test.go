package workloadapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	gospiffe "github.com/spiffe/go-spiffe/v2/workloadapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

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

// startServer launches the Workload API server on a fresh socket and waits
// for the socket file to appear.
func startServer(t *testing.T, store *svid.Store, auth *ca.Authority) (string, context.Context) {
	t.Helper()
	socketPath := shortTempSocket(t, "w.sock")
	srv := NewServer(socketPath, store, auth)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Serve(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			return socketPath, ctx
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("workload API socket %s did not appear", socketPath)
	return "", nil
}

// TestGoSpiffeX509SourceConsumesServer is the acceptance test for the gRPC
// Workload API: go-spiffe's X509Source (the standard SPIFFE client) must be
// able to fetch the SVID served from the SVIDStore.
func TestGoSpiffeX509SourceConsumesServer(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()
	entry := makeEntry(t, auth)
	store.Set(entry)

	socketPath, _ := startServer(t, store, auth)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	src, err := gospiffe.NewX509Source(ctx,
		gospiffe.WithClientOptions(gospiffe.WithAddr("unix://"+socketPath)))
	if err != nil {
		t.Fatalf("NewX509Source: %v", err)
	}
	defer src.Close()

	got, err := src.GetX509SVID()
	if err != nil {
		t.Fatalf("GetX509SVID: %v", err)
	}
	if got.ID.String() != entry.SpiffeID {
		t.Fatalf("SVID ID = %s, want %s", got.ID, entry.SpiffeID)
	}
	if len(got.Certificates) == 0 ||
		got.Certificates[0].SerialNumber.Cmp(entry.Leaf.SerialNumber) != 0 {
		t.Fatalf("SVID leaf does not match the stored entry")
	}
	if got.PrivateKey == nil {
		t.Fatal("SVID has no private key")
	}
}

// TestGoSpiffeX509SourceSeesRotation verifies a store rotation propagates to
// a connected go-spiffe client.
func TestGoSpiffeX509SourceSeesRotation(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()
	e1 := makeEntry(t, auth)
	store.Set(e1)

	socketPath, _ := startServer(t, store, auth)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	src, err := gospiffe.NewX509Source(ctx,
		gospiffe.WithClientOptions(gospiffe.WithAddr("unix://"+socketPath)))
	if err != nil {
		t.Fatalf("NewX509Source: %v", err)
	}
	defer src.Close()

	// Rotate.
	e2 := makeEntry(t, auth)
	store.Set(e2)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got, err := src.GetX509SVID()
		if err == nil && got.Certificates[0].SerialNumber.Cmp(e2.Leaf.SerialNumber) == 0 {
			return // rotation observed
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("client never observed the rotated SVID")
}

// TestGoSpiffeBundleServed verifies FetchX509Bundles serves the trust bundle
// for the trust domain.
func TestGoSpiffeBundleServed(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()
	store.Set(makeEntry(t, auth))

	socketPath, _ := startServer(t, store, auth)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	src, err := gospiffe.NewX509Source(ctx,
		gospiffe.WithClientOptions(gospiffe.WithAddr("unix://"+socketPath)))
	if err != nil {
		t.Fatalf("NewX509Source: %v", err)
	}
	defer src.Close()

	td := spiffeid.RequireTrustDomainFromString("cluster.local")
	bundle, err := src.GetX509BundleForTrustDomain(td)
	if err != nil {
		t.Fatalf("GetX509BundleForTrustDomain: %v", err)
	}
	if len(bundle.X509Authorities()) == 0 {
		t.Fatal("bundle has no X.509 authorities")
	}
	if !bundle.X509Authorities()[0].Equal(auth.RootCert()) {
		t.Fatal("bundle authority is not the CA root certificate")
	}
}

// TestFetchX509SVIDRejectsMissingSecurityHeader verifies the SPIFFE-mandated
// security header check: a raw gRPC client that omits the
// workload.spiffe.io metadata must be rejected with InvalidArgument.
func TestFetchX509SVIDRejectsMissingSecurityHeader(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()
	store.Set(makeEntry(t, auth))

	socketPath, _ := startServer(t, store, auth)

	conn, err := grpc.NewClient("unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := workload.NewSpiffeWorkloadAPIClient(conn).
		FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		t.Fatalf("FetchX509SVID open: %v", err)
	}
	_, err = stream.Recv()
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Recv error = %v (code %s), want InvalidArgument", err, status.Code(err))
	}
}

// TestServeStopsOnContextCancel verifies Serve returns promptly when the
// context is cancelled and does not report a spurious error.
func TestServeStopsOnContextCancel(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	store := svid.NewStore()
	socketPath := shortTempSocket(t, "w.sock")
	srv := NewServer(socketPath, store, auth)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, statErr := os.Stat(socketPath); statErr == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Serve returned %v after cancel, want nil", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after context cancel")
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
	leaf1, _ := x509.ParseCertificate(cert1.Certificate[0])
	leaf2, _ := x509.ParseCertificate(cert2.Certificate[0])
	if leaf1.SerialNumber.Cmp(leaf2.SerialNumber) == 0 &&
		string(cert1.Certificate[0]) == string(cert2.Certificate[0]) {
		t.Fatal("GetCertificate returned same cert after rotation")
	}
}
