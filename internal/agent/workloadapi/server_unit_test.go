package workloadapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/joshuawu/meridian/internal/agent/svid"
	"github.com/joshuawu/meridian/internal/control/ca"
)

func testGRPCServer(t *testing.T) (*grpcServer, *ca.Authority) {
	t.Helper()
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	srv, ok := NewServer("unused.sock", svid.NewStore(), auth).(*grpcServer)
	if !ok {
		t.Fatal("NewServer did not return a *grpcServer")
	}
	return srv, auth
}

func TestSvidResponseMarshalsEntry(t *testing.T) {
	srv, auth := testGRPCServer(t)
	e := makeEntry(t, auth)

	resp, err := srv.svidResponse(e)
	if err != nil {
		t.Fatalf("svidResponse: %v", err)
	}
	if len(resp.Svids) != 1 {
		t.Fatalf("Svids = %d, want 1", len(resp.Svids))
	}
	got := resp.Svids[0]
	if got.SpiffeId != e.SpiffeID {
		t.Fatalf("SpiffeId = %s, want %s", got.SpiffeId, e.SpiffeID)
	}
	if len(got.X509Svid) == 0 || len(got.X509SvidKey) == 0 || len(got.Bundle) == 0 {
		t.Fatal("svidResponse produced empty chain, key, or bundle")
	}
}

func TestSvidResponseFailsWithoutRootCert(t *testing.T) {
	srv, auth := testGRPCServer(t)
	srv.rootCert = nil

	if _, err := srv.svidResponse(makeEntry(t, auth)); err == nil {
		t.Fatal("expected error without root certificate, got nil")
	}
}

func TestBundlesResponseKeyedByTrustDomain(t *testing.T) {
	srv, auth := testGRPCServer(t)

	resp, err := srv.bundlesResponse(makeEntry(t, auth))
	if err != nil {
		t.Fatalf("bundlesResponse: %v", err)
	}
	der, ok := resp.Bundles["spiffe://cluster.local"]
	if !ok {
		t.Fatalf("bundles keys = %v, want spiffe://cluster.local", keysOf(resp.Bundles))
	}
	if len(der) == 0 {
		t.Fatal("bundle DER is empty")
	}
}

func TestBundlesResponseRejectsBadSpiffeID(t *testing.T) {
	srv, _ := testGRPCServer(t)

	if _, err := srv.bundlesResponse(&svid.Entry{SpiffeID: "not-a-spiffe-uri"}); err == nil {
		t.Fatal("expected error for malformed SPIFFE ID, got nil")
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestServeFailsOnUnusableSocketPath(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	srv := NewServer("/nonexistent-dir/w.sock", svid.NewStore(), auth)

	err = srv.Serve(context.Background())
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("Serve = %v, want listen error", err)
	}
}

// TestFetchX509BundlesRejectsMissingSecurityHeader covers the header check on
// the bundles stream (the SVID stream variant is covered elsewhere).
func TestFetchX509BundlesRejectsMissingSecurityHeader(t *testing.T) {
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
		FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		t.Fatalf("FetchX509Bundles open: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Recv error = %v, want InvalidArgument", err)
	}
}

// TestFetchX509BundlesStreamsBundle exercises the bundles RPC directly with a
// conformant client (header set): the first message must carry the root
// bundle keyed by the trust domain.
func TestFetchX509BundlesStreamsBundle(t *testing.T) {
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
	ctx = metadata.AppendToOutgoingContext(ctx, "workload.spiffe.io", "true")

	stream, err := workload.NewSpiffeWorkloadAPIClient(conn).
		FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		t.Fatalf("FetchX509Bundles open: %v", err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatalf("Recv: %v", err)
	}
	der, ok := resp.Bundles["spiffe://cluster.local"]
	if !ok || len(der) == 0 {
		t.Fatalf("bundles = %v, want spiffe://cluster.local entry", keysOf(resp.Bundles))
	}

	// A rotation triggers a re-send on the open stream.
	store.Set(makeEntry(t, auth))
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv after rotation: %v", err)
	}
}
