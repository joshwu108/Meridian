package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/joshuawu/meridian/internal/control/ca"
	"github.com/joshuawu/meridian/pkg/wire"
)

// fakeSpiffeLookup implements SpiffeIDLookup with a fixed table.
type fakeSpiffeLookup struct {
	byID map[wire.IdentityID]string
}

func (f *fakeSpiffeLookup) LookupID(id wire.IdentityID) (string, bool) {
	uri, ok := f.byID[id]
	return uri, ok
}

// handshakedTLSPair builds an in-memory mTLS-style pair where the server
// presents a workload SVID for spiffeID. It returns the fully handshaked
// client-side *tls.Conn (what the dialer would hand the outbound handler)
// and the server-side *tls.Conn (the fake remote proxy).
func handshakedTLSPair(t *testing.T, auth *ca.Authority, spiffeID string) (*tls.Conn, *tls.Conn) {
	t.Helper()
	key, csr, err := ca.GenerateCSR(spiffeID)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	chain, err := auth.SignWorkloadSVID(csr, spiffeID)
	if err != nil {
		t.Fatalf("SignWorkloadSVID: %v", err)
	}
	var der [][]byte
	for _, c := range chain {
		der = append(der, c.Raw)
	}
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: der, PrivateKey: key, Leaf: chain[0]}},
		MinVersion:   tls.VersionTLS13,
	}
	// The client skips hostname verification (SVIDs carry URI SANs only);
	// peer certificates are still surfaced for the identity cross-check.
	clientCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13}

	rawClient, rawServer := net.Pipe()
	server := tls.Server(rawServer, serverCfg)
	client := tls.Client(rawClient, clientCfg)

	serverErr := make(chan error, 1)
	go func() { serverErr <- server.Handshake() }()
	if err := client.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	return client, server
}

// TestOutboundPeerIdentityMismatchCloses verifies that when the remote proxy's
// SPIFFE URI does not match the expected dst_identity, the connection is
// closed before any bytes are tunneled and the mismatch metric is recorded.
func TestOutboundPeerIdentityMismatchCloses(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	// Peer presents "attacker"; dst_identity 42 maps to "victim".
	upstreamClient, upstreamServer := handshakedTLSPair(t, auth,
		ca.WorkloadSPIFFEID("cluster.local", "ns", "attacker"))
	lookup := &fakeSpiffeLookup{byID: map[wire.IdentityID]string{
		42: ca.WorkloadSPIFFEID("cluster.local", "ns", "victim"),
	}}

	origDst := netip.MustParseAddrPort("10.0.0.5:8080")
	resolver := &fakeResolver{origDst: origDst, dstID: wire.IdentityID(42)}
	dialer := &fakeDialer{dialConn: upstreamClient}
	reg := prometheus.NewRegistry()
	metrics := NewProxyMetrics(reg)

	ln := newFakeListener()
	h := NewOutboundHandler(ln, resolver, dialer,
		WithOutboundLogf(func(string, ...any) {}),
		WithOutboundSpiffeIDLookup(lookup),
		WithOutboundMetrics(metrics),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	client, server := net.Pipe()
	ln.inject(server)
	_, _ = client.Write([]byte("secret"))

	// The upstream (fake remote proxy) must see the connection close without
	// ever receiving the tunneled bytes.
	_ = upstreamServer.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 16)
	n, readErr := upstreamServer.Read(buf)
	if readErr == nil || n > 0 {
		t.Fatalf("upstream received %d byte(s) (%q, err=%v) despite identity mismatch", n, buf[:n], readErr)
	}

	// The pod-side connection must be closed too.
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(buf); err == nil {
		t.Fatal("pod-side connection still open after identity mismatch")
	}

	got := testutil.ToFloat64(metrics.RequestsTotal.WithLabelValues("outbound", "peer-mismatch", "0", "42"))
	if got != 1 {
		t.Fatalf("peer-mismatch metric = %v, want 1", got)
	}
}

// TestOutboundPeerIdentityMatchTunnels verifies the happy path: when the peer
// URI matches the expected dst_identity the flow is tunneled as before.
func TestOutboundPeerIdentityMatchTunnels(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "ns", "backend")
	upstreamClient, upstreamServer := handshakedTLSPair(t, auth, spiffeID)
	lookup := &fakeSpiffeLookup{byID: map[wire.IdentityID]string{7: spiffeID}}

	resolver := &fakeResolver{origDst: netip.MustParseAddrPort("10.0.0.5:8080"), dstID: wire.IdentityID(7)}
	dialer := &fakeDialer{dialConn: upstreamClient}

	ln := newFakeListener()
	h := NewOutboundHandler(ln, resolver, dialer,
		WithOutboundLogf(func(string, ...any) {}),
		WithOutboundSpiffeIDLookup(lookup),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	client, server := net.Pipe()
	ln.inject(server)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = upstreamServer.SetDeadline(time.Now().Add(2 * time.Second))

	payload := []byte("hello backend")
	go func() { _, _ = client.Write(payload) }()

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(upstreamServer, buf); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Fatalf("upstream got %q, want %q", buf, payload)
	}
}

// TestOutboundPeerIdentityUnknownDstProceeds verifies that when the resolver
// has no mapping for dst_identity (e.g. before the first ADS snapshot) the
// cross-check cannot run and the flow proceeds — matching the pre-existing
// audit-only behavior rather than blackholing all traffic on cold start.
func TestOutboundPeerIdentityUnknownDstProceeds(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	upstreamClient, upstreamServer := handshakedTLSPair(t, auth,
		ca.WorkloadSPIFFEID("cluster.local", "ns", "backend"))
	lookup := &fakeSpiffeLookup{byID: map[wire.IdentityID]string{}} // empty table

	resolver := &fakeResolver{origDst: netip.MustParseAddrPort("10.0.0.5:8080"), dstID: wire.IdentityID(7)}
	dialer := &fakeDialer{dialConn: upstreamClient}

	ln := newFakeListener()
	h := NewOutboundHandler(ln, resolver, dialer,
		WithOutboundLogf(func(string, ...any) {}),
		WithOutboundSpiffeIDLookup(lookup),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	client, server := net.Pipe()
	ln.inject(server)
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	_ = upstreamServer.SetDeadline(time.Now().Add(2 * time.Second))

	payload := []byte("cold start")
	go func() { _, _ = client.Write(payload) }()

	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(upstreamServer, buf); err != nil {
		t.Fatalf("upstream read: %v", err)
	}
}
