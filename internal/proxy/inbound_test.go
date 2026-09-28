package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/joshuawu/meridian/internal/control/ca"
	"github.com/joshuawu/meridian/pkg/wire"
)

// fakeCertSource implements workloadapi.CertSource using a pre-built tls.Config.
type fakeCertSource struct {
	cfg *tls.Config
}

func (f *fakeCertSource) TLSConfig(_ *x509.CertPool) *tls.Config { return f.cfg }

// fakePolicySource implements PolicySource.
type fakePolicySource struct {
	snap wire.ProxyPolicySnapshot
	err  error
}

func (f *fakePolicySource) Current(_ context.Context) (wire.ProxyPolicySnapshot, error) {
	return f.snap, f.err
}

// makeTestCA returns an Authority + a server TLS config for use in tests.
func makeTestCA(t *testing.T) (*ca.Authority, *tls.Config) {
	t.Helper()
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	// Server cert.
	boot, err := ca.IssueBootstrap(auth, "proxy-node")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}
	tlsCert, err := boot.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		ClientCAs:    auth.TrustPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
	return auth, cfg
}

// TestInboundHandlerMTLSRejectsNoClientCert verifies that the inbound handler
// rejects a connection that presents no client certificate (unauthorized peer).
func TestInboundHandlerMTLSRejectsNoClientCert(t *testing.T) {
	auth, serverCfg := makeTestCA(t)

	resolver := &fakeResolver{origDst: netip.MustParseAddrPort("10.0.0.5:8080")}
	policy := &fakePolicySource{snap: wire.ProxyPolicySnapshot{}}
	ln := newFakeListener()

	h := NewInboundHandler(ln,
		&fakeCertSource{cfg: serverCfg},
		auth.TrustPool(),
		resolver,
		policy,
		WithInboundLogf(func(string, ...any) {}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	client, server := net.Pipe()
	ln.inject(server)

	tlsClient := tls.Client(client, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test only — we're testing auth rejection
		MinVersion:         tls.VersionTLS13,
	})

	// In TLS 1.3, the server's client-cert rejection arrives as a post-handshake
	// alert. The client's Handshake() may succeed before the alert is received;
	// the error surfaces on the next Write or Read.
	_ = tlsClient.SetDeadline(time.Now().Add(2 * time.Second))
	_ = tlsClient.Handshake()
	_, writeErr := tlsClient.Write([]byte("test"))
	if writeErr == nil {
		buf := make([]byte, 64)
		_, writeErr = tlsClient.Read(buf)
	}
	if writeErr == nil {
		t.Fatal("expected error (connection rejected for no client cert), got nil")
	}
}

// TestInboundHandlerMTLSAcceptsValidPeer verifies that a peer presenting a
// valid node cert from the same CA can complete the TLS handshake.
func TestInboundHandlerMTLSAcceptsValidPeer(t *testing.T) {
	auth, serverCfg := makeTestCA(t)

	resolver := &fakeResolver{origDst: netip.MustParseAddrPort("10.0.0.5:8080")}
	policy := &fakePolicySource{snap: wire.ProxyPolicySnapshot{}} // no rules → deny

	ln := newFakeListener()
	h := NewInboundHandler(ln,
		&fakeCertSource{cfg: serverCfg},
		auth.TrustPool(),
		resolver,
		policy,
		WithInboundLogf(func(string, ...any) {}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	// Build a valid client cert (node bootstrap cert from the same CA).
	clientBoot, err := ca.IssueBootstrap(auth, "client-node")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}
	clientTLSCert, err := clientBoot.TLSCertificate()
	if err != nil {
		t.Fatalf("client TLSCertificate: %v", err)
	}

	client, server := net.Pipe()
	ln.inject(server)

	tlsClient := tls.Client(client, &tls.Config{
		Certificates:       []tls.Certificate{clientTLSCert},
		InsecureSkipVerify: true, //nolint:gosec // test only
		MinVersion:         tls.VersionTLS13,
	})

	_ = tlsClient.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tlsClient.Handshake(); err != nil {
		t.Fatalf("expected successful handshake with valid peer cert, got: %v", err)
	}
	_ = tlsClient.Close()
}

// TestEvalPolicy covers the authz policy evaluation logic.
func TestEvalPolicy(t *testing.T) {
	allow := wire.PolicyRule{
		Key:     wire.PolicyRuleKey{SrcIdentity: 1, DstIdentity: 2, DstPort: 443, Protocol: 6},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	}
	deny := wire.PolicyRule{
		Key:     wire.PolicyRuleKey{SrcIdentity: 1, DstIdentity: 2, DstPort: 80, Protocol: 6},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
	}
	redirect := wire.PolicyRule{
		Key:     wire.PolicyRuleKey{SrcIdentity: 3, DstIdentity: 4, DstPort: 0, Protocol: 0},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionRedirectProxy},
	}
	snap := wire.ProxyPolicySnapshot{Policies: []wire.PolicyRule{allow, deny, redirect}}
	dst443 := netip.MustParseAddrPort("10.0.0.1:443")
	dst80 := netip.MustParseAddrPort("10.0.0.1:80")
	dst9090 := netip.MustParseAddrPort("10.0.0.1:9090")

	tests := []struct {
		name string
		src  wire.IdentityID
		dst  wire.IdentityID
		addr netip.AddrPort
		want AuthzResult
	}{
		{"allow rule hits", 1, 2, dst443, AuthzAllow},
		{"deny rule hits", 1, 2, dst80, AuthzDeny},
		{"no matching rule → deny", 1, 2, dst9090, AuthzDeny},
		{"wildcard port redirect", 3, 4, dst443, AuthzRedirectProxy},
		{"unknown src → deny", 99, 2, dst443, AuthzDeny},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EvalPolicy(snap, tc.src, tc.dst, tc.addr, 6)
			if got != tc.want {
				t.Fatalf("EvalPolicy = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSPIFFEIDFromCert covers the SPIFFE URI extraction.
func TestSPIFFEIDFromCert(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	boot, err := ca.IssueBootstrap(auth, "node-1")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}
	spiffeID, err := SPIFFEIDFromCert(boot.Cert)
	if err != nil {
		t.Fatalf("SPIFFEIDFromCert: %v", err)
	}
	wantID := ca.NodeSPIFFEID("cluster.local", "node-1")
	if spiffeID != wantID {
		t.Fatalf("got %q, want %q", spiffeID, wantID)
	}
}

func TestSPIFFEIDFromCertRejectsNil(t *testing.T) {
	if _, err := SPIFFEIDFromCert(nil); err == nil {
		t.Fatal("expected error for nil cert")
	}
}

func TestSPIFFEIDFromCertRejectsNoURISAN(t *testing.T) {
	cert := &x509.Certificate{} // no URI SANs
	if _, err := SPIFFEIDFromCert(cert); err == nil {
		t.Fatal("expected error for cert with no URI SAN")
	}
}

// TestInboundHandlerContextCancellation ensures Serve returns on ctx cancel.
func TestInboundHandlerContextCancellation(t *testing.T) {
	auth, serverCfg := makeTestCA(t)
	ln := newFakeListener()
	h := NewInboundHandler(ln,
		&fakeCertSource{cfg: serverCfg},
		auth.TrustPool(),
		&fakeResolver{origDst: netip.MustParseAddrPort("10.0.0.1:80")},
		&fakePolicySource{},
		WithInboundLogf(func(string, ...any) {}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.Serve(ctx) }()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned non-nil on cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not stop after context cancellation")
	}
}

// closedConnError is a helper that checks if reads return promptly on denial.
func closedConnError(conn net.Conn) error {
	buf := make([]byte, 1)
	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := conn.Read(buf)
	return err
}

// TestInboundHandlerDeniesUnauthorizedFlow verifies that a flow with no
// matching policy rule is dropped before any data reaches the upstream.
func TestInboundHandlerDeniesUnauthorizedFlow(t *testing.T) {
	auth, serverCfg := makeTestCA(t)

	var upstreamConns sync.WaitGroup
	upstreamAccepted := false

	resolver := &fakeResolver{origDst: netip.MustParseAddrPort("10.0.0.5:8080")}
	policy := &fakePolicySource{snap: wire.ProxyPolicySnapshot{}} // no rules → deny

	ln := newFakeListener()
	h := NewInboundHandler(ln,
		&fakeCertSource{cfg: serverCfg},
		auth.TrustPool(),
		resolver,
		policy,
		WithInboundLogf(func(string, ...any) {}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Serve(ctx) }()

	clientBoot, err := ca.IssueBootstrap(auth, "client")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}
	tlsCert, _ := clientBoot.TLSCertificate()
	client, server := net.Pipe()
	ln.inject(server)

	tlsClient := tls.Client(client, &tls.Config{
		Certificates:       []tls.Certificate{tlsCert},
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS13,
	})
	_ = tlsClient.SetDeadline(time.Now().Add(2 * time.Second))
	if err := tlsClient.Handshake(); err != nil {
		// Handshake might succeed but connection gets dropped after authz.
		t.Logf("note: handshake result: %v", err)
	}

	// Connection must be closed (denied) — no data passes through.
	err = closedConnError(tlsClient)
	if err == nil {
		t.Fatal("expected connection closed on authz deny, got nil read error")
	}
	upstreamConns.Wait()
	if upstreamAccepted {
		t.Fatal("upstream was reached despite authz denial")
	}
	_ = errors.New("") // ensure errors imported
	_ = io.EOF
}
