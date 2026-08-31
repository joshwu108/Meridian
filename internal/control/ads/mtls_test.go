package ads

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc/test/bufconn"

	"github.com/joshuawu/meridian/internal/control/ca"
	"github.com/joshuawu/meridian/internal/control/store"
)

// dialMTLS dials the bufconn listener with node-cert mTLS. It skips server
// hostname verification because SPIFFE certs carry URI SANs, not DNS SANs,
// so they won't match "bufnet" — we are testing client-auth semantics here.
func dialMTLS(t *testing.T, lis *bufconn.Listener, auth *ca.Authority, boot *ca.Bootstrap) *grpc.ClientConn {
	t.Helper()
	tlsCert, err := boot.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      auth.TrustPool(),
		// InsecureSkipVerify skips hostname checking only — we still verify the
		// server cert chain via VerifyPeerCertificate. Bufconn resolves to
		// "bufnet" which doesn't match the URI SAN on the server's node cert.
		InsecureSkipVerify: true, //nolint:gosec // test-only: chain verified below
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			// Manually verify the server cert chain against our root pool.
			if len(rawCerts) == 0 {
				return fmt.Errorf("server sent no certificate")
			}
			cert, parseErr := x509.ParseCertificate(rawCerts[0])
			if parseErr != nil {
				return parseErr
			}
			inter := x509.NewCertPool()
			for _, raw := range rawCerts[1:] {
				c, e := x509.ParseCertificate(raw)
				if e == nil {
					inter.AddCert(c)
				}
			}
			_, verifyErr := cert.Verify(x509.VerifyOptions{
				Roots:         auth.TrustPool(),
				Intermediates: inter,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			})
			return verifyErr
		},
		MinVersion: tls.VersionTLS13,
	}
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// startMTLSServer starts an ADS server requiring mTLS; returns the bufconn listener.
func startMTLSServer(t *testing.T, auth *ca.Authority) (*bufconn.Listener, *ca.Bootstrap) {
	t.Helper()

	// Issue a server cert (node cert for the control plane) and a client cert
	// (node cert for the agent). Both are signed by the same CA.
	serverBoot, err := ca.IssueBootstrap(auth, "control-plane")
	if err != nil {
		t.Fatalf("IssueBootstrap server: %v", err)
	}
	serverTLSCert, err := serverBoot.TLSCertificate()
	if err != nil {
		t.Fatalf("server TLSCertificate: %v", err)
	}

	agentBoot, err := ca.IssueBootstrap(auth, "node-1")
	if err != nil {
		t.Fatalf("IssueBootstrap agent: %v", err)
	}

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(ServerTLSOption(auth, []tls.Certificate{serverTLSCert}))
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(gs, NewServer(store.NewMemory()))
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(func() { gs.Stop(); _ = lis.Close() })

	return lis, agentBoot
}

// TestMTLSAuthenticatedClientCanStream verifies that a client presenting a
// valid node cert can establish an ADS stream.
func TestMTLSAuthenticatedClientCanStream(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}

	lis, agentBoot := startMTLSServer(t, auth)
	conn := dialMTLS(t, lis, auth, agentBoot)

	client := discoveryv3.NewAggregatedDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	stream, err := client.StreamAggregatedResources(ctx)
	if err != nil {
		t.Fatalf("StreamAggregatedResources: %v", err)
	}
	// Send an initial subscribe request to prove the stream is live.
	if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: "type.googleapis.com/envoy.config.cluster.v3.Cluster"}); err != nil {
		t.Fatalf("stream.Send: %v", err)
	}
}

// TestMTLSUnauthenticatedClientRejected verifies that a client without a
// certificate is rejected at the TLS handshake (unauthenticated stream rejected).
func TestMTLSUnauthenticatedClientRejected(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}

	lis, _ := startMTLSServer(t, auth)

	// Dial without any credentials.
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	client := discoveryv3.NewAggregatedDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.StreamAggregatedResources(ctx)
	if err == nil {
		t.Fatal("expected error for unauthenticated client, got nil")
	}
}

// TestMTLSWrongTrustDomainRejected verifies that a client cert from a different
// CA is rejected (attacker presenting a certificate not signed by our CA).
func TestMTLSWrongTrustDomainRejected(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	// Attacker uses a different CA.
	attackerAuth, err := ca.NewTestAuthority("attacker.example")
	if err != nil {
		t.Fatalf("attacker NewTestAuthority: %v", err)
	}
	attackerBoot, err := ca.IssueBootstrap(attackerAuth, "evil-node")
	if err != nil {
		t.Fatalf("attacker IssueBootstrap: %v", err)
	}

	lis, _ := startMTLSServer(t, auth)

	// Dial with attacker's cert but trust the real CA (server will reject it).
	attackerTLSCert, err := attackerBoot.TLSCertificate()
	if err != nil {
		t.Fatalf("attacker TLSCertificate: %v", err)
	}
	cfg := &tls.Config{
		Certificates:       []tls.Certificate{attackerTLSCert},
		RootCAs:            auth.TrustPool(), // trust the real CA for the server cert
		InsecureSkipVerify: true,             //nolint:gosec // test-only: testing client-auth rejection
		MinVersion:         tls.VersionTLS13,
	}
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	client := discoveryv3.NewAggregatedDiscoveryServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = client.StreamAggregatedResources(ctx)
	if err == nil {
		t.Fatal("expected error for client with wrong CA cert, got nil")
	}
}

// TestValidateNodeCert checks that node certs pass and workload SVIDs fail.
func TestValidateNodeCert(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}

	t.Run("valid_node_cert", func(t *testing.T) {
		boot, err := ca.IssueBootstrap(auth, "worker-1")
		if err != nil {
			t.Fatalf("IssueBootstrap: %v", err)
		}
		if err := validateNodeCert(boot.Cert); err != nil {
			t.Fatalf("validateNodeCert rejected a valid node cert: %v", err)
		}
	})

	t.Run("workload_svid_rejected", func(t *testing.T) {
		_, csr, err := ca.GenerateCSR(ca.WorkloadSPIFFEID("cluster.local", "ns", "svc"))
		if err != nil {
			t.Fatalf("GenerateCSR: %v", err)
		}
		chain, err := auth.SignWorkloadSVID(csr, ca.WorkloadSPIFFEID("cluster.local", "ns", "svc"))
		if err != nil {
			t.Fatalf("SignWorkloadSVID: %v", err)
		}
		if err := validateNodeCert(chain[0]); err == nil {
			t.Fatal("validateNodeCert accepted a workload SVID — want rejection")
		}
	})

	t.Run("no_uri_san_rejected", func(t *testing.T) {
		// Build a cert with no URI SANs (just a regular TLS cert).
		fakeCert := &x509.Certificate{}
		if err := validateNodeCert(fakeCert); err == nil {
			t.Fatal("validateNodeCert accepted cert with no URI SAN")
		}
	})
}

// TestExtractNodeID checks happy path and error cases.
func TestExtractNodeID(t *testing.T) {
	tests := []struct {
		uri     string
		wantID  string
		wantErr bool
	}{
		{"spiffe://cluster.local/node/worker-1", "worker-1", false},
		{"spiffe://cluster.local/node/a-b-c", "a-b-c", false},
		{"spiffe://cluster.local/ns/svc", "", true},   // workload, not node
		{"spiffe://cluster.local/node/", "", true},     // empty id
		{"not-a-uri", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.uri, func(t *testing.T) {
			id, err := ExtractNodeID(tc.uri)
			if (err != nil) != tc.wantErr {
				t.Fatalf("ExtractNodeID(%q) err=%v, wantErr=%v", tc.uri, err, tc.wantErr)
			}
			if !tc.wantErr && id != tc.wantID {
				t.Fatalf("got %q, want %q", id, tc.wantID)
			}
		})
	}
}
