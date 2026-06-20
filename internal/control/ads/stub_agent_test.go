package ads

import (
	"context"
	"net"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/joshuawu/meridian/internal/cc2"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
)

func quietStub(conn grpc.ClientConnInterface) *StubAgent {
	return NewStubAgent(conn, WithLogf(func(string, ...any) {}))
}

// dialServer starts a real MER-54 ADS server on a bufconn and returns a client
// connection to it.
func dialServer(t *testing.T, st *store.Memory) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(gs, NewServer(st))
	go func() { _ = gs.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		gs.Stop()
		_ = lis.Close()
	})
	return conn
}

func waitFor(t *testing.T, cond func() bool, d time.Duration, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within %v: %s", d, what)
}

func clusterVersion(s Snapshot) string { return s.Versions[resourcev3.ClusterType] }

func TestStubReceivesInitialThenUpdate(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutPolicy(ctx, samplePolicy(443)); err != nil {
		t.Fatalf("seed: %v", err)
	}

	stub := quietStub(dialServer(t, st))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = stub.Run(runCtx) }()

	waitFor(t, func() bool {
		s := stub.Snapshot()
		return len(s.Policies) == 1 && s.Policies[0].Key.DstPort == 443 && clusterVersion(s) != ""
	}, 5*time.Second, "initial policy received and ACKed")

	// A store change must propagate to the stub as a new accepted snapshot.
	if err := st.PutPolicy(ctx, samplePolicy(8080)); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	waitFor(t, func() bool {
		return len(stub.Snapshot().Policies) == 2
	}, 5*time.Second, "updated policy received")
}

func TestStubReconnectReReceivesCurrentState(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutPolicy(ctx, samplePolicy(443)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	stub := quietStub(dialServer(t, st))

	// Session 1.
	c1, cancel1 := context.WithCancel(ctx)
	done1 := make(chan error, 1)
	go func() { done1 <- stub.Run(c1) }()
	waitFor(t, func() bool { return len(stub.Snapshot().Policies) == 1 }, 5*time.Second, "session-1 initial")

	// Disconnect cleanly — Run must return (no leaked receive goroutine).
	cancel1()
	select {
	case err := <-done1:
		if err != nil {
			t.Fatalf("session-1 Run returned error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("session-1 Run did not return after cancel (goroutine leak)")
	}

	// State changes while the stub is disconnected.
	if err := st.PutPolicy(ctx, samplePolicy(9000)); err != nil {
		t.Fatalf("offline mutate: %v", err)
	}

	// Session 2 (reconnect): a fresh stream must re-subscribe and re-receive the
	// current (changed) state.
	c2, cancel2 := context.WithCancel(ctx)
	defer cancel2()
	go func() { _ = stub.Run(c2) }()
	waitFor(t, func() bool {
		return len(stub.Snapshot().Policies) == 2
	}, 5*time.Second, "session-2 re-receives current state")
}

// badServer is a fake ADS server that pushes a contract-violating Cluster
// resource and captures the client's reply, to exercise the NACK path.
type badServer struct {
	discoveryv3.UnimplementedAggregatedDiscoveryServiceServer
	gotNACK chan *discoveryv3.DiscoveryRequest
}

func (b *badServer) StreamAggregatedResources(srv discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	// Wait for the first subscription, then push undecodable JSON on the Cluster
	// channel.
	if _, err := srv.Recv(); err != nil {
		return err
	}
	bad, err := anypb.New(wrapperspb.Bytes([]byte("this is not json")))
	if err != nil {
		return err
	}
	if err := srv.Send(&discoveryv3.DiscoveryResponse{
		TypeUrl:     resourcev3.ClusterType,
		VersionInfo: "1",
		Nonce:       "n1",
		Resources:   []*anypb.Any{bad},
	}); err != nil {
		return err
	}
	// Drain the remaining subscriptions until the NACK arrives.
	for {
		req, err := srv.Recv()
		if err != nil {
			return err
		}
		if req.GetErrorDetail() != nil {
			select {
			case b.gotNACK <- req:
			default:
			}
			return nil
		}
	}
}

func TestStubNacksContractViolation(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	bs := &badServer{gotNACK: make(chan *discoveryv3.DiscoveryRequest, 1)}
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(gs, bs)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	stub := quietStub(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = stub.Run(ctx) }()

	select {
	case nack := <-bs.gotNACK:
		if nack.GetErrorDetail() == nil {
			t.Fatalf("expected NACK with error_detail, got %+v", nack)
		}
		if nack.GetTypeUrl() != resourcev3.ClusterType {
			t.Fatalf("NACK type_url = %q, want cluster", nack.GetTypeUrl())
		}
		if nack.GetResponseNonce() != "n1" {
			t.Fatalf("NACK nonce = %q, want n1", nack.GetResponseNonce())
		}
		if nack.GetVersionInfo() != "" {
			t.Fatalf("NACK must revert to last-accepted (empty), got %q", nack.GetVersionInfo())
		}
	case <-ctx.Done():
		t.Fatalf("no NACK received before timeout")
	}

	// The stub must not have adopted the rejected config.
	if s := stub.Snapshot(); len(s.Policies) != 0 || clusterVersion(s) != "" {
		t.Fatalf("stub adopted rejected config: %+v", s)
	}
}

func TestDecodeSnapshot(t *testing.T) {
	policyAny := func(r wire.PolicyRule) *anypb.Any {
		a, err := cc2.EncodePolicyRule(r)
		if err != nil {
			t.Fatalf("encode policy: %v", err)
		}
		return a
	}
	identityAny := func(id wire.Identity) *anypb.Any {
		a, err := cc2.EncodeIdentity(id)
		if err != nil {
			t.Fatalf("encode identity: %v", err)
		}
		return a
	}
	notBytesValue, err := anypb.New(wrapperspb.String("not a bytes value"))
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}
	badJSON, err := anypb.New(wrapperspb.Bytes([]byte("{not json")))
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}
	sampleIdentity := wire.Identity{ID: 7, SpiffeID: "spiffe://x/y", Name: "y"}

	tests := []struct {
		name    string
		resp    *discoveryv3.DiscoveryResponse
		wantErr bool
		wantLen int
	}{
		{"empty cluster", &discoveryv3.DiscoveryResponse{TypeUrl: resourcev3.ClusterType}, false, 0},
		{"one policy", &discoveryv3.DiscoveryResponse{TypeUrl: resourcev3.ClusterType, Resources: []*anypb.Any{policyAny(samplePolicy(1))}}, false, 1},
		{"many policies", &discoveryv3.DiscoveryResponse{TypeUrl: resourcev3.ClusterType, Resources: []*anypb.Any{policyAny(samplePolicy(1)), policyAny(samplePolicy(2))}}, false, 2},
		{"empty endpoint ok", &discoveryv3.DiscoveryResponse{TypeUrl: resourcev3.EndpointType}, false, 0},
		{"identity on endpoint ok", &discoveryv3.DiscoveryResponse{TypeUrl: resourcev3.EndpointType, Resources: []*anypb.Any{identityAny(sampleIdentity)}}, false, 0},
		{"kind mismatch: policy on endpoint", &discoveryv3.DiscoveryResponse{TypeUrl: resourcev3.EndpointType, Resources: []*anypb.Any{policyAny(samplePolicy(1))}}, true, 0},
		{"kind mismatch: identity on cluster", &discoveryv3.DiscoveryResponse{TypeUrl: resourcev3.ClusterType, Resources: []*anypb.Any{identityAny(sampleIdentity)}}, true, 0},
		{"not a bytesvalue", &discoveryv3.DiscoveryResponse{TypeUrl: resourcev3.ClusterType, Resources: []*anypb.Any{notBytesValue}}, true, 0},
		{"undecodable json", &discoveryv3.DiscoveryResponse{TypeUrl: resourcev3.ClusterType, Resources: []*anypb.Any{badJSON}}, true, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := decodeSnapshot(tc.resp)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got rules=%+v", rules)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rules) != tc.wantLen {
				t.Fatalf("len(rules) = %d, want %d", len(rules), tc.wantLen)
			}
		})
	}
}
