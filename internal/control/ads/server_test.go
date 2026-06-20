package ads

import (
	"context"
	"net"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/joshuawu/meridian/internal/cc2"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
)

type adsStreamClient = discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesClient

func samplePolicy(port uint16) wire.PolicyRule {
	return wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: 1, DstIdentity: 2, DstPort: port,
			Protocol: 6, Direction: wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	}
}

// newTestStream spins up the ADS server on an in-process bufconn dialer and
// returns an open client stream plus the backing store.
func newTestStream(t *testing.T) (*store.Memory, adsStreamClient, context.CancelFunc) {
	t.Helper()
	st := store.NewMemory()

	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(gs, NewServer(st))
	go func() { _ = gs.Serve(lis) }()

	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	stream, err := discoveryv3.NewAggregatedDiscoveryServiceClient(conn).StreamAggregatedResources(ctx)
	if err != nil {
		cancel()
		t.Fatalf("open stream: %v", err)
	}

	cleanup := func() {
		cancel()
		_ = conn.Close()
		gs.Stop()
		_ = lis.Close()
	}
	return st, stream, cleanup
}

func recvWithin(t *testing.T, stream adsStreamClient, d time.Duration) *discoveryv3.DiscoveryResponse {
	t.Helper()
	type result struct {
		resp *discoveryv3.DiscoveryResponse
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		r, e := stream.Recv()
		ch <- result{r, e}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("stream.Recv: %v", r.err)
		}
		return r.resp
	case <-time.After(d):
		t.Fatalf("timed out waiting for DiscoveryResponse")
		return nil
	}
}

// decodePolicies decodes a CDS DiscoveryResponse — one CC-2 resource per policy.
func decodePolicies(t *testing.T, resp *discoveryv3.DiscoveryResponse) []wire.PolicyRule {
	t.Helper()
	rules := make([]wire.PolicyRule, 0, len(resp.GetResources()))
	for i, res := range resp.GetResources() {
		r, err := cc2.DecodePolicyRule(res)
		if err != nil {
			t.Fatalf("decode resource[%d]: %v", i, err)
		}
		rules = append(rules, r)
	}
	return rules
}

func TestInitialSubscribePushesPolicy(t *testing.T) {
	st, stream, cleanup := newTestStream(t)
	defer cleanup()
	ctx := context.Background()
	if err := st.PutPolicy(ctx, samplePolicy(443)); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: resourcev3.ClusterType}); err != nil {
		t.Fatalf("send initial request: %v", err)
	}

	resp := recvWithin(t, stream, 5*time.Second)
	if resp.GetVersionInfo() != "1" {
		t.Fatalf("first push version = %q, want 1", resp.GetVersionInfo())
	}
	if resp.GetNonce() == "" {
		t.Fatalf("first push missing nonce")
	}
	rules := decodePolicies(t, resp)
	if len(rules) != 1 || rules[0].Key.DstPort != 443 {
		t.Fatalf("unexpected policy payload: %+v", rules)
	}
}

func TestStoreChangeTriggersOrderedRePush(t *testing.T) {
	st, stream, cleanup := newTestStream(t)
	defer cleanup()
	ctx := context.Background()

	// Subscribe to all four types in CDS, EDS, LDS, RDS order; drain initials.
	for _, typeURL := range pushOrder {
		if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: typeURL}); err != nil {
			t.Fatalf("subscribe %s: %v", typeURL, err)
		}
		_ = recvWithin(t, stream, 5*time.Second)
	}

	// One store change must re-push every subscribed type in make-before-break
	// order: CDS, EDS, LDS, RDS.
	if err := st.PutPolicy(ctx, samplePolicy(8080)); err != nil {
		t.Fatalf("mutate store: %v", err)
	}

	for i, want := range pushOrder {
		resp := recvWithin(t, stream, 5*time.Second)
		if got := resp.GetTypeUrl(); got != want {
			t.Fatalf("push %d type_url = %q, want %q (ordering violated)", i, got, want)
		}
	}
}

func TestAckAdvancesThenNackHoldsAcrossStream(t *testing.T) {
	st, stream, cleanup := newTestStream(t)
	defer cleanup()
	ctx := context.Background()

	// Initial subscribe + push v1.
	if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: resourcev3.ClusterType}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	v1 := recvWithin(t, stream, 5*time.Second)

	// ACK v1.
	if err := stream.Send(&discoveryv3.DiscoveryRequest{
		TypeUrl:       resourcev3.ClusterType,
		VersionInfo:   v1.GetVersionInfo(),
		ResponseNonce: v1.GetNonce(),
	}); err != nil {
		t.Fatalf("ack v1: %v", err)
	}

	// Store change → push v2.
	if err := st.PutPolicy(ctx, samplePolicy(9000)); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	v2 := recvWithin(t, stream, 5*time.Second)
	if v2.GetVersionInfo() != "2" {
		t.Fatalf("second push version = %q, want 2", v2.GetVersionInfo())
	}

	// NACK v2: the server must hold last-known-good and keep the stream alive.
	if err := stream.Send(&discoveryv3.DiscoveryRequest{
		TypeUrl:       resourcev3.ClusterType,
		VersionInfo:   v1.GetVersionInfo(), // client reverts to last-good
		ResponseNonce: v2.GetNonce(),
		ErrorDetail:   &spb.Status{Code: 3, Message: "rejected by test"},
	}); err != nil {
		t.Fatalf("nack v2: %v", err)
	}

	// A subsequent change still pushes (stream healthy after NACK) as v3.
	if err := st.PutPolicy(ctx, samplePolicy(9001)); err != nil {
		t.Fatalf("mutate after nack: %v", err)
	}
	v3 := recvWithin(t, stream, 5*time.Second)
	if v3.GetVersionInfo() != "3" {
		t.Fatalf("post-nack push version = %q, want 3", v3.GetVersionInfo())
	}
}
