package xds

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/joshuawu/meridian/internal/control/ads"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
)

// fakeWriter records applied CommitPlans and maintains the cumulative state, so a
// test can assert what the client landed "in the kernel".
type fakeWriter struct {
	mu         sync.Mutex
	applies    int
	failNext   bool
	policies   map[wire.PolicyRuleKey]wire.PolicyRule
	identities map[wire.IdentityID]wire.Identity
}

func newFakeWriter() *fakeWriter {
	return &fakeWriter{
		policies:   map[wire.PolicyRuleKey]wire.PolicyRule{},
		identities: map[wire.IdentityID]wire.Identity{},
	}
}

func (w *fakeWriter) Apply(_ context.Context, plan wire.CommitPlan) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failNext {
		w.failNext = false
		return context.DeadlineExceeded // any error; client must hold last-known-good
	}
	w.applies++
	for _, id := range plan.IdentityUpserts {
		w.identities[id.ID] = id
	}
	for _, id := range plan.IdentityDeletes {
		delete(w.identities, id)
	}
	for _, p := range plan.PolicyUpserts {
		w.policies[p.Key] = p
	}
	for _, k := range plan.PolicyDeletes {
		delete(w.policies, k)
	}
	return nil
}

func (w *fakeWriter) counts() (pol, ident int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.policies), len(w.identities)
}

func samplePolicy(port uint16) wire.PolicyRule {
	return wire.PolicyRule{
		Key:     wire.PolicyRuleKey{SrcIdentity: 1, DstIdentity: 2, DstPort: port, Protocol: 6, Direction: wire.DirectionIngress},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	}
}

func sampleIdentity(id wire.IdentityID, name string) wire.Identity {
	return wire.Identity{ID: id, SpiffeID: "spiffe://x/" + name, Name: name}
}

func dialServer(t *testing.T, st *store.Memory) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(gs, ads.NewServer(st))
	go func() { _ = gs.Serve(lis) }()
	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(); gs.Stop(); _ = lis.Close() })
	return conn
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("condition not met within timeout: %s", what)
}

func TestClientAppliesAndUpdates(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutIdentity(ctx, sampleIdentity(2, "svc")); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	if err := st.PutPolicy(ctx, samplePolicy(443)); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	w := newFakeWriter()
	c := NewClient(dialServer(t, st), w, WithLogf(func(string, ...any) {}))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = c.Run(runCtx) }()

	waitFor(t, func() bool { p, i := w.counts(); return p == 1 && i == 1 }, "initial snapshot applied")

	// A store change propagates to the kernel via a fresh CommitPlan.
	if err := st.PutPolicy(ctx, samplePolicy(8080)); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	waitFor(t, func() bool { p, _ := w.counts(); return p == 2 }, "policy add applied")

	pols, idents := c.Applied()
	if len(pols) != 2 || len(idents) != 1 {
		t.Fatalf("Applied() = %d policies, %d identities; want 2,1", len(pols), len(idents))
	}
}

// badServer pushes a contract-violating Cluster resource to exercise the NACK path.
type badServer struct {
	discoveryv3.UnimplementedAggregatedDiscoveryServiceServer
	gotNACK chan *discoveryv3.DiscoveryRequest
}

func (b *badServer) StreamAggregatedResources(srv discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	if _, err := srv.Recv(); err != nil {
		return err
	}
	bad, err := anypb.New(wrapperspb.Bytes([]byte("this is not a cc2 envelope")))
	if err != nil {
		return err
	}
	if err := srv.Send(&discoveryv3.DiscoveryResponse{
		TypeUrl: resourcev3.ClusterType, VersionInfo: "1", Nonce: "n1", Resources: []*anypb.Any{bad},
	}); err != nil {
		return err
	}
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

func TestClientNacksAndHoldsLastKnownGood(t *testing.T) {
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

	w := newFakeWriter()
	c := NewClient(conn, w, WithLogf(func(string, ...any) {}))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	select {
	case nack := <-bs.gotNACK:
		if nack.GetErrorDetail() == nil {
			t.Fatalf("expected NACK with error_detail")
		}
	case <-ctx.Done():
		t.Fatalf("no NACK received before timeout")
	}

	// A rejected push must never be applied (hold last-known-good).
	if p, i := w.counts(); p != 0 || i != 0 {
		t.Fatalf("writer applied a rejected snapshot: policies=%d identities=%d", p, i)
	}
}

func TestDiff(t *testing.T) {
	id2 := sampleIdentity(2, "b")
	old := snapshot{
		identities: []wire.Identity{sampleIdentity(1, "a"), id2},
		policies:   []wire.PolicyRule{samplePolicy(80), samplePolicy(443)},
	}
	// Drop identity 1, change identity 2's name, keep 443, drop 80, add 8080.
	id2Changed := id2
	id2Changed.Name = "b2"
	next := snapshot{
		identities: []wire.Identity{id2Changed, sampleIdentity(3, "c")},
		policies:   []wire.PolicyRule{samplePolicy(443), samplePolicy(8080)},
	}
	plan := diff(old, next)

	if len(plan.IdentityUpserts) != 2 { // id2Changed + id3
		t.Fatalf("IdentityUpserts = %d, want 2", len(plan.IdentityUpserts))
	}
	if len(plan.IdentityDeletes) != 1 || plan.IdentityDeletes[0] != 1 {
		t.Fatalf("IdentityDeletes = %v, want [1]", plan.IdentityDeletes)
	}
	if len(plan.PolicyUpserts) != 1 || plan.PolicyUpserts[0].Key.DstPort != 8080 {
		t.Fatalf("PolicyUpserts = %+v, want [8080]", plan.PolicyUpserts)
	}
	if len(plan.PolicyDeletes) != 1 || plan.PolicyDeletes[0].DstPort != 80 {
		t.Fatalf("PolicyDeletes = %+v, want [80]", plan.PolicyDeletes)
	}

	// Idempotence: diff(s, s) is empty.
	empty := diff(next, next)
	if len(empty.IdentityUpserts)+len(empty.IdentityDeletes)+len(empty.PolicyUpserts)+len(empty.PolicyDeletes) != 0 {
		t.Fatalf("diff(s,s) not empty: %+v", empty)
	}
}
