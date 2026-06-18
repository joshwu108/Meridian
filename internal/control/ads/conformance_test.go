package ads

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"

	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/internal/control/rest"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
)

// propagationBudget is the CP-3 ROADMAP gate: a REST policy change must reach a
// subscribed agent in under 500 ms (measured end to end, in-process).
const propagationBudget = 500 * time.Millisecond

// loadSeed reads the committed regression fixture the conformance suite starts from.
func loadSeed(t *testing.T) []wire.PolicyRule {
	t.Helper()
	b, err := os.ReadFile("testdata/conformance_seed.json")
	if err != nil {
		t.Fatalf("read seed fixture: %v", err)
	}
	var rules []wire.PolicyRule
	if err := json.Unmarshal(b, &rules); err != nil {
		t.Fatalf("decode seed fixture: %v", err)
	}
	if len(rules) == 0 {
		t.Fatal("seed fixture is empty")
	}
	return rules
}

// waitUntil polls cond until it holds or deadline passes; returns the final
// result. Used instead of time.Sleep so propagation timing is measured, not assumed.
func waitUntil(deadline time.Time, cond func() bool) bool {
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}

func openRawStream(t *testing.T, conn *grpc.ClientConn, ctx context.Context) adsStreamClient {
	t.Helper()
	stream, err := discoveryv3.NewAggregatedDiscoveryServiceClient(conn).StreamAggregatedResources(ctx)
	if err != nil {
		t.Fatalf("open raw ADS stream: %v", err)
	}
	return stream
}

// TestADSConformanceGate_MER56 is the CP-3 gate: it drives the MER-55 stub and
// raw clients against the MER-54 server through the full xDS lifecycle, and
// proves REST→stub propagation stays within the 500 ms budget. Pure Go — it must
// never t.Skip (MER-44 gate integrity).
func TestADSConformanceGate_MER56(t *testing.T) {
	t.Run("lifecycle_initial_add_delete", testConformanceLifecycle)
	t.Run("nack_recovery", testConformanceNackRecovery)
	t.Run("stale_nonce_ignored", testConformanceStaleNonce)
	t.Run("reconnect_last_known_version", testConformanceReconnect)
	t.Run("rest_propagation_under_budget", testConformanceRestPropagation)
}

// (a) initial snapshot, (b) policy add, (c) policy delete via the stub.
func testConformanceLifecycle(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	seed := loadSeed(t)
	for _, r := range seed {
		if err := st.PutPolicy(ctx, r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	stub := quietStub(dialServer(t, st))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = stub.Run(runCtx) }()

	waitFor(t, func() bool {
		return len(stub.Snapshot().Policies) == len(seed)
	}, 5*time.Second, "initial seed snapshot received")

	add := samplePolicy(12345)
	if err := st.PutPolicy(ctx, add); err != nil {
		t.Fatalf("add: %v", err)
	}
	waitFor(t, func() bool {
		return len(stub.Snapshot().Policies) == len(seed)+1
	}, 5*time.Second, "policy add propagated")

	if err := st.DeletePolicy(ctx, add.Key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	waitFor(t, func() bool {
		return len(stub.Snapshot().Policies) == len(seed)
	}, 5*time.Second, "policy delete propagated")
}

// (d) After a NACK the server holds last-known-good and a subsequent valid change
// still propagates on the same stream.
func testConformanceNackRecovery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := store.NewMemory()
	if err := st.PutPolicy(ctx, samplePolicy(443)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	conn := dialServer(t, st)
	stream := openRawStream(t, conn, ctx)

	if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: resourcev3.ClusterType}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	v1 := recvWithin(t, stream, 5*time.Second)
	if v1.GetVersionInfo() != "1" {
		t.Fatalf("initial version = %q, want 1", v1.GetVersionInfo())
	}

	// NACK v1.
	if err := stream.Send(&discoveryv3.DiscoveryRequest{
		TypeUrl:       resourcev3.ClusterType,
		ResponseNonce: v1.GetNonce(),
		ErrorDetail:   &spb.Status{Code: 3, Message: "conformance forced NACK"},
	}); err != nil {
		t.Fatalf("nack: %v", err)
	}

	// A subsequent valid change must still propagate (stream healthy, server
	// recovered) as version 2.
	if err := st.PutPolicy(ctx, samplePolicy(7777)); err != nil {
		t.Fatalf("post-nack mutate: %v", err)
	}
	v2 := recvWithin(t, stream, 5*time.Second)
	if v2.GetVersionInfo() != "2" {
		t.Fatalf("post-nack push version = %q, want 2", v2.GetVersionInfo())
	}
	rules := decodePolicies(t, v2)
	if !hasPort(rules, 7777) {
		t.Fatalf("post-nack snapshot missing the new rule: %+v", rules)
	}
}

// (e) A stale/unknown nonce is ignored: it causes no server state change and no
// spurious push, so the next real mutation advances cleanly to version 2.
func testConformanceStaleNonce(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	st := store.NewMemory()
	if err := st.PutPolicy(ctx, samplePolicy(443)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	conn := dialServer(t, st)
	stream := openRawStream(t, conn, ctx)

	if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: resourcev3.ClusterType}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	v1 := recvWithin(t, stream, 5*time.Second)

	// ACK v1, then send a stale-nonce request the server must ignore.
	if err := stream.Send(&discoveryv3.DiscoveryRequest{
		TypeUrl: resourcev3.ClusterType, VersionInfo: v1.GetVersionInfo(), ResponseNonce: v1.GetNonce(),
	}); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if err := stream.Send(&discoveryv3.DiscoveryRequest{
		TypeUrl: resourcev3.ClusterType, ResponseNonce: "stale-nonce-does-not-exist",
	}); err != nil {
		t.Fatalf("stale request: %v", err)
	}

	// The next message must be the single real mutation (version 2) — a stale
	// request that wrongly triggered a push would surface here first.
	if err := st.PutPolicy(ctx, samplePolicy(6666)); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	next := recvWithin(t, stream, 5*time.Second)
	if next.GetVersionInfo() != "2" {
		t.Fatalf("stale nonce perturbed state: next version = %q, want 2", next.GetVersionInfo())
	}
	if !hasPort(decodePolicies(t, next), 6666) {
		t.Fatalf("expected the post-stale mutation in the snapshot")
	}
}

// (f) Reconnect: a fresh stream re-subscribes and re-receives current state,
// including changes made while the agent was disconnected.
func testConformanceReconnect(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	seed := loadSeed(t)
	for _, r := range seed {
		if err := st.PutPolicy(ctx, r); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	stub := quietStub(dialServer(t, st))

	c1, cancel1 := context.WithCancel(ctx)
	done1 := make(chan error, 1)
	go func() { done1 <- stub.Run(c1) }()
	waitFor(t, func() bool { return len(stub.Snapshot().Policies) == len(seed) }, 5*time.Second, "session-1 seed")

	cancel1()
	select {
	case err := <-done1:
		if err != nil {
			t.Fatalf("session-1 Run error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("session-1 Run did not return after cancel (goroutine leak)")
	}

	// Change state while disconnected.
	if err := st.PutPolicy(ctx, samplePolicy(9000)); err != nil {
		t.Fatalf("offline mutate: %v", err)
	}

	c2, cancel2 := context.WithCancel(ctx)
	defer cancel2()
	go func() { _ = stub.Run(c2) }()
	waitFor(t, func() bool {
		s := stub.Snapshot()
		return len(s.Policies) == len(seed)+1 && hasPort(s.Policies, 9000)
	}, 5*time.Second, "reconnect re-receives current state")
}

// (2) End-to-end REST→Store→ADS→stub propagation within the 500 ms budget.
func testConformanceRestPropagation(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	restSrv := rest.NewServer(st, identity.NewRegistry())
	httpSrv := httptest.NewServer(restSrv.Handler())
	defer httpSrv.Close()

	stub := quietStub(dialServer(t, st))
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = stub.Run(runCtx) }()

	// Ensure the stub is subscribed before we POST, so the change is pushed.
	waitFor(t, func() bool {
		_, ok := stub.Snapshot().Versions[resourcev3.ClusterType]
		return ok
	}, 5*time.Second, "stub subscribed to cluster channel")

	body := `{"Key":{"SrcIdentity":1,"DstIdentity":2,"DstPort":8443,"Protocol":6,"Direction":0},"Verdict":{"Action":0,"Flags":0}}`
	start := time.Now()
	resp, err := http.Post(httpSrv.URL+"/policies", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /policies: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /policies status = %d, want 201", resp.StatusCode)
	}

	// Generous safety window prevents false timeouts on a stalled runner; the
	// gate is the measured elapsed below.
	got := waitUntil(start.Add(2*time.Second), func() bool {
		return hasPort(stub.Snapshot().Policies, 8443)
	})
	elapsed := time.Since(start)
	if !got {
		t.Fatalf("policy never propagated to the stub within the 2s safety window")
	}
	if elapsed > propagationBudget {
		t.Fatalf("REST→stub propagation took %v, exceeds the %v CP-3 budget", elapsed, propagationBudget)
	}
	t.Logf("REST→stub propagation: %v (budget %v)", elapsed, propagationBudget)
}

func hasPort(rules []wire.PolicyRule, port uint16) bool {
	for _, r := range rules {
		if r.Key.DstPort == port {
			return true
		}
	}
	return false
}
