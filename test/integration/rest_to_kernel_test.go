//go:build integration

package integration

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/datapath"
	adssrv "github.com/joshuawu/meridian/internal/agent/xds"
	"github.com/joshuawu/meridian/internal/control/ads"
	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/internal/control/rest"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	mer73ClientID = wire.IdentityID(1001)
	mer73ServerID = wire.IdentityID(2001)
	mer73Port     = 8443
	mer73Budget   = 500 * time.Millisecond
)

// TestRestToKernelGate_MER73 is the Phase-3 A-3 exit gate: a REST POST /policies on
// meridian-control must land in the real kernel policy_map — via store → ADS server
// → agent xds.Client → datapath.Writer — within 500 ms (the ROADMAP week-5/6
// success criterion). Pure end-to-end: it wires the shipped components and reads the
// kernel map back. Must never t.Skip under root on 5.15 (MER-44).
func TestRestToKernelGate_MER73(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}
	ctx := context.Background()
	pinDir := harness.PinDir(t)

	// Real kernel maps + the production datapath writer.
	objs, err := bpfobj.LoadTcIngress(pinDir)
	if err != nil {
		t.Fatalf("load tc_ingress objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	writer := datapath.NewWriter(objs.IdentityMap, objs.PolicyMap)

	// Control plane: shared store behind the REST surface + the ADS server.
	st := store.NewMemory()
	for _, id := range []wire.Identity{
		{ID: mer73ClientID, SpiffeID: "spiffe://cluster.local/client", PodIPv4: "10.0.0.1", Name: "client"},
		{ID: mer73ServerID, SpiffeID: "spiffe://cluster.local/server", PodIPv4: "10.0.0.2", Name: "server"},
	} {
		if err := st.PutIdentity(ctx, id); err != nil {
			t.Fatalf("seed identity: %v", err)
		}
	}
	httpSrv := httptest.NewServer(rest.NewServer(st, identity.NewRegistry()).Handler())
	t.Cleanup(httpSrv.Close)

	// Agent: the production ADS client applying to the real maps via the writer.
	conn := dialADS(t, st)
	client := adssrv.NewClient(conn, writer, adssrv.WithLogf(func(string, ...any) {}))
	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = client.Run(runCtx) }()

	// Wait until the agent has applied the seeded identities (initial EDS snapshot),
	// so the stream is live before we measure the policy POST.
	harness.WaitUntil(t, 5*time.Second, func() bool {
		return countMapEntries(t, objs.IdentityMap) == 2
	}, "seeded identities applied to identity_map")

	base := countMapEntries(t, objs.PolicyMap)

	// POST a valid policy and measure REST → kernel policy_map propagation.
	body := `{"Key":{"SrcIdentity":1001,"DstIdentity":2001,"DstPort":8443,"Protocol":6,"Direction":0},"Verdict":{"Action":0,"Flags":0}}`
	start := time.Now()
	resp, err := http.Post(httpSrv.URL+"/policies", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /policies: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /policies = %d, want 201", resp.StatusCode)
	}

	landed := pollUntil(start.Add(2*time.Second), func() bool {
		return countMapEntries(t, objs.PolicyMap) == base+1
	})
	elapsed := time.Since(start)
	if !landed {
		t.Fatalf("policy never reached kernel policy_map within the 2s safety window")
	}
	if elapsed > mer73Budget {
		t.Fatalf("REST→kernel propagation %v exceeds the %v gate", elapsed, mer73Budget)
	}
	t.Logf("REST→kernel policy_map propagation: %v (budget %v)", elapsed, mer73Budget)

	// Malformed input never reaches the kernel: REST fails closed (4xx) and the map
	// is unchanged (CC-5 fail-closed, end to end).
	bad, err := http.Post(httpSrv.URL+"/policies", "application/json", strings.NewReader(`{"Key":`))
	if err != nil {
		t.Fatalf("POST malformed: %v", err)
	}
	_ = bad.Body.Close()
	if bad.StatusCode < 400 || bad.StatusCode >= 500 {
		t.Fatalf("malformed POST = %d, want 4xx", bad.StatusCode)
	}
	time.Sleep(200 * time.Millisecond) // allow any erroneous push to register
	if got := countMapEntries(t, objs.PolicyMap); got != base+1 {
		t.Fatalf("malformed input changed kernel policy_map: %d entries, want %d", got, base+1)
	}
}

// dialADS starts the control-plane ADS server on a bufconn and returns a client conn.
func dialADS(t *testing.T, st *store.Memory) *grpc.ClientConn {
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

// countMapEntries counts keys in a tc_ingress map (identity_map or policy_map). The
// test package is exempt from the wire-bpf-bridge depguard rule, so it may read the
// generated bpf types directly.
func countMapEntries(t *testing.T, m *ebpf.Map) int {
	t.Helper()
	var k, v []byte
	it := m.Iterate()
	n := 0
	for it.Next(&k, &v) {
		n++
	}
	if err := it.Err(); err != nil {
		t.Fatalf("iterate map: %v", err)
	}
	return n
}

func pollUntil(deadline time.Time, cond func() bool) bool {
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(2 * time.Millisecond)
	}
	return cond()
}
