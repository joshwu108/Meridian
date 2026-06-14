//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/joshuawu/meridian/internal/agent/config"
	"github.com/joshuawu/meridian/internal/agent/identitytable"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/internal/agent/supervisor"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	mer32ClientSpiffe = "spiffe://mer-29/ns/test/sa/client"
	mer32ServerSpiffe = "spiffe://mer-29/ns/test/sa/server"
)

var (
	metricCounterValue = regexp.MustCompile(`^([a-zA-Z0-9_:]+)(\{[^}]*\})?\s+([0-9]+(?:\.[0-9]+)?)\s*$`)
)

// MER-32 (O-2 gate): denied_flows_map join + Prometheus metrics for the MER-29
// traffic pattern — exact allow/deny counters and SPIFFE labels on denied flows.
func TestDeniedFlowsMetricsGate_MER32(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	pinDir := harness.PinDir(t)
	v := harness.NewVethPair(t, "o2", 10)

	allowYAML := writePolicyYAML(t, "allow", wire.PolicyActionAllow)
	ctx := context.Background()

	runtime, err := supervisor.NewPolicyStartupRunner(supervisor.StartupOptions{
		PinDir:     pinDir,
		Interface:  v.HostVeth,
		PolicyFile: allowYAML,
	}).Startup(ctx)
	if err != nil {
		t.Fatalf("policy startup (allow): %v", err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	objs, err := runtime.TcIngressObjects()
	if err != nil {
		t.Fatalf("tc ingress objects: %v", err)
	}

	snapshot, err := config.LoadPolicySnapshot(allowYAML)
	if err != nil {
		t.Fatalf("load policy snapshot: %v", err)
	}
	resolver := identitytable.NewYAMLResolver(snapshot.Identities)

	reg := prometheus.NewRegistry()
	reg.MustRegister(metrics.NewCollector(metrics.NewMapReader(objs.MetricsMap)))
	reg.MustRegister(metrics.NewDeniedCollector(metrics.NewMapDeniedReader(
		objs.DeniedFlowsMap,
		objs.IdentityMap,
		resolver,
	)))

	metricsServer := metrics.NewServer("127.0.0.1:0", reg)
	ln, err := net.Listen("tcp", metricsServer.Addr)
	if err != nil {
		t.Fatalf("listen metrics: %v", err)
	}
	metricsErr := make(chan error, 1)
	go func() {
		if serveErr := metricsServer.Serve(ln); serveErr != nil && serveErr != http.ErrServerClosed {
			metricsErr <- serveErr
		}
	}()
	t.Cleanup(func() { _ = metrics.Shutdown(metricsServer) })

	metricsURL := "http://" + ln.Addr().String() + "/metrics"

	allowedBefore, deniedBefore := readFlowVerdictCounters(t, objs.MetricsMap)

	assertTCPConnectFromPeer(t, v, mer29TestPort, true, "allowed connect before policy flip")

	harness.WaitUntil(t, 3*time.Second, func() bool {
		allowed, denied := readFlowVerdictCounters(t, objs.MetricsMap)
		return allowed == allowedBefore+1 && denied == deniedBefore
	}, "flows_allowed did not increment by exactly one after allowed connect")

	denyRule := wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: mer29ClientID,
			DstIdentity: mer29ServerID,
			DstPort:     mer29FlipPort,
			Protocol:    6,
			Direction:   wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
	}
	if err := runtime.Writer().Apply(ctx, wire.CommitPlan{
		PolicyUpserts: []wire.PolicyRule{denyRule},
	}); err != nil {
		t.Fatalf("flip policy allow->deny: %v", err)
	}

	assertTCPConnectFromPeer(t, v, mer29FlipPort, false, "denied connect after policy flip")

	wantAllowed := allowedBefore + 1
	harness.WaitUntil(t, 3*time.Second, func() bool {
		allowed, denied := readFlowVerdictCounters(t, objs.MetricsMap)
		return allowed == wantAllowed && denied > deniedBefore
	}, "flows_denied never incremented after denied connect")

	allowedAfter, deniedAfter := readFlowVerdictCounters(t, objs.MetricsMap)
	if allowedAfter != wantAllowed {
		t.Fatalf("meridian_flows_allowed_total = %d, want %d", allowedAfter, wantAllowed)
	}
	deniedDelta := deniedAfter - deniedBefore
	if deniedDelta < 1 {
		t.Fatalf("meridian_flows_denied_total delta = %d, want >= 1", deniedDelta)
	}

	body := fetchMetrics(t, metricsURL)
	assertMetricValue(t, body, "meridian_flows_allowed_total", float64(wantAllowed))
	assertMetricValue(t, body, "meridian_flows_denied_total", float64(deniedAfter))

	deniedLine := findDeniedFlowMetricLine(t, body, mer32ClientSpiffe, mer32ServerSpiffe, mer29FlipPort)
	if deniedLine == "" {
		t.Fatalf("/metrics missing denied flow with SPIFFE labels %q -> %q on port %d; body:\n%s",
			mer32ClientSpiffe, mer32ServerSpiffe, mer29FlipPort, body)
	}
	if !strings.Contains(deniedLine, `reason="policy_deny"`) {
		t.Fatalf("denied flow metric missing policy_deny reason: %q", deniedLine)
	}
	if !strings.Contains(deniedLine, `protocol="tcp"`) {
		t.Fatalf("denied flow metric missing tcp protocol label: %q", deniedLine)
	}

	select {
	case serveErr := <-metricsErr:
		t.Fatalf("metrics server failed: %v", serveErr)
	default:
	}
}

func readFlowVerdictCounters(t *testing.T, metricsMap any) (allowed, denied uint64) {
	t.Helper()
	m, ok := metricsMap.(*ebpf.Map)
	if !ok {
		t.Fatalf("metrics map handle is %T, want *ebpf.Map", metricsMap)
	}
	reader := metrics.NewMapReader(m)
	var err error
	allowed, err = reader.Read(metrics.MetricFlowsAllowed)
	if err != nil {
		t.Fatalf("read flows_allowed: %v", err)
	}
	denied, err = reader.Read(metrics.MetricFlowsDenied)
	if err != nil {
		t.Fatalf("read flows_denied: %v", err)
	}
	return allowed, denied
}

func fetchMetrics(t *testing.T, url string) string {
	t.Helper()
	var lastErr error
	var body string
	harness.WaitUntil(t, 3*time.Second, func() bool {
		resp, err := http.Get(url)
		if err != nil {
			lastErr = err
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			return false
		}
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = err
			return false
		}
		body = string(raw)
		return true
	}, "GET /metrics never succeeded")
	if lastErr != nil {
		t.Fatalf("fetch %s: %v", url, lastErr)
	}
	return body
}

func assertMetricValue(t *testing.T, body, name string, want float64) {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := metricCounterValue.FindStringSubmatch(line)
		if len(m) < 4 || m[1] != name {
			continue
		}
		got, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			t.Fatalf("parse %s value %q: %v", name, m[3], err)
		}
		if got != want {
			t.Fatalf("%s = %v, want %v (line %q)", name, got, want, line)
		}
		return
	}
	t.Fatalf("metric %q not found in /metrics body:\n%s", name, body)
}

func findDeniedFlowMetricLine(t *testing.T, body, srcSpiffe, dstSpiffe string, dstPort int) string {
	t.Helper()
	wantPort := strconv.Itoa(dstPort)
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "meridian_denied_flow_packets_total{") {
			continue
		}
		if !strings.Contains(line, `src_identity="`+srcSpiffe+`"`) {
			continue
		}
		if !strings.Contains(line, `dst_identity="`+dstSpiffe+`"`) {
			continue
		}
		if !strings.Contains(line, `dst_port="`+wantPort+`"`) {
			continue
		}
		return line
	}
	return ""
}
