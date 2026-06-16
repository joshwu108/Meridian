//go:build e2e

// Package integration, e2e tag: MER-52 P2.2-BENCH. This is a NIGHTLY/self-hosted
// benchmark, NOT a PR gate — it is excluded from `make test-integration`
// (-tags=integration) and `make test-bpf` (-tags=bpf), arms no manifest row, and
// reports data rather than passing/failing on a latency threshold.
//
// It measures the intra-node latency effect of the SOCKMAP redirect fast path:
// the same loopback connect + first-byte round-trip with an eligible
// (ALLOW + SOCKMAP_ELIGIBLE) policy vs a baseline ALLOW policy (no redirect),
// using the production attach path (bpfobj loaders + attach managers). The
// honest verdict — a measured win with numbers, or "no win on <kernel>" with the
// numbers — is written to testdata/sockmap_bench.json.
package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/internal/agent/attach"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	benchClientIP   = "127.0.0.1"
	benchServerIP   = "127.0.0.2"
	benchClientID   = wire.IdentityID(1001)
	benchServerID   = wire.IdentityID(2001)
	benchIterations = 2000
	benchWarmup     = 200
)

// latencyStats holds one scenario's connect+first-byte distribution.
type latencyStats struct {
	P50us float64 `json:"p50_us"`
	P99us float64 `json:"p99_us"`
}

// benchResult is the committed fixture schema (testdata/sockmap_bench.json).
type benchResult struct {
	Kernel          string       `json:"kernel"`
	Iterations      int          `json:"iterations"`
	Warmup          int          `json:"warmup"`
	Sockmap         latencyStats `json:"sockmap"`
	Baseline        latencyStats `json:"baseline"`
	DeltaP50Pct     float64      `json:"delta_p50_pct"` // negative = SOCKMAP faster
	DeltaP99Pct     float64      `json:"delta_p99_pct"`
	RedirectedDelta uint64       `json:"redirected_delta"`
	Verdict         string       `json:"verdict"`
	Timestamp       string       `json:"timestamp"`
}

// TestSockmapBench measures and records the SOCKMAP redirect latency effect. It
// fails only on harness/measurement error — never on "win too small" — because
// the benchmark is data, not a gate.
func TestSockmapBench(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}
	ctx := context.Background()
	pinDir := harness.PinDir(t)

	sockObjs, err := bpfobj.LoadSockOps(pinDir)
	if err != nil {
		t.Fatalf("bpfobj.LoadSockOps: %v", err)
	}
	t.Cleanup(func() { _ = sockObjs.Close() })
	skObjs, err := bpfobj.LoadSkMsg(pinDir)
	if err != nil {
		t.Fatalf("bpfobj.LoadSkMsg: %v", err)
	}
	t.Cleanup(func() { _ = skObjs.Close() })

	w := datapath.NewWriter(sockObjs.IdentityMap, sockObjs.PolicyMap)
	benchSeedIdentity(t, ctx, w, benchClientID, benchClientIP, "client")
	benchSeedIdentity(t, ctx, w, benchServerID, benchServerIP, "server")

	cgMgr := attach.NewCgroupSockOpsManager(sockObjs.MeridianSockOps)
	if err := cgMgr.EnsureAttached(benchCgroupPath(t)); err != nil {
		t.Fatalf("attach sock_ops: %v", err)
	}
	t.Cleanup(func() { _ = cgMgr.Detach() })
	skMgr := attach.NewSkMsgSockhashManager(skObjs.MeridianSkMsg, skObjs.Sockhash.FD())
	if err := skMgr.EnsureAttached(); err != nil {
		t.Fatalf("attach sk_msg: %v", err)
	}
	t.Cleanup(func() { _ = skMgr.Detach() })

	reader := metrics.NewMapReader(sockObjs.MetricsMap)

	ln, err := net.Listen("tcp", net.JoinHostPort(benchServerIP, "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverPort := ln.Addr().(*net.TCPAddr).Port
	stopEcho := startEchoServer(ln)
	defer stopEcho()

	dialer := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(benchClientIP)}}
	serverAddr := net.JoinHostPort(benchServerIP, strconv.Itoa(serverPort))

	// Baseline: ALLOW without SOCKMAP_ELIGIBLE — normal loopback path.
	benchSeedPolicy(t, ctx, w, serverPort, wire.PolicyVerdict{Action: wire.PolicyActionAllow})
	baseline := measureLatencies(t, dialer, serverAddr)

	// SOCKMAP: ALLOW + SOCKMAP_ELIGIBLE — redirected fast path.
	benchSeedPolicy(t, ctx, w, serverPort, wire.PolicyVerdict{
		Action: wire.PolicyActionAllow,
		Flags:  wire.PolicyFlagSockmapEligible,
	})
	redirBefore := readRedirectedCount(t, reader)
	sockmap := measureLatencies(t, dialer, serverAddr)
	redirDelta := readRedirectedCount(t, reader) - redirBefore

	res := benchResult{
		Kernel:          kernelRelease(),
		Iterations:      benchIterations,
		Warmup:          benchWarmup,
		Sockmap:         latencyStats{P50us: micros(pctile(sockmap, 0.50)), P99us: micros(pctile(sockmap, 0.99))},
		Baseline:        latencyStats{P50us: micros(pctile(baseline, 0.50)), P99us: micros(pctile(baseline, 0.99))},
		RedirectedDelta: redirDelta,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	}
	res.DeltaP50Pct = pctChange(res.Baseline.P50us, res.Sockmap.P50us)
	res.DeltaP99Pct = pctChange(res.Baseline.P99us, res.Sockmap.P99us)
	res.Verdict = verdictFor(res)

	writeBenchResult(t, res)
	t.Logf("MER-52 SOCKMAP bench (kernel %s, n=%d): baseline p50=%.1fµs p99=%.1fµs | sockmap p50=%.1fµs p99=%.1fµs | Δp50=%.1f%% Δp99=%.1f%% | redirected+%d | %s",
		res.Kernel, res.Iterations, res.Baseline.P50us, res.Baseline.P99us,
		res.Sockmap.P50us, res.Sockmap.P99us, res.DeltaP50Pct, res.DeltaP99Pct, res.RedirectedDelta, res.Verdict)

	if redirDelta == 0 {
		t.Fatalf("SOCKMAP redirect never engaged (METRIC_FLOWS_REDIRECTED flat) — benchmark measured nothing; check attach path")
	}
}

// verdictFor reports the honest outcome. A "win" requires BOTH p50 AND p99 to
// improve — a p50 gain alongside a p99 regression is reported as "mixed", never
// green-washed into a win (MER-52 honesty requirement).
func verdictFor(r benchResult) string {
	if r.RedirectedDelta == 0 {
		return "INVALID: SOCKMAP redirect did not engage"
	}
	p50Win := r.Sockmap.P50us < r.Baseline.P50us
	p99Win := r.Sockmap.P99us < r.Baseline.P99us
	switch {
	case p50Win && p99Win:
		return fmt.Sprintf("SOCKMAP win on %s: p50 %+.1f%%, p99 %+.1f%%", r.Kernel, r.DeltaP50Pct, r.DeltaP99Pct)
	case !p50Win && !p99Win:
		return fmt.Sprintf("no win on %s: p50 %+.1f%%, p99 %+.1f%%", r.Kernel, r.DeltaP50Pct, r.DeltaP99Pct)
	default:
		return fmt.Sprintf("mixed on %s (no clear win): p50 %+.1f%%, p99 %+.1f%%", r.Kernel, r.DeltaP50Pct, r.DeltaP99Pct)
	}
}

// measureLatencies runs warmup+N connect→write→first-byte cycles and returns the
// post-warmup durations.
func measureLatencies(t *testing.T, dialer net.Dialer, serverAddr string) []time.Duration {
	t.Helper()
	durs := make([]time.Duration, 0, benchIterations)
	for i := 0; i < benchWarmup+benchIterations; i++ {
		start := time.Now()
		conn, err := dialer.Dial("tcp", serverAddr)
		if err != nil {
			t.Fatalf("dial[%d]: %v", i, err)
		}
		if _, err := conn.Write([]byte{1}); err != nil {
			_ = conn.Close()
			t.Fatalf("write[%d]: %v", i, err)
		}
		var b [1]byte
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			_ = conn.Close()
			t.Fatalf("read[%d]: %v", i, err)
		}
		d := time.Since(start)
		_ = conn.Close()
		if i >= benchWarmup {
			durs = append(durs, d)
		}
	}
	return durs
}

// startEchoServer accepts connections and echoes one byte each, until the
// returned stop func closes the listener.
func startEchoServer(ln net.Listener) func() {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var b [1]byte
				if _, err := io.ReadFull(c, b[:]); err != nil {
					return
				}
				_, _ = c.Write(b[:])
			}(c)
		}
	}()
	return func() { _ = ln.Close() }
}

func pctile(durs []time.Duration, p float64) time.Duration {
	s := append([]time.Duration(nil), durs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if len(s) == 0 {
		return 0
	}
	idx := int(float64(len(s)-1) * p)
	return s[idx]
}

func micros(d time.Duration) float64 { return float64(d.Nanoseconds()) / 1000.0 }

func pctChange(base, val float64) float64 {
	if base == 0 {
		return 0
	}
	return (val - base) / base * 100.0
}

func readRedirectedCount(t *testing.T, r *metrics.MapReader) uint64 {
	t.Helper()
	v, err := r.Read(metrics.MetricFlowsRedirected)
	if err != nil {
		t.Fatalf("read METRIC_FLOWS_REDIRECTED: %v", err)
	}
	return v
}

func kernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

func writeBenchResult(t *testing.T, res benchResult) {
	t.Helper()
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		t.Fatalf("marshal bench result: %v", err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(filepath.Join("testdata", "sockmap_bench.json"), b, 0o644); err != nil {
		t.Fatalf("write bench result: %v", err)
	}
}

func benchSeedIdentity(t *testing.T, ctx context.Context, w datapath.Writer, id wire.IdentityID, ip, name string) {
	t.Helper()
	if err := harness.SeedIdentity(ctx, w, wire.Identity{
		ID:        id,
		PodIPv4:   ip,
		SpiffeID:  "spiffe://meridian/ns/test/sa/" + name,
		Namespace: "test",
		Name:      name,
	}); err != nil {
		t.Fatalf("seed identity %s: %v", name, err)
	}
}

func benchSeedPolicy(t *testing.T, ctx context.Context, w datapath.Writer, serverPort int, verdict wire.PolicyVerdict) {
	t.Helper()
	for _, dir := range []wire.Direction{wire.DirectionIngress, wire.DirectionEgress} {
		if err := harness.SeedPolicy(ctx, w, wire.PolicyRule{
			Key: wire.PolicyRuleKey{
				SrcIdentity: benchClientID,
				DstIdentity: benchServerID,
				DstPort:     uint16(serverPort),
				Protocol:    6,
				Direction:   dir,
			},
			Verdict: verdict,
		}); err != nil {
			t.Fatalf("seed policy dir=%d: %v", dir, err)
		}
	}
}

func benchCgroupPath(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Fatalf("cgroup v2 unified hierarchy not mounted: %v", err)
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatalf("read /proc/self/cgroup: %v", err)
	}
	rel := "/"
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel = strings.TrimPrefix(line, "0::")
			break
		}
	}
	p := filepath.Join("/sys/fs/cgroup", rel)
	if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
		return "/sys/fs/cgroup"
	}
	return p
}
