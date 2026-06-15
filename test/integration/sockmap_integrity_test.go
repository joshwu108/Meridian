//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"net"
	"os"
	"path/filepath"
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
	mer51ClientIP = "127.0.0.1"
	mer51ServerIP = "127.0.0.2"
	mer51ClientID = wire.IdentityID(1001)
	mer51ServerID = wire.IdentityID(2001)
	mer51Payload  = 1 << 20 // 1 MiB
)

// MER-51 (P2.2 gate): the RUNTIME proof of the CC-5 invariant, complementing the
// static MER-49 negative gate. With the agent's production attach managers
// (MER-57) holding sock_ops on the cgroup and sk_msg on sockhash:
//
//   - an eligible (ALLOW + SOCKMAP_ELIGIBLE) flow transfers 1 MiB byte-for-byte
//     identical (no corruption/truncation) AND is observably redirected
//     (METRIC_FLOWS_REDIRECTED rises); and
//   - after the flow's policy is flipped to DENY, a NEW connection is not
//     inserted at establish and is never SOCKMAP-redirected (counter flat) while
//     its bytes still flow over the normal kernel path.
//
// Note (design boundary): SOCKHASH membership is decided at TCP establish by
// sock_ops; Phase 2 has no per-send re-evaluation or membership revocation, so a
// flip cannot evict an already-established socket. This gate therefore asserts
// the achievable, security-relevant invariant — a flow denied at establish never
// redirects — which is what closes ROADMAP Top-risk #2 at runtime.
func TestSockmapIntegrityGate_MER51(t *testing.T) {
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
	seedIdentity(t, ctx, w, mer51ClientID, mer51ClientIP, "client")
	seedIdentity(t, ctx, w, mer51ServerID, mer51ServerIP, "server")

	cgMgr := attach.NewCgroupSockOpsManager(sockObjs.MeridianSockOps)
	if err := cgMgr.EnsureAttached(mer51CgroupPath(t)); err != nil {
		t.Fatalf("attach sock_ops: %v", err)
	}
	t.Cleanup(func() { _ = cgMgr.Detach() })
	skMgr := attach.NewSkMsgSockhashManager(skObjs.MeridianSkMsg, skObjs.Sockhash.FD())
	if err := skMgr.EnsureAttached(); err != nil {
		t.Fatalf("attach sk_msg: %v", err)
	}
	t.Cleanup(func() { _ = skMgr.Detach() })

	reader := metrics.NewMapReader(sockObjs.MetricsMap)

	// Listener on a fixed server port so the flip can target the same flow tuple.
	ln, err := net.Listen("tcp", net.JoinHostPort(mer51ServerIP, "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	serverPort := ln.Addr().(*net.TCPAddr).Port

	// --- Eligible: 1 MiB byte-identical + redirected ---
	seedPolicy(t, ctx, w, serverPort, wire.PolicyVerdict{
		Action: wire.PolicyActionAllow,
		Flags:  wire.PolicyFlagSockmapEligible,
	})

	before := readRedirected(t, reader)
	sentSum, gotSum := transfer1MiB(t, ln, serverPort)
	if sentSum != gotSum {
		t.Fatalf("eligible 1 MiB transfer corrupted: sha256 sent=%x recv=%x", sentSum, gotSum)
	}
	if after := waitRedirectedAbove(t, reader, before); after <= before {
		t.Fatalf("eligible flow not redirected: METRIC_FLOWS_REDIRECTED before=%d after=%d", before, after)
	}

	// --- Flip the SAME flow to DENY: a new connection must not redirect ---
	seedPolicy(t, ctx, w, serverPort, wire.PolicyVerdict{Action: wire.PolicyActionDeny})
	// Let the eligible flow's sockets fully close so no stale sockhash entry
	// from the first transfer masks the assertion.
	time.Sleep(200 * time.Millisecond)

	before = readRedirected(t, reader)
	sentSum, gotSum = transfer1MiB(t, ln, serverPort)
	if sentSum != gotSum {
		t.Fatalf("denied flow's bytes corrupted on the normal path: sent=%x recv=%x", sentSum, gotSum)
	}
	time.Sleep(200 * time.Millisecond) // allow any erroneous redirect to register
	if after := readRedirected(t, reader); after != before {
		t.Fatalf("denied flow was SOCKMAP-redirected: METRIC_FLOWS_REDIRECTED before=%d after=%d; CC-5 runtime invariant violated", before, after)
	}
}

func seedIdentity(t *testing.T, ctx context.Context, w datapath.Writer, id wire.IdentityID, ip, name string) {
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

// seedPolicy upserts the (client->server, serverPort) verdict for both
// directions so the active (egress) and passive (ingress) established callbacks
// resolve the same verdict.
func seedPolicy(t *testing.T, ctx context.Context, w datapath.Writer, serverPort int, verdict wire.PolicyVerdict) {
	t.Helper()
	for _, dir := range []wire.Direction{wire.DirectionIngress, wire.DirectionEgress} {
		if err := harness.SeedPolicy(ctx, w, wire.PolicyRule{
			Key: wire.PolicyRuleKey{
				SrcIdentity: mer51ClientID,
				DstIdentity: mer51ServerID,
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

// transfer1MiB dials serverPort from the client IP, streams 1 MiB client->server,
// and returns the sha256 of the sent and fully-received payloads.
func transfer1MiB(t *testing.T, ln net.Listener, serverPort int) (sent, got [32]byte) {
	t.Helper()
	payload := make([]byte, mer51Payload)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand payload: %v", err)
	}

	type res struct {
		sum [32]byte
		err error
	}
	srvCh := make(chan res, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			srvCh <- res{err: aerr}
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, mer51Payload)
		if _, rerr := io.ReadFull(c, buf); rerr != nil {
			srvCh <- res{err: rerr}
			return
		}
		srvCh <- res{sum: sha256.Sum256(buf)}
	}()

	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(mer51ClientIP)}}
	conn, err := d.Dial("tcp", net.JoinHostPort(mer51ServerIP, strconv.Itoa(serverPort)))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}

	r := <-srvCh
	if r.err != nil {
		t.Fatalf("server receive: %v", r.err)
	}
	return sha256.Sum256(payload), r.sum
}

func readRedirected(t *testing.T, r *metrics.MapReader) uint64 {
	t.Helper()
	v, err := r.Read(metrics.MetricFlowsRedirected)
	if err != nil {
		t.Fatalf("read METRIC_FLOWS_REDIRECTED: %v", err)
	}
	return v
}

func waitRedirectedAbove(t *testing.T, r *metrics.MapReader, base uint64) uint64 {
	t.Helper()
	var v uint64
	for i := 0; i < 50; i++ {
		if v = readRedirected(t, r); v > base {
			return v
		}
		time.Sleep(10 * time.Millisecond)
	}
	return v
}

// mer51CgroupPath resolves the unified-hierarchy cgroup of the test process so
// the production sock_ops manager captures this process's loopback connections.
func mer51CgroupPath(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skipf("cgroup v2 unified hierarchy not mounted: %v", err)
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
