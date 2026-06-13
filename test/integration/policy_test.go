//go:build integration

package integration

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/internal/agent/supervisor"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	mer29ClientID = wire.IdentityID(1001)
	mer29ServerID = wire.IdentityID(2001)
	mer29TestPort = 18080
	mer29FlipPort = 18081

	dropReasonPolicyDeny = 1
)

// MER-29 (P1.2 gate): full product-path policy integration — agent stub
// (supervisor + YAML + datapath.Writer + attach.Manager), not raw map ops.
func TestLivePolicyIntegrationGate_MER29(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	pinDir := harness.PinDir(t)
	v := harness.NewVethPair(t, "pol", 10)

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

	assertTCPConnectFromPeer(t, v, mer29TestPort, true, "allowed connect before policy flip")

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

	peerIPKey := ipv4NetworkKey(t, v.PeerIP)
	hostIPKey := ipv4NetworkKey(t, v.HostAddr)
	harness.WaitUntil(t, 3*time.Second, func() bool {
		info, ok := lookupDeniedFlow(objs.DeniedFlowsMap, peerIPKey, hostIPKey, hostPortToFlowKey(mer29FlipPort), 6)
		return ok && info.Reason == dropReasonPolicyDeny && info.Count >= 1
	}, "denied_flows_map missing DROP_REASON_POLICY_DENY entry")

	if err := runtime.Close(ctx); err != nil {
		t.Fatalf("shutdown before restart: %v", err)
	}

	denyYAML := writePolicyYAML(t, "deny", wire.PolicyActionDeny)
	restarted, err := supervisor.NewPolicyStartupRunner(supervisor.StartupOptions{
		PinDir:     pinDir,
		Interface:  v.HostVeth,
		PolicyFile: denyYAML,
	}).Startup(ctx)
	if err != nil {
		t.Fatalf("policy restart startup: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Close(context.Background()) })

	assertTCPConnectFromPeer(t, v, mer29TestPort, false, "denied connect after agent restart (pins survived)")
}

func writePolicyYAML(t *testing.T, label string, action wire.PolicyAction) string {
	t.Helper()
	actionStr := "allow"
	if action == wire.PolicyActionDeny {
		actionStr = "deny"
	}
	body := fmt.Sprintf(`version: mer-29-%s
identities:
  - id: %d
    pod_ipv4: 169.254.10.2
    spiffe_id: spiffe://mer-29/ns/test/sa/client
    namespace: test
    name: client
  - id: %d
    pod_ipv4: 169.254.10.1
    spiffe_id: spiffe://mer-29/ns/test/sa/server
    namespace: test
    name: server
policies:
  - src_identity: %d
    dst_identity: %d
    dst_port: %d
    protocol: 6
    direction: 0
    action: %s
`, label, mer29ClientID, mer29ServerID, mer29ClientID, mer29ServerID, mer29TestPort, actionStr)
	path := filepath.Join(t.TempDir(), "policy-"+label+".yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write policy yaml: %v", err)
	}
	return path
}

func assertTCPConnectFromPeer(t *testing.T, v *harness.VethPair, port int, wantOK bool, msg string) {
	t.Helper()
	stop := startTCPListenerOnHost(t, port)
	defer stop()
	waitForHostListener(t, port)

	harness.WaitUntil(t, 3*time.Second, func() bool {
		_, err := v.TryExecInNS("nc", "-z", "-w", "1", v.HostAddr, strconv.Itoa(port))
		if wantOK {
			return err == nil
		}
		return err != nil
	}, msg)
}

func startTCPListenerOnHost(t *testing.T, port int) func() {
	t.Helper()
	cmd := exec.Command("sh", "-c",
		fmt.Sprintf("while true; do nc -l -p %d >/dev/null 2>&1 || true; done", port))
	if err := cmd.Start(); err != nil {
		t.Fatalf("start host listener on port %d: %v", port, err)
	}
	return func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}
}

func waitForHostListener(t *testing.T, port int) {
	t.Helper()
	harness.WaitUntil(t, 2*time.Second, func() bool {
		out, err := exec.Command("nc", "-z", "-w", "1", "127.0.0.1", strconv.Itoa(port)).CombinedOutput()
		_ = out
		return err == nil
	}, fmt.Sprintf("host listener never ready on port %d", port))
}

type flowMapKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
	Proto   uint8
	Pad     [3]uint8
}

type denyInfo struct {
	LastNs uint64
	Count  uint32
	Reason uint32
}

func lookupDeniedFlow(m *ebpf.Map, srcIP, dstIP uint32, dstPortNet uint16, proto uint8) (denyInfo, bool) {
	if m == nil {
		return denyInfo{}, false
	}
	var (
		key   flowMapKey
		value denyInfo
	)
	iter := m.Iterate()
	for iter.Next(&key, &value) {
		if key.SrcIP == srcIP && key.DstIP == dstIP && key.DstPort == dstPortNet && key.Proto == proto {
			return value, true
		}
	}
	return denyInfo{}, false
}

func ipv4NetworkKey(t *testing.T, addr string) uint32 {
	t.Helper()
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		t.Fatalf("parse ipv4 %q: %v", addr, err)
	}
	if !parsed.Is4() {
		t.Fatalf("address %q is not IPv4", addr)
	}
	v4 := parsed.As4()
	return binary.BigEndian.Uint32(v4[:])
}

func hostPortToFlowKey(port uint16) uint16 {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:], port)
	return binary.LittleEndian.Uint16(buf[:])
}
