//go:build integration

package integration

import (
	"context"
	"encoding/binary"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	identityRemoteClient = wire.IdentityID(1001)
	identityLocalServer  = wire.IdentityID(2001)
	geneveAllowPort      = 18080
	geneveDenyPort       = 18081
)

// TestGeneveIngressIdentityPolicyGate_MER21 is the P1.3 gate: cross-node traffic
// carries remote src_identity in the Geneve TLV (MER-20 egress stamp), node B's
// tc_ingress decodes it (MER-21), and policy keyed on that identity enforces
// allow and deny cases on the two-node harness (MER-28).
func TestGeneveIngressIdentityPolicyGate_MER21(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	top := harness.NewTwoNode(t, "geneve-gate", 80)
	pinDir := harness.PinDir(t)

	ingressObjs, egressObjs, writer := loadGenevePrograms(t, pinDir)
	t.Cleanup(func() {
		if t.Failed() {
			dumpGeneveGateMetrics(t, egressObjs.MetricsMap, ingressObjs.MetricsMap)
			dumpDeniedFlowsMap(t, ingressObjs.DeniedFlowsMap)
		}
		_ = ingressObjs.Close()
		_ = egressObjs.Close()
	})

	ingressPin := filepath.Join(pinDir, "tc_ingress_prog")
	egressPin := filepath.Join(pinDir, "tc_egress_prog")
	if err := ingressObjs.MeridianTcIngress.Pin(ingressPin); err != nil {
		t.Fatalf("pin tc_ingress: %v", err)
	}
	if err := egressObjs.MeridianTcEgress.Pin(egressPin); err != nil {
		t.Fatalf("pin tc_egress: %v", err)
	}

	harness.AttachTCEgress(t, top.NodeA.Namespace, top.NodeA.Veth, egressPin)
	harness.AttachTCIngress(t, top.NodeB.Namespace, top.NodeB.Veth, ingressPin)

	ctx := context.Background()

	if err := harness.SeedIdentity(ctx, writer, wire.Identity{
		ID:       identityRemoteClient,
		PodIPv4:  top.NodeA.OverlayIP,
		SpiffeID: "spiffe://meridian/ns/default/sa/remote-client",
	}); err != nil {
		t.Fatalf("seed node A identity: %v", err)
	}
	if err := harness.SeedIdentity(ctx, writer, wire.Identity{
		ID:       identityLocalServer,
		PodIPv4:  top.NodeB.OverlayIP,
		SpiffeID: "spiffe://meridian/ns/default/sa/local-server",
	}); err != nil {
		t.Fatalf("seed node B identity: %v", err)
	}

	if err := harness.SeedPolicy(ctx, writer, wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: identityRemoteClient,
			DstIdentity: identityLocalServer,
			DstPort:     geneveAllowPort,
			Protocol:    6,
			Direction:   wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	}); err != nil {
		t.Fatalf("seed allow policy: %v", err)
	}
	if err := harness.SeedPolicy(ctx, writer, wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: identityRemoteClient,
			DstIdentity: identityLocalServer,
			DstPort:     geneveDenyPort,
			Protocol:    6,
			Direction:   wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
	}); err != nil {
		t.Fatalf("seed deny policy: %v", err)
	}

	var seededID uint32
	overlayKey := overlayIPv4Key(t, top.NodeA.OverlayIP)
	if err := ingressObjs.IdentityMap.Lookup(overlayKey, &seededID); err != nil {
		t.Fatalf("lookup seeded overlay identity: %v", err)
	}
	if seededID != uint32(identityRemoteClient) {
		t.Fatalf("overlay identity=%d want %d", seededID, identityRemoteClient)
	}

	harness.AssertAllowed(t, top.NodeA.Namespace, top.NodeB.Namespace, top.NodeB.OverlayIP, geneveAllowPort)
	harness.AssertDenied(t, top.NodeA.Namespace, top.NodeB.Namespace, top.NodeB.OverlayIP, geneveDenyPort)
}

func loadGenevePrograms(t *testing.T, pinDir string) (*bpf.TcIngressObjects, *bpf.TcEgressObjects, datapath.Writer) {
	t.Helper()

	counter, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("load shared counter/maps: %v", err)
	}
	if err := counter.Close(); err != nil {
		t.Fatalf("close counter after map pin: %v", err)
	}

	var ingress bpf.TcIngressObjects
	if err := bpf.LoadTcIngressObjects(&ingress, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}); err != nil {
		t.Fatalf("load tc_ingress: %v", err)
	}

	var egress bpf.TcEgressObjects
	if err := bpf.LoadTcEgressObjects(&egress, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}); err != nil {
		_ = ingress.Close()
		t.Fatalf("load tc_egress: %v", err)
	}

	writer := datapath.NewWriter(ingress.IdentityMap, ingress.PolicyMap)
	return &ingress, &egress, writer
}

func overlayIPv4Key(t *testing.T, addr string) uint32 {
	t.Helper()
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		t.Fatalf("parse overlay addr %q: %v", addr, err)
	}
	if !parsed.Is4() {
		t.Fatalf("overlay addr %q is not IPv4", addr)
	}
	v4 := parsed.As4()
	return binary.NativeEndian.Uint32(v4[:])
}

func dumpGeneveGateMetrics(t *testing.T, egressMap, ingressMap *ebpf.Map) {
	t.Helper()
	for _, pair := range []struct {
		name string
		m    *ebpf.Map
	}{
		{"egress", egressMap},
		{"ingress", ingressMap},
	} {
		reader := metrics.NewMapReader(pair.m)
		for _, id := range []metrics.MetricID{
			metrics.MetricPacketsTotal,
			metrics.MetricGeneveEncapFail,
			metrics.MetricGeneveDecodeFail,
			metrics.MetricFlowsDenied,
			metrics.MetricFlowsAllowed,
		} {
			v, err := reader.Read(id)
			t.Logf("%s metric %d = %d err=%v", pair.name, id, v, err)
		}
	}
}

func dumpDeniedFlowsMap(t *testing.T, m *ebpf.Map) {
	t.Helper()
	type flowKey struct {
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
	var (
		key flowKey
		val denyInfo
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		t.Logf("denied flow src=%#x dst=%#x sport=%#x dport=%#x proto=%d reason=%d count=%d",
			key.SrcIP, key.DstIP, key.SrcPort, key.DstPort, key.Proto, val.Reason, val.Count)
	}
	if err := iter.Err(); err != nil {
		t.Logf("denied flows iterate: %v", err)
	}
}
