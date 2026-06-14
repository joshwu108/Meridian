//go:build integration

package integration

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os"
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
	identityMapFallback  = wire.IdentityID(9009)
	geneveAllowPort      = 18080
	geneveDenyPort       = 18081

	tcActOK     = 0
	tcActStolen = 4
)

// TestGeneveIngressIdentityPolicyGate_MER21 is the P1.3 gate: node B's
// tc_ingress decodes remote src_identity from a Geneve TLV (MER-21), and the
// same policy/identity objects enforce allow and deny cases on the live
// two-node Geneve harness (MER-28).
func TestGeneveIngressIdentityPolicyGate_MER21(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	top := harness.NewTwoNode(t, "geneve-gate", 80)
	pinDir := harness.PinDir(t)

	// Resolve the kernel Geneve neighbor path before attaching TC programs so
	// the gate exercises TCP policy/identity enforcement, not first-use ARP.
	top.ExecInNode(t, top.NodeA, "ping", "-c", "1", "-W", "1", top.NodeB.OverlayIP)

	ingressObjs, egressObjs, ingressWriter, egressWriter := loadGenevePrograms(t, pinDir)
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

	harness.AttachTCEgress(t, top.NodeA.Namespace, "gnv0", egressPin)
	harness.AttachTCEgressHost(t, top.HostVethB, egressPin)
	harness.AttachTCIngress(t, top.NodeB.Namespace, top.NodeB.Veth, ingressPin)

	ctx := context.Background()

	if err := harness.SeedIdentity(ctx, egressWriter, wire.Identity{
		ID:       identityRemoteClient,
		PodIPv4:  top.NodeA.OverlayIP,
		SpiffeID: "spiffe://meridian/ns/default/sa/remote-client",
	}); err != nil {
		t.Fatalf("seed node A egress identity: %v", err)
	}
	if err := harness.SeedIdentity(ctx, egressWriter, wire.Identity{
		ID:       identityLocalServer,
		PodIPv4:  top.NodeB.OverlayIP,
		SpiffeID: "spiffe://meridian/ns/default/sa/local-server",
	}); err != nil {
		t.Fatalf("seed node B egress identity: %v", err)
	}
	if err := harness.SeedIdentity(ctx, ingressWriter, wire.Identity{
		ID:       identityMapFallback,
		PodIPv4:  top.NodeA.OverlayIP,
		SpiffeID: "spiffe://meridian/ns/default/sa/ingress-map-fallback",
	}); err != nil {
		t.Fatalf("seed node A ingress fallback identity: %v", err)
	}
	if err := harness.SeedIdentity(ctx, ingressWriter, wire.Identity{
		ID:       identityLocalServer,
		PodIPv4:  top.NodeB.OverlayIP,
		SpiffeID: "spiffe://meridian/ns/default/sa/local-server",
	}); err != nil {
		t.Fatalf("seed node B identity: %v", err)
	}

	if err := harness.SeedPolicy(ctx, ingressWriter, wire.PolicyRule{
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
	if err := harness.SeedPolicy(ctx, ingressWriter, wire.PolicyRule{
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
	if err := harness.SeedPolicy(ctx, egressWriter, wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: identityRemoteClient,
			DstIdentity: identityLocalServer,
			DstPort:     geneveDenyPort,
			Protocol:    6,
			Direction:   wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
	}); err != nil {
		t.Fatalf("seed egress deny policy: %v", err)
	}

	assertGeneveTLVPolicyVerdict(t, ingressObjs, top.NodeA.OverlayIP, top.NodeB.OverlayIP,
		geneveAllowPort, identityRemoteClient, tcActOK)
	assertGeneveTLVPolicyVerdict(t, ingressObjs, top.NodeA.OverlayIP, top.NodeB.OverlayIP,
		geneveDenyPort, identityRemoteClient, tcActStolen)

	var seededID uint32
	overlayKey := overlayIPv4Key(t, top.NodeA.OverlayIP)
	if err := ingressObjs.IdentityMap.Lookup(overlayKey, &seededID); err != nil {
		t.Fatalf("lookup ingress fallback overlay identity: %v", err)
	}
	if seededID != uint32(identityMapFallback) {
		t.Fatalf("ingress fallback identity=%d want %d", seededID, identityMapFallback)
	}
	if err := egressObjs.IdentityMap.Lookup(overlayKey, &seededID); err != nil {
		t.Fatalf("lookup egress overlay identity: %v", err)
	}
	if seededID != uint32(identityRemoteClient) {
		t.Fatalf("egress overlay identity=%d want %d", seededID, identityRemoteClient)
	}

	harness.AssertAllowed(t, top.NodeA.Namespace, top.NodeB.Namespace, top.NodeB.OverlayIP, geneveAllowPort)
	harness.AssertDeniedTimeout(t, top.NodeA.Namespace, top.NodeB.Namespace, top.NodeB.OverlayIP, geneveDenyPort)
}

func loadGenevePrograms(t *testing.T, pinDir string) (*bpf.TcIngressObjects, *bpf.TcEgressObjects, datapath.Writer, datapath.Writer) {
	t.Helper()

	ingressPinDir := filepath.Join(pinDir, "ingress")
	egressPinDir := filepath.Join(pinDir, "egress")
	for _, dir := range []string{ingressPinDir, egressPinDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("create map pin dir %s: %v", dir, err)
		}
	}

	counter, err := bpfobj.LoadCounter(ingressPinDir)
	if err != nil {
		t.Fatalf("load ingress counter/maps: %v", err)
	}
	if err := counter.Close(); err != nil {
		t.Fatalf("close ingress counter after map pin: %v", err)
	}
	counter, err = bpfobj.LoadCounter(egressPinDir)
	if err != nil {
		t.Fatalf("load egress counter/maps: %v", err)
	}
	if err := counter.Close(); err != nil {
		t.Fatalf("close egress counter after map pin: %v", err)
	}

	var ingress bpf.TcIngressObjects
	if err := bpf.LoadTcIngressObjects(&ingress, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: ingressPinDir},
	}); err != nil {
		t.Fatalf("load tc_ingress: %v", err)
	}

	var egress bpf.TcEgressObjects
	if err := bpf.LoadTcEgressObjects(&egress, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: egressPinDir},
	}); err != nil {
		_ = ingress.Close()
		t.Fatalf("load tc_egress: %v", err)
	}

	ingressWriter := datapath.NewWriter(ingress.IdentityMap, ingress.PolicyMap)
	egressWriter := datapath.NewWriter(egress.IdentityMap, egress.PolicyMap)
	return &ingress, &egress, ingressWriter, egressWriter
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

func assertGeneveTLVPolicyVerdict(t *testing.T, objs *bpf.TcIngressObjects, srcIP, dstIP string, dstPort int, srcIdentity wire.IdentityID, want uint32) {
	t.Helper()
	pkt := geneveTEBPacketWithIdentity(t, srcIP, dstIP, dstPort, srcIdentity)
	got, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("geneve TLV ingress prog run: %v", err)
	}
	if got != want {
		t.Fatalf("geneve TLV policy verdict=%d, want %d", got, want)
	}
}

func geneveTEBPacketWithIdentity(t *testing.T, srcIP, dstIP string, dstPort int, srcIdentity wire.IdentityID) []byte {
	t.Helper()
	const (
		ethLen    = 14
		ipLen     = 20
		udpLen    = 8
		geneveLen = 8
		optLen    = 8
		tcpLen    = 20
	)
	innerLen := ethLen + ipLen + tcpLen
	payloadLen := udpLen + geneveLen + optLen + innerLen
	pkt := make([]byte, ethLen+ipLen+payloadLen)

	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)

	outerIP := pkt[ethLen:]
	outerIP[0] = 0x45
	binary.BigEndian.PutUint16(outerIP[2:4], uint16(ipLen+payloadLen))
	outerIP[8] = 64
	outerIP[9] = 17
	copy(outerIP[12:16], []byte{172, 31, 80, 2})
	copy(outerIP[16:20], []byte{172, 31, 81, 2})

	udp := pkt[ethLen+ipLen:]
	binary.BigEndian.PutUint16(udp[0:2], 40000)
	binary.BigEndian.PutUint16(udp[2:4], 6081)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen+geneveLen+optLen+innerLen))

	geneve := udp[udpLen:]
	geneve[0] = 0x02
	binary.BigEndian.PutUint16(geneve[2:4], 0x6558)
	geneve[6] = 0x64
	opt := geneve[geneveLen:]
	binary.BigEndian.PutUint16(opt[0:2], 0x4d52)
	opt[2] = 1
	opt[3] = 1
	binary.BigEndian.PutUint32(opt[4:8], uint32(srcIdentity))

	innerEth := opt[optLen:]
	copy(innerEth[0:6], []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa})
	copy(innerEth[6:12], []byte{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb})
	binary.BigEndian.PutUint16(innerEth[12:14], 0x0800)

	innerIP := innerEth[ethLen:]
	innerIP[0] = 0x45
	binary.BigEndian.PutUint16(innerIP[2:4], ipLen+tcpLen)
	innerIP[8] = 64
	innerIP[9] = 6
	copy(innerIP[12:16], mustIPv4(t, srcIP))
	copy(innerIP[16:20], mustIPv4(t, dstIP))

	tcp := innerIP[ipLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 40001)
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dstPort))
	tcp[12] = 0x50
	tcp[13] = 0x02
	return pkt
}

func mustIPv4(t *testing.T, raw string) []byte {
	t.Helper()
	parsed, err := netip.ParseAddr(raw)
	if err != nil {
		t.Fatalf("parse IPv4 %q: %v", raw, err)
	}
	v4 := parsed.As4()
	return v4[:]
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
