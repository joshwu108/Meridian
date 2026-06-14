//go:build bpf

package bpftest

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/reference"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	cfgSlotUnknownIdentity = uint32(0)
	cfgFailopenUnknownBit  = uint32(1 << 0)
	tcActShot              = 2
)

func TestTcIngressLoad(t *testing.T) {
	objs := loadTcIngress(t)
	_ = objs // load-only smoke; loadTcIngress registers Close cleanup
}

func TestTcIngressIdentityHit(t *testing.T) {
	objs := loadTcIngress(t)

	pkt := synthIPv4Packet(6, []byte{10, 0, 1, 2}, []byte{10, 0, 1, 3})
	const srcID, dstID = uint32(1001), uint32(1002)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[26:30]), srcID)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[30:34]), dstID)
	seedAllowIngressPolicyFromPacket(t, objs.PolicyMap, pkt, srcID, dstID)

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("identity hit verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}
}

func TestTcIngressIdentityMissFailClosed(t *testing.T) {
	objs := loadTcIngress(t)

	pkt := synthIPv4Packet(6, []byte{10, 0, 2, 2}, []byte{10, 0, 2, 3})
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[26:30]), 2001)
	// Dst intentionally missing.

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("identity miss verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
}

func TestTcIngressIdentityMissFailOpen(t *testing.T) {
	objs := loadTcIngress(t)

	pkt := synthIPv4Packet(17, []byte{10, 0, 3, 2}, []byte{10, 0, 3, 3})
	if err := objs.RuntimeConfigMap.Put(cfgSlotUnknownIdentity, cfgFailopenUnknownBit); err != nil {
		t.Fatalf("set runtime_config_map fail-open flag: %v", err)
	}

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("identity miss fail-open verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}
}

func TestTcIngressIdentityZeroFailClosed(t *testing.T) {
	objs := loadTcIngress(t)

	pkt := synthIPv4Packet(6, []byte{10, 0, 4, 2}, []byte{10, 0, 4, 3})
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[26:30]), 4001)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[30:34]), 0)

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("identity zero fail-closed verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
}

func TestTcIngressIdentityZeroFailOpen(t *testing.T) {
	objs := loadTcIngress(t)

	pkt := synthIPv4Packet(6, []byte{10, 0, 5, 2}, []byte{10, 0, 5, 3})
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[26:30]), 5001)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[30:34]), 0)
	if err := objs.RuntimeConfigMap.Put(cfgSlotUnknownIdentity, cfgFailopenUnknownBit); err != nil {
		t.Fatalf("set runtime_config_map fail-open flag: %v", err)
	}

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("identity zero fail-open verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}
}

func TestTcIngressIPv4PacketPassesWhenIdentitiesPresent(t *testing.T) {
	objs := loadTcIngress(t)

	// UDP frame exercises the UDP parse path (separate from TCP identity-hit test).
	pkt := synthIPv4Packet(17, []byte{10, 1, 1, 2}, []byte{10, 1, 1, 3})
	const srcID, dstID = uint32(3001), uint32(3002)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[26:30]), srcID)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[30:34]), dstID)
	seedAllowIngressPolicyFromPacket(t, objs.PolicyMap, pkt, srcID, dstID)

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("IPv4 UDP verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}
}

func TestTcIngressIPv4NonTcpUdpStillRequiresIdentities(t *testing.T) {
	objs := loadTcIngress(t)

	// ICMP packet: parser skips L4 ports, but identity posture still applies.
	pkt := synthIPv4Packet(1, []byte{10, 1, 9, 2}, []byte{10, 1, 9, 3})

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run (identity miss, fail-closed): %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("IPv4 ICMP miss verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}

	if err := objs.RuntimeConfigMap.Put(cfgSlotUnknownIdentity, cfgFailopenUnknownBit); err != nil {
		t.Fatalf("set runtime_config_map fail-open flag: %v", err)
	}
	ret, err = objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run (identity miss, fail-open): %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("IPv4 ICMP miss fail-open verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}

	const srcID, dstID = uint32(3901), uint32(3902)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[26:30]), srcID)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[30:34]), dstID)
	seedAllowIngressPolicyFromPacket(t, objs.PolicyMap, pkt, srcID, dstID)
	ret, err = objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run (identity hit): %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("IPv4 ICMP identity-hit verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}
}

func TestTcIngressNonIPv4PacketPasses(t *testing.T) {
	objs := loadTcIngress(t)

	pkt := synthNonIPv4Packet(0x0806) // ARP ethertype
	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("non-IPv4 verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}
}

func TestTcIngressVlanTaggedSameVerdictAsUntagged(t *testing.T) {
	objs := loadTcIngress(t)

	srcIP := []byte{10, 43, 0, 2}
	dstIP := []byte{10, 43, 0, 3}
	const srcID = uint32(4301)
	const dstID = uint32(4302)

	untagged := synthIPv4Packet(6, srcIP, dstIP)
	tagged := synthVLANTaggedIPv4Packet(6, srcIP, dstIP)

	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(srcIP), srcID)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(dstIP), dstID)
	seedPolicy(t, objs.PolicyMap, reference.Rule{
		SrcIdentity: wire.IdentityID(srcID),
		DstIdentity: wire.IdentityID(dstID),
		DstPort:     8080,
		Protocol:    6,
		Direction:   reference.DirectionIngress,
		Verdict:     wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	})

	untaggedRet, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: untagged})
	if err != nil {
		t.Fatalf("untagged prog run: %v", err)
	}
	taggedRet, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: tagged})
	if err != nil {
		t.Fatalf("vlan-tagged prog run: %v", err)
	}
	if untaggedRet != tcActOK {
		t.Fatalf("untagged verdict = %d, want TC_ACT_OK (%d)", untaggedRet, tcActOK)
	}
	if taggedRet != untaggedRet {
		t.Fatalf("vlan-tagged verdict = %d, want same as untagged %d", taggedRet, untaggedRet)
	}
}

func TestTcIngressGeneveCarriedIdentityAllows(t *testing.T) {
	objs := loadTcIngress(t)

	const remoteIdentity = uint32(9001)
	const localIdentity = uint32(9002)
	innerSrc := []byte{10, 200, 80, 1}
	innerDst := []byte{10, 200, 80, 2}

	pkt := synthGeneveIPv4PacketWithIdentity(6, innerSrc, innerDst, remoteIdentity)
	// Remote src is NOT in identity_map; only local dst is seeded.
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(innerDst), localIdentity)
	seedPolicy(t, objs.PolicyMap, reference.Rule{
		SrcIdentity: wire.IdentityID(remoteIdentity),
		DstIdentity: wire.IdentityID(localIdentity),
		DstPort:     8080,
		Protocol:    6,
		Direction:   reference.DirectionIngress,
		Verdict:     wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	})

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("geneve carried identity verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}
}

func TestTcIngressGeneveTEBCarriedIdentityAllows(t *testing.T) {
	objs := loadTcIngress(t)

	const remoteIdentity = uint32(1001)
	const localIdentity = uint32(2001)
	innerSrc := []byte{10, 200, 80, 1}
	innerDst := []byte{10, 200, 80, 2}

	pkt := synthGeneveTEBPacketWithIdentity(6, innerSrc, innerDst, remoteIdentity)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(innerDst), localIdentity)
	seedPolicy(t, objs.PolicyMap, reference.Rule{
		SrcIdentity: wire.IdentityID(remoteIdentity),
		DstIdentity: wire.IdentityID(localIdentity),
		DstPort:     8080,
		Protocol:    6,
		Direction:   reference.DirectionIngress,
		Verdict:     wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	})

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("geneve TEB carried identity verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}
}

func TestTcIngressGeneveMissingTLVFailClosed(t *testing.T) {
	objs := loadTcIngress(t)

	innerSrc := []byte{10, 200, 81, 1}
	innerDst := []byte{10, 200, 81, 2}
	pkt := synthGeneveIPv4Packet(6, innerSrc, innerDst, false)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(innerDst), 9102)

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("missing TLV verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
}

func loadTcIngress(t *testing.T) *bpf.TcIngressObjects {
	t.Helper()
	bpfLoadMu.Lock()
	defer bpfLoadMu.Unlock()

	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	var objs bpf.TcIngressObjects
	if err := bpf.LoadTcIngressObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: harness.PinDir(t)},
	}); err != nil {
		t.Fatalf("load tc_ingress objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return &objs
}

// seedAllowIngressPolicyFromPacket seeds an ALLOW rule keyed on the packet's
// L4 tuple so identity-resolved flows pass default-deny enforcement (MER-17+).
func seedAllowIngressPolicyFromPacket(t *testing.T, m *ebpf.Map, pkt []byte, srcID, dstID uint32) {
	t.Helper()
	const ethHdrLen = 14
	ip := pkt[ethHdrLen:]
	proto := ip[9]
	ihl := int(ip[0]&0x0f) * 4
	l4 := pkt[ethHdrLen+ihl:]
	dstPort := uint16(0)
	if proto == 6 || proto == 17 {
		dstPort = binary.BigEndian.Uint16(l4[2:4])
	}
	seedPolicy(t, m, reference.Rule{
		SrcIdentity: wire.IdentityID(srcID),
		DstIdentity: wire.IdentityID(dstID),
		DstPort:     dstPort,
		Protocol:    proto,
		Direction:   reference.DirectionIngress,
		Verdict:     wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	})
}

func seedIdentity(t *testing.T, m *ebpf.Map, ipKey uint32, id uint32) {
	t.Helper()
	if err := m.Put(ipKey, id); err != nil {
		t.Fatalf("seed identity_map[%d]=%d: %v", ipKey, id, err)
	}
}

func keyFromIPv4Wire(ipv4 []byte) uint32 {
	// Matches how BPF loads ip->saddr/ip->daddr from packet memory on little-endian hosts.
	return binary.LittleEndian.Uint32(ipv4)
}
