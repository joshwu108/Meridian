//go:build bpf

package bpftest

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	cfgSlotUnknownIdentity = uint32(0)
	cfgFailopenUnknownBit  = uint32(1 << 0)
	tcActShot              = 2
)

func TestTcIngressLoad(t *testing.T) {
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
}

func TestTcIngressIdentityHit(t *testing.T) {
	objs := loadTcIngress(t)

	pkt := synthIPv4Packet(6, []byte{10, 0, 1, 2}, []byte{10, 0, 1, 3})
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[26:30]), 1001)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[30:34]), 1002)

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
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[26:30]), 3001)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[30:34]), 3002)

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

	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[26:30]), 3901)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[30:34]), 3902)
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

func TestTcIngressMalformedIPv4RespectsUnknownIdentityPosture(t *testing.T) {
	objs := loadTcIngress(t)

	// IHL=4 is malformed (<5), so parse_l4_ports fails before identity lookup.
	pkt := synthMalformedIPv4IHLPacket(4)

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run (fail-closed malformed): %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("malformed IPv4 fail-closed verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}

	if err := objs.RuntimeConfigMap.Put(cfgSlotUnknownIdentity, cfgFailopenUnknownBit); err != nil {
		t.Fatalf("set runtime_config_map fail-open flag: %v", err)
	}
	ret, err = objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run (fail-open malformed): %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("malformed IPv4 fail-open verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}
}

func loadTcIngress(t *testing.T) *bpf.TcIngressObjects {
	t.Helper()
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
