//go:build bpf

package bpftest

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/internal/reference"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

const dropReasonGeneveEncapFail = uint32(5)

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

func runTcEgress(t *testing.T, prog *ebpf.Program, pkt []byte) (uint32, []byte) {
	t.Helper()
	// Live encap may grow the skb by MERIDIAN_GENEVE_OPT_BYTES via adjust_room;
	// prog_test_run needs headroom in DataOut or the helper returns ENOSPC.
	out := make([]byte, len(pkt)+8)
	copy(out, pkt)
	ret, err := prog.Run(&ebpf.RunOptions{Data: pkt, DataOut: out})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	return ret, out
}

func TestTcEgressSuccessfulEncapsulation(t *testing.T) {
	objs := loadTcEgress(t)

	pkt := synthGeneveIPv4Packet(6, []byte{10, 60, 1, 2}, []byte{10, 60, 1, 3}, true)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire([]byte{10, 60, 1, 2}), 7001)

	ret, out := runTcEgress(t, objs.MeridianTcEgress, pkt)
	if ret != tcActOK {
		t.Fatalf("egress verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}

	geneve := out[14+20+8:]
	if got := geneve[0] & 0x3f; got != 2 {
		t.Fatalf("geneve opt_len words=%d, want 2", got)
	}
}

// TestTcEgressAdjustRoomPath exercises the live kernel path where Geneve frames
// arrive without pre-reserved TLV headroom (MER-28 / ADR-0002).
func TestTcEgressAdjustRoomPath(t *testing.T) {
	objs := loadTcEgress(t)
	reader := metrics.NewMapReader(objs.MetricsMap)

	pkt := synthGeneveIPv4Packet(6, []byte{10, 60, 2, 2}, []byte{10, 60, 2, 3}, false)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire([]byte{10, 60, 2, 2}), 7002)

	before, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric before: %v", err)
	}

	ret, out := runTcEgress(t, objs.MeridianTcEgress, pkt)
	if ret != tcActOK {
		after, _ := reader.Read(metrics.MetricGeneveEncapFail)
		t.Fatalf("adjust-room egress verdict=%d, want TC_ACT_OK (%d); encap_fail=%d->%d",
			ret, tcActOK, before, after)
	}

	after, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric after: %v", err)
	}
	if after != before {
		t.Fatalf("encap fail metric=%d, want unchanged %d", after, before)
	}

	geneve := out[14+20+8:]
	if got := geneve[0] & 0x3f; got != 2 {
		t.Fatalf("geneve opt_len words=%d, want 2", got)
	}
	opt := out[14+20+8+8 : 14+20+8+8+8]
	if got := binary.BigEndian.Uint32(opt[4:8]); got != 7002 {
		t.Fatalf("identity body=%d, want 7002", got)
	}
}

func TestTcEgressKernelTEBPath(t *testing.T) {
	objs := loadTcEgress(t)
	reader := metrics.NewMapReader(objs.MetricsMap)

	innerSrc := []byte{10, 60, 3, 2}
	innerDst := []byte{10, 60, 3, 3}
	pkt := synthGeneveTEBIPv4Packet(6, innerSrc, innerDst)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(innerSrc), 7003)

	before, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric before: %v", err)
	}

	ret, out := runTcEgress(t, objs.MeridianTcEgress, pkt)
	if ret != tcActOK {
		after, _ := reader.Read(metrics.MetricGeneveEncapFail)
		t.Fatalf("TEB egress verdict=%d, want TC_ACT_OK (%d); encap_fail=%d->%d",
			ret, tcActOK, before, after)
	}

	after, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric after: %v", err)
	}
	if after != before {
		t.Fatalf("encap fail metric=%d, want unchanged %d", after, before)
	}

	geneve := out[14+20+8:]
	if got := geneve[0] & 0x3f; got != 2 {
		t.Fatalf("geneve opt_len words=%d, want 2", got)
	}
}

func TestTcEgressKernelEncapShapeAdjustRoom(t *testing.T) {
	objs := loadTcEgress(t)

	const srcIdentity = uint32(7010)
	pkt := synthGeneveIPv4Packet(6, []byte{10, 60, 2, 2}, []byte{10, 60, 2, 3}, false)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire([]byte{10, 60, 2, 2}), srcIdentity)

	ret, out := runTcEgress(t, objs.MeridianTcEgress, pkt)
	if ret != tcActOK {
		t.Fatalf("kernel encap shape verdict=%d, want TC_ACT_OK (%d)", ret, tcActOK)
	}

	geneve := out[14+20+8:]
	if got := geneve[0] & 0x3f; got != 2 {
		t.Fatalf("geneve opt_len words=%d, want 2 after adjust_room", got)
	}
	opt := out[14+20+8+8 : 14+20+8+8+8]
	if got := binary.BigEndian.Uint32(opt[4:8]); got != srcIdentity {
		t.Fatalf("identity body=%d, want %d", got, srcIdentity)
	}
}

func TestTcEgressIdentityPropagation(t *testing.T) {
	objs := loadTcEgress(t)

	const srcIdentity = uint32(8123)
	pkt := synthGeneveIPv4Packet(17, []byte{10, 61, 1, 2}, []byte{10, 61, 1, 3}, true)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire([]byte{10, 61, 1, 2}), srcIdentity)

	ret, out := runTcEgress(t, objs.MeridianTcEgress, pkt)
	if ret != tcActOK {
		t.Fatalf("identity propagation verdict=%d, want TC_ACT_OK (%d)", ret, tcActOK)
	}

	opt := out[14+20+8+8 : 14+20+8+8+8]
	if got := binary.BigEndian.Uint16(opt[0:2]); got != 0x4d52 {
		t.Fatalf("option class=0x%x, want 0x4d52", got)
	}
	if opt[2] != 1 {
		t.Fatalf("option type=%d, want 1", opt[2])
	}
	if opt[3] != 1 {
		t.Fatalf("option len words=%d, want 1", opt[3])
	}
	if got := binary.BigEndian.Uint32(opt[4:8]); got != srcIdentity {
		t.Fatalf("identity body=%d, want %d", got, srcIdentity)
	}
}

func TestTcEgressEncapsulationFailure(t *testing.T) {
	objs := loadTcEgress(t)
	reader := metrics.NewMapReader(objs.MetricsMap)

	pkt := synthGeneveIPv4Packet(6, []byte{10, 62, 1, 2}, []byte{10, 62, 1, 3}, false)
	// No identity_map entry: egress cannot stamp the TLV.

	before, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric before: %v", err)
	}

	ret, err := objs.MeridianTcEgress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run (fail-closed): %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("encap failure verdict=%d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}

	after, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric after fail-closed: %v", err)
	}
	if after != before+1 {
		t.Fatalf("encap fail metric=%d, want %d", after, before+1)
	}

	key := flowKey{
		SrcIP:   keyFromIPv4Wire([]byte{10, 62, 1, 2}),
		DstIP:   keyFromIPv4Wire([]byte{10, 62, 1, 3}),
		SrcPort: binary.LittleEndian.Uint16([]byte{0xa0, 0x28}), // 41000 network bytes
		DstPort: binary.LittleEndian.Uint16([]byte{0x1f, 0x90}), // 8080 network bytes
		Proto:   6,
	}
	var info denyInfo
	if err := objs.DeniedFlowsMap.Lookup(&key, &info); err != nil {
		t.Fatalf("lookup denied flow: %v", err)
	}
	if info.Reason != dropReasonGeneveEncapFail {
		t.Fatalf("deny reason=%d, want %d", info.Reason, dropReasonGeneveEncapFail)
	}

	if err := objs.RuntimeConfigMap.Put(cfgSlotUnknownIdentity, cfgFailopenUnknownBit); err != nil {
		t.Fatalf("set runtime_config_map fail-open flag: %v", err)
	}
	ret, err = objs.MeridianTcEgress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run (fail-open): %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("encap failure fail-open verdict=%d, want TC_ACT_OK (%d)", ret, tcActOK)
	}
	afterOpen, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric after fail-open: %v", err)
	}
	if afterOpen != after+1 {
		t.Fatalf("encap fail metric after fail-open=%d, want %d", afterOpen, after+1)
	}
}

func TestTcEgressMalformedPacket(t *testing.T) {
	objs := loadTcEgress(t)
	reader := metrics.NewMapReader(objs.MetricsMap)

	pkt := synthMalformedGenevePacket()

	before, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric before: %v", err)
	}
	ret, err := objs.MeridianTcEgress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("malformed packet verdict=%d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}
	after, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric after: %v", err)
	}
	if after != before+1 {
		t.Fatalf("encap fail metric=%d, want %d", after, before+1)
	}
}

func TestTcEgressVlanTaggedIdentityPropagation(t *testing.T) {
	objs := loadTcEgress(t)

	const srcIdentity = uint32(8124)
	innerSrc := []byte{10, 61, 2, 2}
	innerDst := []byte{10, 61, 2, 3}
	pkt := synthVLANTaggedGeneveIPv4Packet(17, innerSrc, innerDst, true)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(innerSrc), srcIdentity)

	ret, out := runTcEgress(t, objs.MeridianTcEgress, pkt)
	if ret != tcActOK {
		t.Fatalf("vlan-tagged egress verdict=%d, want TC_ACT_OK (%d)", ret, tcActOK)
	}

	// Outer layout: eth(14) + vlan(4) + ip(20) + udp(8) + geneve(8) + opt(8)
	opt := out[14+4+20+8+8 : 14+4+20+8+8+8]
	if got := binary.BigEndian.Uint32(opt[4:8]); got != srcIdentity {
		t.Fatalf("identity body=%d, want %d", got, srcIdentity)
	}
}

func TestTcEgressNonTunnelPassthroughNoEncapFailMetric(t *testing.T) {
	objs := loadTcEgress(t)
	reader := metrics.NewMapReader(objs.MetricsMap)

	pkt := synthTCPPacket()
	before, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric before: %v", err)
	}

	ret, err := objs.MeridianTcEgress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("non-tunnel verdict=%d, want TC_ACT_OK (%d)", ret, tcActOK)
	}

	after, err := reader.Read(metrics.MetricGeneveEncapFail)
	if err != nil {
		t.Fatalf("read metric after: %v", err)
	}
	if after != before {
		t.Fatalf("encap fail metric changed for non-tunnel packet: got=%d want=%d", after, before)
	}
}

func TestTcEgressToIngressTEBRoundTrip(t *testing.T) {
	ingressObjs := loadTcIngress(t)
	egressObjs := loadTcEgress(t)

	const remoteIdentity = uint32(1001)
	const localIdentity = uint32(2001)
	const testPort = 18080
	innerSrc := []byte{10, 200, 80, 1}
	innerDst := []byte{10, 200, 80, 2}

	pkt := synthGeneveTEBIPv4Packet(6, innerSrc, innerDst)
	innerIPOff := 14 + 20 + 8 + 8 + 14
	binary.BigEndian.PutUint16(pkt[innerIPOff+20+2:innerIPOff+20+4], testPort)

	seedIdentity(t, egressObjs.IdentityMap, keyFromIPv4Wire(innerSrc), remoteIdentity)
	seedIdentity(t, ingressObjs.IdentityMap, keyFromIPv4Wire(innerDst), localIdentity)
	seedPolicy(t, ingressObjs.PolicyMap, reference.Rule{
		SrcIdentity: wire.IdentityID(remoteIdentity),
		DstIdentity: wire.IdentityID(localIdentity),
		DstPort:     testPort,
		Protocol:    6,
		Direction:   reference.DirectionIngress,
		Verdict:     wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	})

	egressRet, stamped := runTcEgress(t, egressObjs.MeridianTcEgress, pkt)
	if egressRet != tcActOK {
		t.Fatalf("egress round-trip verdict=%d, want TC_ACT_OK (%d)", egressRet, tcActOK)
	}

	ingressRet, err := ingressObjs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: stamped})
	if err != nil {
		t.Fatalf("ingress prog test run: %v", err)
	}
	if ingressRet != tcActOK {
		t.Fatalf("ingress round-trip verdict=%d, want TC_ACT_OK (%d)", ingressRet, tcActOK)
	}
}

func loadTcEgress(t *testing.T) *bpf.TcEgressObjects {
	t.Helper()
	bpfLoadMu.Lock()
	defer bpfLoadMu.Unlock()

	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	var objs bpf.TcEgressObjects
	if err := bpf.LoadTcEgressObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: harness.PinDir(t)},
	}); err != nil {
		t.Fatalf("load tc_egress objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return &objs
}
