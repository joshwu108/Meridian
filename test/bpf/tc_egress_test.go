//go:build bpf

package bpftest

import (
	"encoding/binary"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/agent/metrics"
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

func TestTcEgressSuccessfulEncapsulation(t *testing.T) {
	objs := loadTcEgress(t)

	pkt := synthGeneveIPv4Packet(6, []byte{10, 60, 1, 2}, []byte{10, 60, 1, 3}, true)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire([]byte{10, 60, 1, 2}), 7001)

	ret, err := objs.MeridianTcEgress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("egress verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}

	geneve := pkt[14+20+8:]
	if got := geneve[0] & 0x3f; got != 2 {
		t.Fatalf("geneve opt_len words=%d, want 2", got)
	}
}

func TestTcEgressIdentityPropagation(t *testing.T) {
	objs := loadTcEgress(t)

	const srcIdentity = uint32(8123)
	pkt := synthGeneveIPv4Packet(17, []byte{10, 61, 1, 2}, []byte{10, 61, 1, 3}, true)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire([]byte{10, 61, 1, 2}), srcIdentity)

	ret, err := objs.MeridianTcEgress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("identity propagation verdict=%d, want TC_ACT_OK (%d)", ret, tcActOK)
	}

	opt := pkt[14+20+8+8 : 14+20+8+8+8]
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
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire([]byte{10, 62, 1, 2}), 9001)

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

func loadTcEgress(t *testing.T) *bpf.TcEgressObjects {
	t.Helper()
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
