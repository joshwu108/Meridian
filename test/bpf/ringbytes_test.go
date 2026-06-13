//go:build bpf

package bpftest

import (
	"encoding/binary"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/reference"
	"github.com/joshuawu/meridian/pkg/wire"
)

const flowEventWireSize = int(unsafe.Sizeof(bpf.TcIngressFlowEvent{}))

// MER-19 (T-4): byte-level ring record assertion after prog_test_run.
func TestFlowEventRingRecordBytes(t *testing.T) {
	objs := loadTcIngress(t)
	reader := newRingReader(t, objs.FlowEvents)
	t.Cleanup(func() { _ = reader.Close() })

	srcIP := []byte{169, 254, 10, 2}
	dstIP := []byte{169, 254, 10, 1}
	pkt := synthTCPPacket()
	// synthTCPPacket already sets SYN in tcp[13]; offset 47 = eth(14)+ip(20)+tcp(13).

	const (
		srcIdentity = uint32(5001)
		dstIdentity = uint32(5002)
	)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[26:30]), srcIdentity)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(pkt[30:34]), dstIdentity)
	seedPolicy(t, objs.PolicyMap, reference.Rule{
		SrcIdentity: wire.IdentityID(srcIdentity),
		DstIdentity: wire.IdentityID(dstIdentity),
		DstPort:     8080,
		Protocol:    6,
		Direction:   reference.DirectionIngress,
		Verdict: wire.PolicyVerdict{
			Action: wire.PolicyActionDeny,
		},
	})

	ret, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActShot {
		t.Fatalf("verdict = %d, want TC_ACT_SHOT (%d)", ret, tcActShot)
	}

	reader.SetDeadline(time.Now().Add(500 * time.Millisecond))
	var rec ringbuf.Record
	if err := reader.ReadInto(&rec); err != nil {
		t.Fatalf("read flow_event: %v", err)
	}
	if len(rec.RawSample) != flowEventWireSize {
		t.Fatalf("record size = %d, want %d", len(rec.RawSample), flowEventWireSize)
	}

	raw := rec.RawSample
	if got := binary.LittleEndian.Uint64(raw[0:8]); got == 0 {
		t.Fatalf("timestamp_ns at offset 0 = 0, want non-zero monotonic stamp")
	}
	if got := binary.BigEndian.Uint32(raw[8:12]); got != binary.BigEndian.Uint32(srcIP) {
		t.Fatalf("src_ip at offset 8 = %#x, want %#x", got, binary.BigEndian.Uint32(srcIP))
	}
	if got := binary.BigEndian.Uint32(raw[12:16]); got != binary.BigEndian.Uint32(dstIP) {
		t.Fatalf("dst_ip at offset 12 = %#x, want %#x", got, binary.BigEndian.Uint32(dstIP))
	}
	if got := binary.BigEndian.Uint16(raw[16:18]); got != 49152 {
		t.Fatalf("src_port at offset 16 = %d, want 49152", got)
	}
	if got := binary.BigEndian.Uint16(raw[18:20]); got != 8080 {
		t.Fatalf("dst_port at offset 18 = %d, want 8080", got)
	}
	if raw[20] != 6 {
		t.Fatalf("proto at offset 20 = %d, want 6 (TCP)", raw[20])
	}
	if raw[21] != 1 {
		t.Fatalf("verdict at offset 21 = %d, want 1 (DENY)", raw[21])
	}
	if got := binary.LittleEndian.Uint16(raw[22:24]); got != 0 {
		t.Fatalf("_pad0 at offset 22 = %#x, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(raw[24:28]); got != srcIdentity {
		t.Fatalf("src_identity at offset 24 = %d, want %d", got, srcIdentity)
	}
	if got := binary.LittleEndian.Uint32(raw[28:32]); got != dstIdentity {
		t.Fatalf("dst_identity at offset 28 = %d, want %d", got, dstIdentity)
	}
	if got := binary.LittleEndian.Uint32(raw[32:36]); got != uint32(len(pkt)) {
		t.Fatalf("bytes at offset 32 = %d, want %d", got, len(pkt))
	}
	if got := binary.LittleEndian.Uint32(raw[36:40]); got != 0 {
		t.Fatalf("_pad1 at offset 36 = %#x, want 0", got)
	}
	if got := binary.LittleEndian.Uint64(raw[40:48]); got != 0 {
		t.Fatalf("latency_ns at offset 40 = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint16(raw[48:50]); got != 0 {
		t.Fatalf("l7_status_code at offset 48 = %d, want 0", got)
	}
	for off := 50; off < 56; off += 2 {
		if got := binary.LittleEndian.Uint16(raw[off : off+2]); got != 0 {
			t.Fatalf("_pad2 at offset %d = %#x, want 0", off, got)
		}
	}
}
