//go:build bpf

package bpftest

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/agent/metrics"
)

// MER-19 (T-3): parser-negative regression net for tc_ingress. Each case must
// return TC_ACT_OK, bump METRIC_PACKETS_TOTAL, and emit no flow_event.
func TestMalformedPacketsPassthrough(t *testing.T) {
	cases := []struct {
		name    string
		packet  []byte
		dataEnd uint32 // 0 => skb data_end == len(packet)
	}{
		{name: "truncated eth", packet: synthTruncatedEthPacket(), dataEnd: 10},
		{name: "truncated IPv4", packet: synthTruncatedIPv4Packet()},
		{name: "ihl less than 5", packet: synthMalformedIPv4IHLPacket(4)},
		{name: "ihl greater than 15", packet: synthMalformedIPv4IHLPacket(16)},
		{name: "ihl 15 truncated options", packet: synthMalformedIPv4IHLOptionsTruncated()},
		{name: "vlan tagged passthrough until MER-43", packet: synthVLANTaggedNonIPv4Packet(0x86dd)},
		{name: "non-IPv4 ARP", packet: synthNonIPv4Packet(0x0806)},
		{name: "non-IPv4 IPv6", packet: synthNonIPv4Packet(0x86dd)},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			objs := loadTcIngress(t)
			reader := newRingReader(t, objs.FlowEvents)
			t.Cleanup(func() { _ = reader.Close() })

			before, err := metrics.NewMapReader(objs.MetricsMap).Read(metrics.MetricPacketsTotal)
			if err != nil {
				t.Fatalf("read packets metric before run: %v", err)
			}

			ret, err := runTcIngressPacket(t, objs, tc.packet, tc.dataEnd)
			if err != nil {
				t.Fatalf("prog test run: %v", err)
			}
			if ret != tcActOK {
				t.Fatalf("verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
			}

			after, err := metrics.NewMapReader(objs.MetricsMap).Read(metrics.MetricPacketsTotal)
			if err != nil {
				t.Fatalf("read packets metric after run: %v", err)
			}
			if after != before+1 {
				t.Fatalf("METRIC_PACKETS_TOTAL = %d, want %d", after, before+1)
			}

			assertNoRingEvent(t, reader)
		})
	}
}

func runTcIngressPacket(t *testing.T, objs *bpf.TcIngressObjects, pkt []byte, dataEnd uint32) (uint32, error) {
	t.Helper()
	if dataEnd == 0 {
		return objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt})
	}
	ctx := tcSkBuffPrefix{
		Len:     uint32(len(pkt)),
		Data:    0,
		DataEnd: dataEnd,
	}
	return objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: pkt, Context: ctx})
}

func newRingReader(t *testing.T, flowEvents *ebpf.Map) *ringbuf.Reader {
	t.Helper()
	reader, err := ringbuf.NewReader(flowEvents)
	if err != nil {
		t.Fatalf("new ring reader: %v", err)
	}
	return reader
}

func assertNoRingEvent(t *testing.T, reader *ringbuf.Reader) {
	t.Helper()
	reader.SetDeadline(time.Now().Add(50 * time.Millisecond))
	var rec ringbuf.Record
	err := reader.ReadInto(&rec)
	if err == nil {
		t.Fatalf("unexpected flow_event (%d bytes) on parser-negative path", len(rec.RawSample))
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("ring read: %v, want deadline exceeded (no event)", err)
	}
}
