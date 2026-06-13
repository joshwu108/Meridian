//go:build bpf

package bpftest

import (
	"encoding/binary"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/test/harness"
)

// tcActOK is the verdict the counter program returns for every packet (it
// only counts, never drops). Value from uapi/linux/pkt_cls.h.
const tcActOK = 0

func TestMain(m *testing.M) {
	// Nothing netns-y to reap in a pure prog-test-run suite, but clear any
	// pins a crashed integration run left behind, and our own afterwards.
	harness.Reap()
	code := m.Run()
	harness.Reap()
	os.Exit(code)
}

// TestProgRunCountsSyntheticPacket loads the counter program, feeds it one
// synthetic Ethernet+IPv4+TCP frame via BPF_PROG_TEST_RUN, and asserts the
// return code is TC_ACT_OK and the PERCPU counter incremented to exactly one.
func TestProgRunCountsSyntheticPacket(t *testing.T) {
	harness.RequireRoot(t)

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	objs, err := bpfobj.LoadCounter(harness.PinDir(t))
	if err != nil {
		t.Fatalf("load counter objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	ret, err := objs.MeridianCounter.Run(&ebpf.RunOptions{Data: synthTCPPacket()})
	if err != nil {
		t.Fatalf("prog test run: %v", err)
	}
	if ret != tcActOK {
		t.Fatalf("verdict = %d, want TC_ACT_OK (%d)", ret, tcActOK)
	}

	sum, err := metrics.NewMapReader(objs.MetricsMap).Read(metrics.MetricPacketsTotal)
	if err != nil {
		t.Fatalf("read PERCPU counter: %v", err)
	}
	// Exactly one: prog.Run sent exactly one packet and this test owns the
	// freshly created (per-test pin dir) map. Switch to a delta check if a
	// future shared fixture reuses loaded objects across subtests.
	if sum != 1 {
		t.Fatalf("counter = %d after one packet, want 1", sum)
	}
}

// synthTCPPacket builds a minimal well-formed Ethernet + IPv4 + TCP frame.
// The counter's parser must accept it (IPv4 ethertype, ihl=5, TCP). All
// multi-byte network fields are big-endian, matching on-wire layout.
func synthTCPPacket() []byte {
	const (
		ethHdrLen = 14
		ipHdrLen  = 20
		tcpHdrLen = 20
	)
	pkt := make([]byte, ethHdrLen+ipHdrLen+tcpHdrLen)

	// Ethernet.
	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})  // dst MAC (locally administered)
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01}) // src MAC
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800)  // ethertype = IPv4

	// IPv4.
	ip := pkt[ethHdrLen:]
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], ipHdrLen+tcpHdrLen)
	binary.BigEndian.PutUint16(ip[4:6], 0x0001) // identification
	binary.BigEndian.PutUint16(ip[6:8], 0x4000) // DF
	ip[8] = 64 // TTL
	ip[9] = 6  // TCP
	copy(ip[12:16], []byte{169, 254, 10, 2}) // src
	copy(ip[16:20], []byte{169, 254, 10, 1}) // dst

	// TCP.
	tcp := pkt[ethHdrLen+ipHdrLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 49152) // src port
	binary.BigEndian.PutUint16(tcp[2:4], 8080)  // dst port
	tcp[12] = 0x50                              // data offset 5
	tcp[13] = 0x02                              // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)

	return pkt
}
