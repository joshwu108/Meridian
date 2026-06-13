//go:build bpf

package bpftest

import (
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
