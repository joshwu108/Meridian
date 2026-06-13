//go:build integration

package integration

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/internal/agent/telemetry"
	"github.com/joshuawu/meridian/test/harness"
)

// pingCount is the number of ICMP echoes generated from the peer namespace
// toward the host. Each request crosses HostVeth ingress once, so the PERCPU
// counter must reach at least this many (">=" because ARP and other
// host-bound packets on the link are also counted).
const pingCount = 5

func TestMain(m *testing.M) {
	harness.Reap()
	code := m.Run()
	harness.Reap()
	os.Exit(code)
}

// TestCounterCountsAndEmitsEvents brings up a veth pair, loads and attaches
// the counter TC program to the host-side veth, generates ICMP traffic from
// the peer namespace, and asserts that (a) the PERCPU counter sums to >=
// pingCount and (b) the real telemetry consumer decoded at least one event
// with the expected peer->host addresses. This is the O-1/P0.2 gate: the
// whole pipeline, kernel hook through Go decode, in one test.
func TestCounterCountsAndEmitsEvents(t *testing.T) {
	harness.RequireRoot(t)

	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	// Load with per-test pinning so the harness reaper covers leaks.
	pinDir := harness.PinDir(t)
	objs, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("load counter objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	// Pin the program so `tc` can attach it by path (Phase 0 mechanism).
	progPin := filepath.Join(pinDir, "counter_prog")
	if err := objs.MeridianCounter.Pin(progPin); err != nil {
		t.Fatalf("pin program: %v", err)
	}

	v := harness.NewVethPair(t, "p0", 10)
	v.AttachTC(t, progPin)

	// Start the REAL ring consumer (internal/agent/telemetry) before any
	// traffic so no events are missed; events fan into a buffered channel.
	consumer, err := telemetry.New(objs.FlowEvents)
	if err != nil {
		t.Fatalf("new consumer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	events := make(chan telemetry.Event, 256)
	go func() {
		_ = consumer.Run(ctx, func(ev telemetry.Event) {
			select {
			case events <- ev:
			default: // full: drop; the test only needs one match
			}
		})
	}()

	// Generate traffic: one-shot workload, so `ip netns exec` is correct.
	v.ExecInNS(t, "ping", "-c", strconv.Itoa(pingCount), "-i", "0.2", "-W", "1", v.HostAddr)

	// Assertion 1: PERCPU counter reaches the ping count.
	harness.WaitUntil(t, 3*time.Second, func() bool {
		sum, err := metrics.NewMapReader(objs.MetricsMap).Read(metrics.MetricPacketsTotal)
		return err == nil && sum >= uint64(pingCount)
	}, "PERCPU packet counter never reached ping count")

	// Assertion 2: the consumer decoded a plausible peer->host event.
	hostIP := net.ParseIP(v.HostAddr)
	peerIP := net.ParseIP(v.PeerIP)
	harness.WaitUntil(t, 3*time.Second, func() bool {
		for {
			select {
			case ev := <-events:
				if ev.MonotonicNs != 0 && ev.SrcIP.Equal(peerIP) && ev.DstIP.Equal(hostIP) {
					return true
				}
			default:
				return false
			}
		}
	}, "no plausible flow event decoded from the ring buffer")
}

