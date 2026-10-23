//go:build integration

// O-5 (docs/subsystems/06-observability.md, "Load validation") — the
// flow-events ring buffer under sustained load.
//
// Two NFRs are gated here, both against the PRODUCTION path (bpfobj loader →
// meridian_tc_ingress → flow_events → internal/agent/telemetry consumer →
// Aggregator), never a stand-in:
//
//  1. Drop rate < 0.1% at the NFR's 1M events/s. Numerator and denominator
//     both come from the kernel: METRIC_RINGBUF_DROPPED counts
//     bpf_ringbuf_reserve failures, METRIC_FLOWS_ALLOWED counts
//     emit_flow_event calls on the ALLOW path. Userspace never estimates
//     either side.
//  2. RSS cost within the agent's 50 MB budget while the maps hold ~10k
//     identity and a FULL 16k-entry policy map and the Aggregator holds 10k
//     live identity pairs (O-5's cardinality stress), and that cost is stable
//     across successive load windows rather than growing.
//
// Load generation is BPF_PROG_TEST_RUN (cilium/ebpf prog.Run with Repeat), the
// same facility test/bpf/ uses. Real veth traffic cannot reach 1M pps inside
// the 4-vCPU Lima target, and the NFR is about the ring buffer and its
// consumer, not the NIC path: prog.Run drives the identical program with the
// identical maps and the identical ring, one flow_event per invocation.
//
// Emission is PACED to o5TargetRate on purpose. Unpaced, this target reaches
// ~9.4M events/s and drops ~1.8% — the single Go consumer goroutine, not the
// ring, is the bottleneck there. That is the saturation point, not the NFR:
// O-5 specifies the drop budget AT 1M pps, so the gate measures at 1M pps and
// asserts the achieved rate actually landed there (o5RateTolerance).
//
// RSS CAVEAT — read before changing the budget assertion. This gate asserts
// the RSS DELTA from an idle baseline, not absolute process RSS. A Go test
// binary for this package starts at ~35 MiB before it does anything, and
// bpfobj's BTF/ELF parsing churns a further ~38 MiB of transient heap; both
// are properties of the test process, not of the agent, and comparing their
// sum against the agent's 50 MB budget would measure the wrong program. The
// baseline is taken once the objects are loaded and the consumer is running —
// the agent's idle footprint — so the asserted delta is exactly what holding
// 10k identities, a full policy map, and 10k live aggregates costs. Absolute
// RSS is reported for the record. The agent binary's own absolute RSS belongs
// to the Phase 8 e2e demo, which runs the real process.
package integration

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/internal/agent/telemetry"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	// o5DropRateBudget is the NFR from 06-observability.md risk #2: under 0.1%
	// of emitted flow events may be lost to ring-buffer reserve failures.
	o5DropRateBudget = 0.001

	// o5TargetRate is the rate the NFR names (1M pps). Emission is paced to it;
	// see the RSS/pacing notes in the package comment above.
	o5TargetRate = 1_000_000.0

	// o5RateTolerance is how far below o5TargetRate the achieved rate may land
	// before the drop-rate result stops being a measurement at the NFR point.
	// Without this floor a host too slow to reach the target would pass the
	// gate with zero drops and prove nothing.
	o5RateTolerance = 0.90

	// o5RateCeiling bounds overshoot above o5TargetRate. cilium/ebpf restarts an
	// interrupted prog.Run with the FULL Repeat count again (its EINTR retry), so
	// the kernel can execute more invocations than the pacer counted. Overshoot
	// is rare here (~0.01% observed) and only makes the drop budget harder to
	// meet, but left unbounded it would let the gate quietly measure the drop
	// rate above the NFR's operating point and report a failure as if the NFR,
	// rather than the harness, were at fault.
	o5RateCeiling = 1.10

	// o5RSSBudgetBytes is the agent's documented RSS budget (O-5: "stable RSS
	// within the agent's 50 MB budget"). Asserted against the delta from the
	// idle baseline — see the RSS CAVEAT in the package comment.
	o5RSSBudgetBytes = 50 << 20

	// o5RSSGrowthBudgetBytes bounds what a SECOND identical load window may add
	// on top of the first. The counters, the aggregate table, and the pair set
	// are all bounded, so a steady-state pipeline adds ~nothing; a per-event
	// leak shows up here as linear growth. Sized to absorb Go heap lumpiness
	// (span-level granularity, scavenger timing) without admitting a real leak,
	// which at 1M events/s would run to tens of MiB per window.
	o5RSSGrowthBudgetBytes = 8 << 20

	// o5SourceIdentities is O-5's cardinality stress point: this many distinct
	// source identities, all talking to one destination, so the Aggregator ends
	// the run holding exactly this many live (src,dst) pairs. identity_map
	// therefore holds o5SourceIdentities+1 entries (the shared destination).
	o5SourceIdentities = 10_000

	// o5PolicyEntries fills policy_map to its frozen capacity
	// (MERIDIAN_POLICY_MAP_ENTRIES = 16384, ADR-0004): o5SourceIdentities real
	// ALLOW rules plus never-matching filler. A full map is the worst case for
	// the kernel-side hash lookups on the emit path.
	o5PolicyEntries = 16_384

	// o5LoadWindow is one sustained-emission window, and o5LoadWindows how many
	// run back to back. Two windows are what make the RSS claim a STABILITY
	// claim: window 1 establishes the pipeline's working set, window 2 shows it
	// does not keep growing. A window is long enough that the ring reaches
	// fill/drain equilibrium rather than being absorbed by its 4 MiB of slack.
	o5LoadWindow  = 5 * time.Second
	o5LoadWindows = 2

	// o5RunRepeat is the in-kernel replay count per prog.Run syscall. It trades
	// syscall and pacing overhead against sweep granularity: every emitter must
	// complete whole sweeps of its shard, so calls-per-window must stay well
	// above shard size. At the target rate this yields ~39k calls per shard
	// against a ~5k shard, i.e. several full sweeps per window.
	o5RunRepeat = 64

	// o5MinSweeps is how many complete passes over its shard an emitter makes
	// before the window deadline may end it. Two, not one, and deliberately:
	// Consumer.Run bumps its Decoded counter BEFORE invoking the handler, so
	// "all events decoded" does not prove the Aggregator has seen the last one.
	// A second sweep means every identity was handled well before the final
	// event, which is what actually makes the pair count deterministic rather
	// than a race against that counter.
	o5MinSweeps = 2

	o5DstPort  uint16 = 8080
	o5DstID           = wire.IdentityID(60_000)
	o5ProtoTCP uint8  = 6
)

// o5DstAddr is the single destination every source identity talks to, so the
// live pair count is exactly the source count.
var o5DstAddr = netip.MustParseAddr("10.80.0.1")

// TestRingBufDropRateGate_O5 is the O-5 load-validation gate.
func TestRingBufDropRateGate_O5(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	ctx := context.Background()
	objs, err := bpfobj.LoadTcIngress(harness.PinDir(t))
	if err != nil {
		t.Fatalf("bpfobj.LoadTcIngress: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	// --- Start the real consumer and aggregator before any emission. ---
	consumer, err := telemetry.New(objs.FlowEvents)
	if err != nil {
		t.Fatalf("telemetry.New: %v", err)
	}
	// Capacity must admit the whole pool: a smaller bound would silently evict
	// pairs via LRU and understate both cardinality and RSS.
	aggregator := telemetry.NewAggregator(o5SourceIdentities)
	runCtx, cancelRun := context.WithCancel(ctx)
	runErr := make(chan error, 1)
	runDone := make(chan struct{})
	go func() {
		runErr <- consumer.Run(runCtx, aggregator.Handle)
		close(runDone)
	}()
	// Registered AFTER the objs.Close cleanup, so LIFO runs it FIRST. On an
	// abort path — any t.Fatalf below — cancelling is not sufficient:
	// cancellation only signals Consumer.Run to close its reader, and
	// objs.Close() unpins the flow_events map. Close must not run while the
	// reader goroutine is still in ReadInto, so wait for Run to have RETURNED.
	// Idempotent with the happy-path drain at the end of the test.
	t.Cleanup(func() {
		cancelRun()
		select {
		case <-runDone:
		case <-time.After(10 * time.Second):
			t.Errorf("consumer.Run did not return within 10s of cancel; skipping the wait would race objs.Close against the live ringbuf reader")
		}
	})

	// Idle baseline: objects loaded, ring mapped, consumer running, no load and
	// no cardinality yet. Everything asserted against the 50 MB budget is
	// measured as growth from here.
	rssIdle := o5SettledRSSBytes(t)

	// --- Cardinality stress: fill the maps through the real single writer. ---
	// Seeding is ~26k one-entry harness.Seed* calls rather than a few batched
	// CommitPlans. Deliberate: those helpers are the repo's seeding path, and
	// the whole fill measures ~0.2s against a 10s load, so batching would buy
	// nothing and bypass them. ctx is unbounded because datapath.Writer.Apply
	// ignores it (writer_linux.go) — a deadline here would be decorative; the
	// test timeout is the real bound.
	writer := datapath.NewWriter(objs.IdentityMap, objs.PolicyMap)
	srcAddrs := o5SeedIdentities(ctx, t, writer)
	o5SeedPolicies(ctx, t, writer)
	packets := o5SynPackets(srcAddrs)

	// --- Sustained, paced emission across o5LoadWindows windows. ---
	reader := metrics.NewMapReader(objs.MetricsMap)
	allowedBefore := o5ReadMetric(t, reader, metrics.MetricFlowsAllowed)
	droppedBefore := o5ReadMetric(t, reader, metrics.MetricRingbufDropped)

	var (
		elapsed    time.Duration
		rssPerWind = make([]uint64, 0, o5LoadWindows)
	)
	for w := 0; w < o5LoadWindows; w++ {
		elapsed += o5Emit(t, objs.MeridianTcIngress, packets)
		rssPerWind = append(rssPerWind, o5SettledRSSBytes(t))
	}

	allowed := o5ReadMetric(t, reader, metrics.MetricFlowsAllowed) - allowedBefore
	dropped := o5ReadMetric(t, reader, metrics.MetricRingbufDropped) - droppedBefore
	if allowed == 0 {
		t.Fatalf("METRIC_FLOWS_ALLOWED flat after %s of emission: the ALLOW emit path never ran, so nothing was measured", elapsed)
	}
	// Guard the unsigned arithmetic below. METRIC_RINGBUF_DROPPED is bumped by
	// every emit_flow_event path, METRIC_FLOWS_ALLOWED only by the ALLOW one, so
	// drops exceeding allows means some other path (a DENY verdict, a policy
	// miss) emitted during this window and the drop rate below would be
	// attributed to the wrong denominator.
	if dropped > allowed {
		t.Fatalf("metrics_map inconsistent: %d ring-buffer drops exceed %d ALLOW-path emit attempts — an emit path this gate does not account for ran during the load window", dropped, allowed)
	}
	written := allowed - dropped
	dropRate := float64(dropped) / float64(allowed)
	rate := float64(allowed) / elapsed.Seconds()

	// --- Drain, then assert the kernel/userspace event ledger balances. ---
	// A BPF ring buffer never overwrites: a full ring fails the reserve (counted
	// in METRIC_RINGBUF_DROPPED) instead. Every submitted record therefore has
	// to reach the consumer, so decoded == allowed-dropped exactly. Any other
	// value means events were lost somewhere this gate does not measure.
	harness.WaitUntil(t, 30*time.Second, func() bool {
		return consumer.Stats().Decoded >= written
	}, fmt.Sprintf("consumer drained only %d of %d submitted flow events", consumer.Stats().Decoded, written))

	stats := consumer.Stats()
	pairs := o5AwaitPairs(t, aggregator, o5SourceIdentities)
	rssLoaded := rssPerWind[len(rssPerWind)-1]
	rssCost := o5Sub(rssLoaded, rssIdle)
	rssGrowth := o5Sub(rssLoaded, rssPerWind[0])

	t.Logf("O-5 ring-buffer load validation (kernel %s, %d emitter(s), repeat=%d, %d × %s windows):\n"+
		"  emitted      %d events in %s = %.0f events/s (target %.0f)\n"+
		"  kernel drops %d (%.5f%% — budget %.3f%%)\n"+
		"  decoded      %d (ledger %s), decode errors %d\n"+
		"  maps         identity=%d policy=%d/%d (full)\n"+
		"  aggregator   %d live identity pairs\n"+
		"  RSS          idle %.1f MiB → loaded %.1f MiB = cost %.1f MiB (budget %d MiB)\n"+
		"  RSS growth   window 1 %.1f MiB → window %d %.1f MiB = %.1f MiB (budget %.0f MiB)",
		o5KernelRelease(), o5Emitters(), o5RunRepeat, o5LoadWindows, o5LoadWindow,
		allowed, elapsed.Round(time.Millisecond), rate, o5TargetRate,
		dropped, dropRate*100, o5DropRateBudget*100,
		stats.Decoded, map[bool]string{true: "balances", false: "MISMATCH"}[stats.Decoded == written], stats.DecodeErrors,
		o5SourceIdentities+1, o5PolicyEntries, o5PolicyEntries,
		pairs,
		o5MiB(rssIdle), o5MiB(rssLoaded), o5MiB(rssCost), o5RSSBudgetBytes>>20,
		o5MiB(rssPerWind[0]), o5LoadWindows, o5MiB(rssLoaded), o5MiB(rssGrowth), float64(o5RSSGrowthBudgetBytes)/(1<<20))

	if stats.Decoded != written {
		t.Errorf("consumer decoded %d events, want exactly %d (allowed %d - kernel drops %d): the ring lost records without counting them",
			stats.Decoded, written, allowed, dropped)
	}
	if stats.DecodeErrors != 0 {
		t.Errorf("consumer reported %d decode errors, want 0: flow_event layout drift", stats.DecodeErrors)
	}
	if rate < o5TargetRate*o5RateTolerance {
		t.Errorf("achieved %.0f events/s, want at least %.0f (%.0f%% of the %.0f events/s NFR target): the drop-rate result is not a measurement at the NFR operating point",
			rate, o5TargetRate*o5RateTolerance, o5RateTolerance*100, o5TargetRate)
	}
	if rate > o5TargetRate*o5RateCeiling {
		t.Errorf("achieved %.0f events/s, above the %.0f events/s ceiling (%.0f%% of the %.0f events/s NFR target): the pacer overshot, so any drop-rate result below is measured past the NFR operating point, not at it",
			rate, o5TargetRate*o5RateCeiling, o5RateCeiling*100, o5TargetRate)
	}
	if dropRate >= o5DropRateBudget {
		t.Errorf("ring-buffer drop rate %.5f%% (%d of %d events) exceeds the O-5 budget of %.3f%% at %.0f events/s",
			dropRate*100, dropped, allowed, o5DropRateBudget*100, rate)
	}
	if pairs != o5SourceIdentities {
		t.Errorf("aggregator holds %d identity pairs, want %d: the cardinality stress did not materialise, so the RSS figures understate the budget",
			pairs, o5SourceIdentities)
	}
	if rssCost > o5RSSBudgetBytes {
		t.Errorf("RSS cost %.1f MiB over the idle baseline exceeds the agent's %d MiB budget at %d identity pairs and a full %d-entry policy map",
			o5MiB(rssCost), o5RSSBudgetBytes>>20, pairs, o5PolicyEntries)
	}
	if rssGrowth > o5RSSGrowthBudgetBytes {
		t.Errorf("RSS grew %.1f MiB between load window 1 (%.1f MiB) and window %d (%.1f MiB), over the %.0f MiB stability budget: the pipeline is not steady-state at %.0f events/s",
			o5MiB(rssGrowth), o5MiB(rssPerWind[0]), o5LoadWindows, o5MiB(rssLoaded),
			float64(o5RSSGrowthBudgetBytes)/(1<<20), rate)
	}

	// Clean shutdown: cancel, then confirm Run returned without a read error.
	cancelRun()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("consumer.Run: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("consumer.Run did not return after context cancel")
	}
}

// o5AwaitPairs gives the Aggregator a bounded chance to reach want live pairs
// and returns the last count it saw, short or not.
//
// It does NOT fail: the caller asserts on the returned count so the full
// measurement summary is still logged on a shortfall. The wait exists because
// Consumer.Run increments Decoded before calling the handler, so a drained
// ring does not by itself prove the last event has been aggregated —
// o5MinSweeps makes a shortfall essentially impossible, and this closes the
// remaining window instead of relying on that alone.
func o5AwaitPairs(t *testing.T, aggregator *telemetry.Aggregator, want int) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := aggregator.Size()
		if got >= want || time.Now().After(deadline) {
			return got
		}
		time.Sleep(harness.PollInterval)
	}
}

// o5Emitters is the number of concurrent prog.Run drivers. Concurrency is kept
// deliberately below the core count: the consumer is a single goroutine, and
// saturating every core with emitters measures a starved reader rather than the
// ring buffer. Several producers (rather than one) keep the ring's shared
// reserve path contended, as real multi-CPU ingress does.
func o5Emitters() int {
	if n := runtime.NumCPU() - 2; n > 1 {
		return n
	}
	return 1
}

// o5Emit drives one paced load window: BPF_PROG_TEST_RUN from o5Emitters()
// goroutines, together holding o5TargetRate events/s for o5LoadWindow, and
// returns the wall time the window actually took.
//
// Each emitter owns a contiguous shard of the pool and sweeps it in order, so
// one full pass across all emitters touches every source identity exactly once.
// A window always completes o5MinSweeps whole sweeps before honouring its
// deadline, which is what makes the aggregator's pair count deterministic.
//
// Pacing is per-emitter against an absolute schedule (events emitted so far ÷
// its share of the target), so a sleep that overshoots is corrected by the next
// iteration instead of accumulating drift.
func o5Emit(t *testing.T, prog *ebpf.Program, packets [][]byte) time.Duration {
	t.Helper()

	emitters := o5Emitters()
	perEmitterRate := o5TargetRate / float64(emitters)
	var (
		wg      sync.WaitGroup
		errOnce sync.Once
		emitErr error
	)
	start := time.Now()
	deadline := start.Add(o5LoadWindow)
	for e := 0; e < emitters; e++ {
		lo := len(packets) * e / emitters
		hi := len(packets) * (e + 1) / emitters
		wg.Add(1)
		go func(shard [][]byte) {
			defer wg.Done()
			emitted := 0
			for sweep := 0; ; sweep++ {
				for _, pkt := range shard {
					if _, err := prog.Run(&ebpf.RunOptions{Data: pkt, Repeat: o5RunRepeat}); err != nil {
						errOnce.Do(func() { emitErr = err })
						return
					}
					emitted += o5RunRepeat
					due := time.Duration(float64(emitted) / perEmitterRate * float64(time.Second))
					if ahead := due - time.Since(start); ahead > 0 {
						time.Sleep(ahead)
					}
				}
				if sweep+1 >= o5MinSweeps && time.Now().After(deadline) {
					return
				}
			}
		}(packets[lo:hi])
	}
	wg.Wait()
	elapsed := time.Since(start)

	if emitErr != nil {
		t.Fatalf("prog.Run (meridian_tc_ingress): %v", emitErr)
	}
	return elapsed
}

// o5SeedIdentities writes o5SourceIdentities sources plus the shared
// destination through datapath.Writer (the sole writer of identity_map) and
// returns the source pod IPs in pool order.
func o5SeedIdentities(ctx context.Context, t *testing.T, w datapath.Writer) []netip.Addr {
	t.Helper()

	srcAddrs := make([]netip.Addr, o5SourceIdentities)
	for i := range srcAddrs {
		srcAddrs[i] = o5SourceAddr(i)
		if err := harness.SeedIdentity(ctx, w, wire.Identity{
			ID:        wire.IdentityID(i + 1),
			PodIPv4:   srcAddrs[i].String(),
			SpiffeID:  "spiffe://meridian.test/ns/o5/sa/src-" + strconv.Itoa(i),
			Namespace: "o5",
			Name:      "src-" + strconv.Itoa(i),
		}); err != nil {
			t.Fatalf("seed source identity %d: %v", i+1, err)
		}
	}
	if err := harness.SeedIdentity(ctx, w, wire.Identity{
		ID:        o5DstID,
		PodIPv4:   o5DstAddr.String(),
		SpiffeID:  "spiffe://meridian.test/ns/o5/sa/dst",
		Namespace: "o5",
		Name:      "dst",
	}); err != nil {
		t.Fatalf("seed destination identity: %v", err)
	}
	return srcAddrs
}

// o5SeedPolicies fills policy_map to capacity: one ingress ALLOW rule per
// source identity, then never-matching filler up to o5PolicyEntries.
func o5SeedPolicies(ctx context.Context, t *testing.T, w datapath.Writer) {
	t.Helper()

	allow := wire.PolicyVerdict{Action: wire.PolicyActionAllow}
	for i := 0; i < o5SourceIdentities; i++ {
		if err := harness.SeedPolicy(ctx, w, wire.PolicyRule{
			Key: wire.PolicyRuleKey{
				SrcIdentity: wire.IdentityID(i + 1),
				DstIdentity: o5DstID,
				DstPort:     o5DstPort,
				Protocol:    o5ProtoTCP,
				Direction:   wire.DirectionIngress,
			},
			Verdict: allow,
		}); err != nil {
			t.Fatalf("seed allow policy for source %d: %v", i+1, err)
		}
	}

	// Filler occupies the rest of the map under identity IDs no packet carries,
	// so it changes hash-table occupancy without changing any verdict.
	const fillerBase = wire.IdentityID(500_000)
	for j := 0; j < o5PolicyEntries-o5SourceIdentities; j++ {
		if err := harness.SeedPolicy(ctx, w, wire.PolicyRule{
			Key: wire.PolicyRuleKey{
				SrcIdentity: fillerBase + wire.IdentityID(j),
				DstIdentity: o5DstID,
				DstPort:     o5DstPort + 1,
				Protocol:    o5ProtoTCP,
				Direction:   wire.DirectionIngress,
			},
			Verdict: allow,
		}); err != nil {
			t.Fatalf("seed filler policy %d (policy_map capacity is %d): %v", j, o5PolicyEntries, err)
		}
	}
}

// o5SourceAddr maps a pool index to a distinct address inside 10.64.0.0/16,
// which o5SourceIdentities (10k) fits in with room to spare.
func o5SourceAddr(i int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, 64, byte(i / 256), byte(i % 256)})
}

// o5SynPackets builds one immutable Ethernet+IPv4+TCP SYN frame per source IP.
// SYN && !ACK is what makes meridian_tc_ingress treat each invocation as a
// connection open and emit a flow_event on the ALLOW path (eBPF R6:
// decision-point events only), giving exactly one event per prog.Run repeat.
func o5SynPackets(srcAddrs []netip.Addr) [][]byte {
	packets := make([][]byte, len(srcAddrs))
	for i, src := range srcAddrs {
		packets[i] = o5SynPacket(src, o5DstAddr, o5DstPort)
	}
	return packets
}

func o5SynPacket(srcAddr, dstAddr netip.Addr, dstPort uint16) []byte {
	const (
		ethLen = 14
		ipLen  = 20
		tcpLen = 20
	)
	pkt := make([]byte, ethLen+ipLen+tcpLen)

	copy(pkt[0:6], []byte{0x02, 0, 0, 0, 0, 0x02})
	copy(pkt[6:12], []byte{0x02, 0, 0, 0, 0, 0x01})
	binary.BigEndian.PutUint16(pkt[12:14], 0x0800) // IPv4

	ip := pkt[ethLen:]
	ip[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(ip[2:4], ipLen+tcpLen)
	ip[8] = 64
	ip[9] = o5ProtoTCP
	src4 := srcAddr.As4()
	dst4 := dstAddr.As4()
	copy(ip[12:16], src4[:])
	copy(ip[16:20], dst4[:])

	tcp := pkt[ethLen+ipLen:]
	binary.BigEndian.PutUint16(tcp[0:2], 49152)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50 // data offset 5
	tcp[13] = 0x02 // SYN, no ACK
	binary.BigEndian.PutUint16(tcp[14:16], 0xffff)
	return pkt
}

func o5ReadMetric(t *testing.T, r *metrics.MapReader, id metrics.MetricID) uint64 {
	t.Helper()
	v, err := r.Read(id)
	if err != nil {
		t.Fatalf("read metrics_map[%d]: %v", id, err)
	}
	return v
}

// o5SettledRSSBytes returns this process's VmRSS after forcing the Go runtime
// to collect and hand idle spans back to the kernel.
//
// debug.FreeOSMemory is a MEASUREMENT AID, not something the agent does: raw
// VmRSS under a Go program also reflects the scavenger's lazy, time-based
// release schedule, so consecutive readings differ by tens of MiB for reasons
// that have nothing to do with what the pipeline retains. Settling first makes
// each reading reflect live memory, which is what the budget and the stability
// comparison are about.
func o5SettledRSSBytes(t *testing.T) uint64 {
	t.Helper()
	debug.FreeOSMemory()
	return o5ProcessRSSBytes(t)
}

// o5ProcessRSSBytes reads VmRSS for this process. The test binary stands in for
// the agent: it hosts the real ring consumer, the real Aggregator at full
// cardinality, and the real datapath writer. BPF map memory is charged to the
// kernel memcg, not to RSS — the maps are here to load the emit path, and the
// RSS figures are about the agent-side state they drive. See the RSS CAVEAT in
// the package comment for why only deltas are asserted.
func o5ProcessRSSBytes(t *testing.T) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("read /proc/self/status: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("malformed VmRSS line %q", line)
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("parse VmRSS %q: %v", fields[1], err)
		}
		return kb * 1024
	}
	t.Fatalf("VmRSS not present in /proc/self/status")
	return 0
}

// o5Sub is a saturating subtraction: RSS can legitimately fall between
// checkpoints (the settle step releases spans), and an unsigned wrap would turn
// a shrink into a vast fake growth.
func o5Sub(a, b uint64) uint64 {
	if a < b {
		return 0
	}
	return a - b
}

func o5MiB(b uint64) float64 { return float64(b) / (1 << 20) }

func o5KernelRelease() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}
