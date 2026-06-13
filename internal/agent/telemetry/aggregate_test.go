package telemetry

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/joshuawu/meridian/internal/agent/identitytable"
	"github.com/joshuawu/meridian/pkg/wire"
)

func TestAggregatorCountsAndPrometheusLabels(t *testing.T) {
	aggregator := NewAggregator(16)
	resolver := identitytable.NewYAMLResolver([]wire.Identity{
		{
			ID:       101,
			SpiffeID: "spiffe://cluster.local/ns/default/sa/frontend",
		},
		{
			ID:       202,
			SpiffeID: "spiffe://cluster.local/ns/default/sa/backend",
		},
		{
			ID:       303,
			SpiffeID: "spiffe://cluster.local/ns/default/sa/payments",
		},
		{
			ID:       404,
			SpiffeID: "   ",
		},
	})

	events := []Event{
		{SrcIdentity: 101, DstIdentity: 202, Verdict: VerdictAllow, Bytes: 100},
		{SrcIdentity: 101, DstIdentity: 202, Verdict: VerdictAllow, Bytes: 50},
		{SrcIdentity: 101, DstIdentity: 202, Verdict: VerdictDeny, Bytes: 25},
		{SrcIdentity: 303, DstIdentity: 202, Verdict: VerdictDeny, Bytes: 5},
		{SrcIdentity: 999, DstIdentity: 202, Verdict: VerdictAllow, Bytes: 7},  // src unresolved
		{SrcIdentity: 888, DstIdentity: 202, Verdict: VerdictAllow, Bytes: 11}, // src unresolved (same labels)
		{SrcIdentity: 101, DstIdentity: 998, Verdict: VerdictAllow, Bytes: 9},  // dst unresolved
		{SrcIdentity: 101, DstIdentity: 404, Verdict: VerdictAllow, Bytes: 13}, // blank spiffe => unknown
	}
	for _, event := range events {
		aggregator.Handle(event)
	}

	byPair := make(map[[2]uint32]Aggregate)
	for _, aggregate := range aggregator.Snapshot() {
		byPair[[2]uint32{aggregate.SrcIdentity, aggregate.DstIdentity}] = aggregate
	}

	mustPair := func(src, dst uint32) Aggregate {
		t.Helper()
		aggregate, ok := byPair[[2]uint32{src, dst}]
		if !ok {
			t.Fatalf("missing aggregate for pair (%d,%d)", src, dst)
		}
		return aggregate
	}

	agg := mustPair(101, 202)
	if agg.AllowCount != 2 || agg.DenyCount != 1 || agg.ByteCount != 175 {
		t.Fatalf("pair (101,202) = %#v, want allow=2 deny=1 bytes=175", agg)
	}
	agg = mustPair(303, 202)
	if agg.AllowCount != 0 || agg.DenyCount != 1 || agg.ByteCount != 5 {
		t.Fatalf("pair (303,202) = %#v, want allow=0 deny=1 bytes=5", agg)
	}
	agg = mustPair(999, 202)
	if agg.AllowCount != 1 || agg.DenyCount != 0 || agg.ByteCount != 7 {
		t.Fatalf("pair (999,202) = %#v, want allow=1 deny=0 bytes=7", agg)
	}
	agg = mustPair(888, 202)
	if agg.AllowCount != 1 || agg.DenyCount != 0 || agg.ByteCount != 11 {
		t.Fatalf("pair (888,202) = %#v, want allow=1 deny=0 bytes=11", agg)
	}

	registry := prometheus.NewRegistry()
	registry.MustRegister(NewAggregateCollector(aggregator, resolver))

	expected := `
# HELP meridian_flow_allow_total Total ALLOW verdicts per source/destination identity pair.
# TYPE meridian_flow_allow_total counter
meridian_flow_allow_total{dst_identity="spiffe://cluster.local/ns/default/sa/backend",src_identity="spiffe://cluster.local/ns/default/sa/frontend"} 2
meridian_flow_allow_total{dst_identity="spiffe://cluster.local/ns/default/sa/backend",src_identity="unknown"} 2
meridian_flow_allow_total{dst_identity="unknown",src_identity="spiffe://cluster.local/ns/default/sa/frontend"} 2
meridian_flow_allow_total{dst_identity="spiffe://cluster.local/ns/default/sa/backend",src_identity="spiffe://cluster.local/ns/default/sa/payments"} 0
# HELP meridian_flow_bytes_total Total bytes per source/destination identity pair.
# TYPE meridian_flow_bytes_total counter
meridian_flow_bytes_total{dst_identity="spiffe://cluster.local/ns/default/sa/backend",src_identity="spiffe://cluster.local/ns/default/sa/frontend"} 175
meridian_flow_bytes_total{dst_identity="spiffe://cluster.local/ns/default/sa/backend",src_identity="unknown"} 18
meridian_flow_bytes_total{dst_identity="unknown",src_identity="spiffe://cluster.local/ns/default/sa/frontend"} 22
meridian_flow_bytes_total{dst_identity="spiffe://cluster.local/ns/default/sa/backend",src_identity="spiffe://cluster.local/ns/default/sa/payments"} 5
# HELP meridian_flow_deny_total Total DENY verdicts per source/destination identity pair.
# TYPE meridian_flow_deny_total counter
meridian_flow_deny_total{dst_identity="spiffe://cluster.local/ns/default/sa/backend",src_identity="spiffe://cluster.local/ns/default/sa/frontend"} 1
meridian_flow_deny_total{dst_identity="spiffe://cluster.local/ns/default/sa/backend",src_identity="unknown"} 0
meridian_flow_deny_total{dst_identity="unknown",src_identity="spiffe://cluster.local/ns/default/sa/frontend"} 0
meridian_flow_deny_total{dst_identity="spiffe://cluster.local/ns/default/sa/backend",src_identity="spiffe://cluster.local/ns/default/sa/payments"} 1
`

	if err := testutil.GatherAndCompare(
		registry,
		strings.NewReader(expected),
		"meridian_flow_allow_total",
		"meridian_flow_deny_total",
		"meridian_flow_bytes_total",
	); err != nil {
		t.Fatalf("prometheus gather and compare: %v", err)
	}
}

func TestAggregatorCardinalityBoundLRUEviction(t *testing.T) {
	const cap = 3
	aggregator := NewAggregator(cap)

	// Fill capacity.
	aggregator.Handle(Event{SrcIdentity: 1, DstIdentity: 1, Verdict: VerdictAllow, Bytes: 1})
	aggregator.Handle(Event{SrcIdentity: 2, DstIdentity: 2, Verdict: VerdictAllow, Bytes: 1})
	aggregator.Handle(Event{SrcIdentity: 3, DstIdentity: 3, Verdict: VerdictAllow, Bytes: 1})

	// Touch (2,2) so (1,1) becomes least recently used.
	aggregator.Handle(Event{SrcIdentity: 2, DstIdentity: 2, Verdict: VerdictAllow, Bytes: 1})

	// Add a new pair above cap; (1,1) should be evicted.
	aggregator.Handle(Event{SrcIdentity: 4, DstIdentity: 4, Verdict: VerdictAllow, Bytes: 1})

	if got := aggregator.Size(); got > cap {
		t.Fatalf("tracked keys = %d, want <= %d", got, cap)
	}

	seen := make(map[[2]uint32]struct{}, cap)
	for _, aggregate := range aggregator.Snapshot() {
		seen[[2]uint32{aggregate.SrcIdentity, aggregate.DstIdentity}] = struct{}{}
	}

	if _, ok := seen[[2]uint32{1, 1}]; ok {
		t.Fatalf("expected oldest pair (1,1) to be evicted, still present")
	}
	for _, pair := range [][2]uint32{{2, 2}, {3, 3}, {4, 4}} {
		if _, ok := seen[pair]; !ok {
			t.Fatalf("expected pair (%d,%d) to be present after eviction", pair[0], pair[1])
		}
	}
}

func TestAggregatorWithExampleProducer(t *testing.T) {
	aggregator := NewAggregator(64)
	producer := NewExampleProducer(2 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var emitted atomic.Uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = producer.Run(ctx, func(event Event) {
			aggregator.Handle(event)
			if emitted.Add(1) >= 8 {
				cancel()
			}
		})
	}()

	select {
	case <-done:
	case <-time.After(750 * time.Millisecond):
		t.Fatal("producer run did not stop after cancellation")
	}

	var total uint64
	for _, aggregate := range aggregator.Snapshot() {
		total += aggregate.AllowCount + aggregate.DenyCount
	}
	if total == 0 {
		t.Fatal("expected at least one aggregate from ExampleProducer")
	}
}

func TestAggregatorConcurrentHandleAndSnapshot(t *testing.T) {
	aggregator := NewAggregator(256)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var writers sync.WaitGroup
	for i := 0; i < 4; i++ {
		writers.Add(1)
		go func(base uint32) {
			defer writers.Done()
			for j := uint32(0); j < 2000; j++ {
				select {
				case <-ctx.Done():
					return
				default:
				}
				aggregator.Handle(Event{
					SrcIdentity: base + (j % 32),
					DstIdentity: 1000 + (j % 32),
					Verdict:     VerdictAllow,
					Bytes:       1,
				})
			}
		}(uint32(i * 100))
	}

	var readers sync.WaitGroup
	for i := 0; i < 4; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for j := 0; j < 500; j++ {
				_ = aggregator.Snapshot()
			}
		}()
	}

	writers.Wait()
	cancel()
	readers.Wait()

	if got := aggregator.Size(); got == 0 {
		t.Fatal("expected non-zero key count after concurrent ingest")
	}
}
