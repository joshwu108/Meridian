package telemetry

import (
	"context"
	"net"
	"time"
)

// ExampleProducer emits synthetic flow Events for local development and demos.
// It intentionally has no kernel or TC dependencies.
type ExampleProducer struct {
	interval time.Duration
	now      func() time.Time
	baseMono uint64
}

// NewExampleProducer constructs a producer with a fixed interval. A non-positive
// interval falls back to 250ms.
func NewExampleProducer(interval time.Duration) *ExampleProducer {
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	return &ExampleProducer{
		interval: interval,
		now:      time.Now,
		baseMono: uint64(time.Now().UnixNano()),
	}
}

// Run emits one Event per tick until ctx is cancelled.
func (p *ExampleProducer) Run(ctx context.Context, handler Handler) error {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	var seq uint64
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			handler(p.eventFor(seq))
			seq++
		}
	}
}

func (p *ExampleProducer) eventFor(seq uint64) Event {
	ts := p.now()
	// Use a synthetic monotonic timeline so examples preserve the same
	// invariant as kernel events (monotonic value is not wall clock).
	mono := p.baseMono + uint64(p.interval)*seq
	return Event{
		Timestamp:    ts,
		MonotonicNs:  mono,
		SrcIP:        net.IPv4(10, 42, 0, byte((seq%250)+1)).To4(),
		DstIP:        net.IPv4(10, 43, 0, byte((seq%250)+1)).To4(),
		SrcPort:      uint16(10000 + (seq % 1000)),
		DstPort:      8080,
		Proto:        6, // TCP
		Verdict:      VerdictAllow,
		SrcIdentity:  0, // Phase 0: no identity producer yet.
		DstIdentity:  0,
		Bytes:        128 + uint32(seq%2048),
		LatencyNs:    0, // Phase 0: no L7 proxy latency input.
		L7StatusCode: 0, // Phase 0: no L7 status input.
	}
}
