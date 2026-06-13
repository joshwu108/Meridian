package telemetry

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func TestExampleProducerEventFor(t *testing.T) {
	p := NewExampleProducer(100 * time.Millisecond)
	fixed := time.Unix(1700000000, 123456789)
	p.now = func() time.Time { return fixed }
	p.baseMono = 1_000_000

	ev := p.eventFor(7)

	if !ev.Timestamp.Equal(fixed) {
		t.Fatalf("Timestamp = %v, want %v", ev.Timestamp, fixed)
	}
	if ev.MonotonicNs != 1_700_000_000 {
		t.Fatalf("MonotonicNs = %d, want %d", ev.MonotonicNs, uint64(1_700_000_000))
	}
	if !ev.SrcIP.Equal(net.IPv4(10, 42, 0, 8)) {
		t.Fatalf("SrcIP = %v, want 10.42.0.8", ev.SrcIP)
	}
	if !ev.DstIP.Equal(net.IPv4(10, 43, 0, 8)) {
		t.Fatalf("DstIP = %v, want 10.43.0.8", ev.DstIP)
	}
	if ev.SrcPort != 10007 {
		t.Fatalf("SrcPort = %d, want 10007", ev.SrcPort)
	}
	if ev.DstPort != 8080 {
		t.Fatalf("DstPort = %d, want 8080", ev.DstPort)
	}
	if ev.Proto != 6 {
		t.Fatalf("Proto = %d, want 6", ev.Proto)
	}
	if ev.Verdict != VerdictAllow {
		t.Fatalf("Verdict = %d, want %d", ev.Verdict, VerdictAllow)
	}
	if ev.Bytes != 135 {
		t.Fatalf("Bytes = %d, want 135", ev.Bytes)
	}
}

func TestNewExampleProducer_DefaultInterval(t *testing.T) {
	p := NewExampleProducer(0)
	if p.interval != 250*time.Millisecond {
		t.Fatalf("interval = %v, want 250ms", p.interval)
	}
}

func TestExampleProducerRun_EmitsAndStopsOnCancel(t *testing.T) {
	p := NewExampleProducer(10 * time.Millisecond)
	p.now = func() time.Time { return time.Unix(1700000000, 0) }
	p.baseMono = 10

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var count atomic.Uint64
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.Run(ctx, func(Event) {
			if count.Add(1) >= 3 {
				cancel()
			}
		})
	}()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Run did not return after cancellation")
	}

	if count.Load() < 3 {
		t.Fatalf("events emitted = %d, want at least 3", count.Load())
	}
}
