//go:build linux

package telemetry

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/joshuawu/meridian/bpf"
)

// flowEventSize is the on-ring record size (56 bytes), derived from the
// bpf2go-generated struct so it tracks any future layout bump automatically.
const flowEventSize = int(unsafe.Sizeof(bpf.CounterFlowEvent{}))

// Consumer wraps a ringbuf.Reader over the flow_events map and accounts for
// userspace-side decode errors. Kernel-side drops (bpf_ringbuf_reserve
// failures) are counted separately in metrics_map[METRIC_RINGBUF_DROPPED] by
// the producer; the two domains are never conflated.
type Consumer struct {
	reader *ringbuf.Reader
	bootNs int64 // CLOCK_REALTIME - CLOCK_MONOTONIC, computed once at startup

	closeOnce sync.Once // guards exactly-once close of the reader fd
	closeErr  error     // result of the single reader.Close, shared by callers

	decoded   atomic.Uint64 // successfully decoded records
	decodeErr atomic.Uint64 // short/garbled records (counted, skipped)
}

// New constructs a Consumer over the given ring buffer map. The caller owns
// the *ebpf.Map lifecycle; Consumer only reads from it.
func New(flowEvents *ebpf.Map) (*Consumer, error) {
	if flowEvents == nil {
		return nil, errors.New("telemetry: nil flow_events map")
	}
	reader, err := ringbuf.NewReader(flowEvents)
	if err != nil {
		return nil, err
	}
	return &Consumer{
		reader: reader,
		bootNs: computeBootOffsetNs(),
	}, nil
}

// closeReader closes the underlying ringbuf reader exactly once, regardless of
// how many paths race to shut the Consumer down: an explicit Close, Run's
// ctx-cancel watcher, and Run's deferred cleanup all funnel through here.
// ringbuf.Reader.Close is the only call that releases the reader fd and the
// only way to unblock an in-flight ReadInto (it makes pending reads return
// ringbuf.ErrClosed).
func (c *Consumer) closeReader() error {
	c.closeOnce.Do(func() {
		c.closeErr = c.reader.Close()
	})
	return c.closeErr
}

// Close releases the ringbuf reader fd. It exists for the lifecycle path where
// New succeeds but Run is never called: without it the reader fd would leak
// until process exit (review A-4 / D-8, MER-39). Close is idempotent and safe
// to call after — or concurrently with — Run, whose own shutdown also closes
// the reader; the redundant close is a no-op.
func (c *Consumer) Close() error {
	return c.closeReader()
}

// computeBootOffsetNs returns (CLOCK_REALTIME - CLOCK_MONOTONIC) in ns.
// Kernel flow_event timestamps come from bpf_ktime_get_ns (CLOCK_MONOTONIC
// since boot); adding this offset yields wall-clock time. Computed once: the
// clocks drift only by NTP slew, negligible for telemetry windows.
func computeBootOffsetNs() int64 {
	var realtime, monotonic unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_REALTIME, &realtime)
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic)
	return realtime.Nano() - monotonic.Nano()
}

// Run reads records until ctx is cancelled, invoking handler for each decoded
// Event. It returns nil on clean shutdown, or the first fatal read error.
//
// Shutdown contract: ringbuf.Reader.Read blocks; the only way to unblock it
// is reader.Close, which makes the in-flight and all subsequent reads return
// ringbuf.ErrClosed. A small watcher goroutine calls Close on ctx.Done; the
// loop treats ErrClosed as a clean stop.
func (c *Consumer) Run(ctx context.Context, handler Handler) error {
	closed := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = c.closeReader() // unblocks ReadInto with ErrClosed
		case <-closed:
		}
	}()
	defer close(closed)
	// Backstop: release the reader fd on every Run exit, including the fatal
	// read-error path, where the watcher above returns via <-closed without
	// closing the reader. Idempotent with the watcher and any explicit Close.
	defer c.closeReader()

	var rec ringbuf.Record
	for {
		// ReadInto reuses rec's backing buffer across iterations, keeping the
		// steady state allocation-free on the hot goroutine.
		if err := c.reader.ReadInto(&rec); err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil // clean shutdown via ctx cancel
			}
			return err
		}

		if len(rec.RawSample) < flowEventSize {
			c.decodeErr.Add(1) // count and skip; never panic on bad input
			continue
		}
		// Reinterpret the sample as the generated wire struct. The ring buffer
		// guarantees 8-byte alignment of samples, and the layout is owned by
		// bpf2go (never hand-written), so the direct cast is safe and avoids
		// reflection on the hot path.
		wire := *(*bpf.CounterFlowEvent)(unsafe.Pointer(&rec.RawSample[0]))
		c.decoded.Add(1)
		handler(c.fromWire(wire))
	}
}

// fromWire maps the generated wire struct to the domain Event, applying
// byte-order and timestamp normalisation.
func (c *Consumer) fromWire(w bpf.CounterFlowEvent) Event {
	return Event{
		Timestamp:    wallClock(w.TimestampNs, c.bootNs),
		MonotonicNs:  w.TimestampNs,
		SrcIP:        ipFromBE32(w.SrcIp),
		DstIP:        ipFromBE32(w.DstIp),
		SrcPort:      ntohs(w.SrcPort),
		DstPort:      ntohs(w.DstPort),
		Proto:        w.Proto,
		Verdict:      Verdict(w.Verdict),
		SrcIdentity:  w.SrcIdentity,
		DstIdentity:  w.DstIdentity,
		Bytes:        w.Bytes,
		LatencyNs:    w.LatencyNs,
		L7StatusCode: w.L7StatusCode,
	}
}

// Stats are userspace-side counters for the future Prometheus endpoint.
type Stats struct {
	Decoded      uint64
	DecodeErrors uint64
}

func (c *Consumer) Stats() Stats {
	return Stats{
		Decoded:      c.decoded.Load(),
		DecodeErrors: c.decodeErr.Load(),
	}
}
