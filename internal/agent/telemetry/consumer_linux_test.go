//go:build linux

package telemetry

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// countOpenFDs returns the number of file descriptors held by this process by
// counting entries under /proc/self/fd. os.ReadDir opens (and closes) one fd
// internally before returning, so it does not perturb the steady-state count.
func countOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// newTestRingbufMap creates a real BPF ring buffer map for the consumer to read
// from. It skips (rather than fails) when the environment forbids BPF — local
// non-root dev boxes, locked-down kernels — so this hygiene gate never reddens
// CI for reasons unrelated to the fd-leak it guards.
func newTestRingbufMap(t *testing.T) *ebpf.Map {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("cannot remove memlock rlimit (need privileges): %v", err)
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name: "test_flow_events",
		Type: ebpf.RingBuf,
		// Ring buffer size must be a power-of-two multiple of the page size;
		// exactly one page is the smallest valid value on any arch.
		MaxEntries: uint32(os.Getpagesize()),
	})
	if err != nil {
		if errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) {
			t.Skipf("cannot create BPF ringbuf map in this environment: %v", err)
		}
		t.Fatalf("create ringbuf map: %v", err)
	}
	return m
}

// TestConsumerCloseReleasesReaderWithoutRun is the MER-39 T1 gate (review
// A-4 / D-8): New opens a ringbuf reader fd; if Run is never called, Close must
// still release it, and Close must be idempotent.
func TestConsumerCloseReleasesReaderWithoutRun(t *testing.T) {
	m := newTestRingbufMap(t)
	t.Cleanup(func() { _ = m.Close() })

	// Baseline is taken after the map fd already exists, so it is not counted
	// against the consumer; only fds opened by New must be released by Close.
	baseline := countOpenFDs(t)

	c, err := New(m)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if afterNew := countOpenFDs(t); afterNew <= baseline {
		t.Fatalf("New opened no fd (baseline=%d afterNew=%d); test cannot prove the leak is fixed", baseline, afterNew)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if afterClose := countOpenFDs(t); afterClose > baseline {
		t.Fatalf("Close leaked fds across New→Close without Run: baseline=%d afterClose=%d", baseline, afterClose)
	}

	// Idempotent: a second Close must not error or alter the fd count.
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := countOpenFDs(t); got > baseline {
		t.Fatalf("second Close changed fd count: baseline=%d got=%d", baseline, got)
	}
}
