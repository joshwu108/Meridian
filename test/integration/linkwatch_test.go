//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/joshuawu/meridian/internal/agent/linkwatch"
	"github.com/joshuawu/meridian/test/harness"
)

// TestVethAttachLifecycleGate_MER71 is the Phase-3 A-2 gate: the RTNLGRP_LINK
// watcher must call EnsureAttached on every matching host-side veth within
// 100 ms of creation (both reconcile and event paths) and call Detach within
// 100 ms of deletion. No leaked attachments after all veths are removed. Must
// never t.Skip under root on 5.15 (MER-44).
func TestVethAttachLifecycleGate_MER71(t *testing.T) {
	harness.RequireRoot(t)

	const (
		budget = 100 * time.Millisecond
		nPairs = 3
	)

	att := &linkwatchRecorder{
		current:  make(map[string]bool),
		detaches: make(map[string]int),
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	watcher := linkwatch.NewNetlinkWatcher(
		linkwatch.PrefixSelector("mh-"),
		linkwatch.WithWatcherLogf(t.Logf),
	)

	// === Reconcile path: create veths before the watcher starts ===
	// By the time the reconcile-phase assertions pass, the watcher goroutine
	// has completed Reconcile+Events subscription, which acts as a happens-before
	// barrier for the event-path phase below.
	reconcile := make([]*harness.VethPair, nPairs)
	for i := 0; i < nPairs; i++ {
		reconcile[i] = harness.NewVethPair(t, fmt.Sprintf("r71r%d", i), byte(100+i))
	}

	watchErrCh := make(chan error, 1)
	go func() {
		watchErrCh <- linkwatch.Run(ctx, watcher, att, func(op, ifName string, err error) {
			t.Logf("linkwatch error op=%s ifName=%s err=%v", op, ifName, err)
		})
	}()

	for _, p := range reconcile {
		name := p.HostVeth
		harness.WaitUntil(t, budget, func() bool {
			return att.isAttached(name)
		}, fmt.Sprintf("reconcile: %s must get EnsureAttached within %v", name, budget))
	}

	// === Event path: create veths after the watcher is subscribed ===
	// Reconcile assertions above guarantee the watcher reached the event loop.
	event := make([]*harness.VethPair, nPairs)
	for i := 0; i < nPairs; i++ {
		event[i] = harness.NewVethPair(t, fmt.Sprintf("r71e%d", i), byte(110+i))
		name := event[i].HostVeth
		harness.WaitUntil(t, budget, func() bool {
			return att.isAttached(name)
		}, fmt.Sprintf("event: %s must get EnsureAttached within %v", name, budget))
	}

	// === Teardown: delete every veth, assert Detach within budget ===
	all := append(reconcile, event...)
	for _, p := range all {
		name := p.HostVeth
		p.Close() // deletes the link → RTM_DELLINK fires
		harness.WaitUntil(t, budget, func() bool {
			return att.detachCount(name) > 0
		}, fmt.Sprintf("teardown: %s must get Detach within %v of deletion", name, budget))
	}

	// === No leaked attachments: every EnsureAttached was followed by Detach ===
	cancel()
	select {
	case err := <-watchErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("watcher stopped with: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("linkwatch goroutine did not stop within 2s (goroutine leak)")
	}

	att.mu.Lock()
	defer att.mu.Unlock()
	for name := range att.current {
		t.Errorf("leaked attachment: %s still in attached set after all veths deleted", name)
	}
}

// linkwatchRecorder is a thread-safe fake linkwatch.Attacher. It records every
// EnsureAttached and Detach call without touching the kernel, letting the A-2
// gate focus on watcher lifecycle correctness rather than BPF attachment.
type linkwatchRecorder struct {
	mu       sync.Mutex
	current  map[string]bool // interfaces currently "attached"
	detaches map[string]int  // cumulative Detach call count per interface
}

func (r *linkwatchRecorder) EnsureAttached(_ context.Context, ifName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current[ifName] = true
	return nil
}

func (r *linkwatchRecorder) Detach(_ context.Context, ifName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.current, ifName)
	r.detaches[ifName]++
	return nil
}

func (r *linkwatchRecorder) isAttached(ifName string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current[ifName]
}

func (r *linkwatchRecorder) detachCount(ifName string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.detaches[ifName]
}
