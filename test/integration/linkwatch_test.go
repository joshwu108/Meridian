//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/internal/agent/attach"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/linkwatch"
	"github.com/joshuawu/meridian/test/harness"
)

// TestVethAttachLifecycleGate_MER71 is the Phase-3 A-2 gate: the RTNLGRP_LINK
// watcher must EnsureAttach on every matching host-side veth within 100 ms of
// creation (reconcile and event paths) and Detach within 100 ms of deletion.
// The gate drives the REAL MER-57 TC attach manager — not a fake — so the
// 100 ms budget covers actual qdisc/filter kernel operations, and the leak
// check verifies real kernel state. Must never t.Skip under root on 5.15.
func TestVethAttachLifecycleGate_MER71(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	const (
		budget = 100 * time.Millisecond
		nPairs = 3
	)

	// Load the real production TC ingress BPF objects. The gate exercises the
	// EnsureAttached → clsact qdisc + direct-action filter kernel path (MER-57).
	pinDir := harness.PinDir(t)
	objs, err := bpfobj.LoadTcIngress(pinDir)
	if err != nil {
		t.Fatalf("load tc_ingress objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })

	progPin := filepath.Join(pinDir, "tc_ingress_prog")
	tcMgr := attach.NewManager(objs.MeridianTcIngress, progPin)

	// att delegates every call to the real MER-57 attach manager (kernel path
	// exercised) while recording call counts so the 100 ms timing assertions
	// can poll an in-process observable without busy-looping tc(8).
	att := &tcAttacher{
		real:     tcMgr,
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
	// has completed Reconcile+Events subscription, which acts as a
	// happens-before barrier for the event-path phase below.
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
		// Kernel-state proof: a direct-action BPF filter must be visible on the
		// ingress hook — EnsureAttached did real work, not just an accounting update.
		if !hasIngressBPFFilter(name) {
			t.Errorf("reconcile: no direct-action BPF filter in kernel on %s after EnsureAttached", name)
		}
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
		if !hasIngressBPFFilter(name) {
			t.Errorf("event: no direct-action BPF filter in kernel on %s after EnsureAttached", name)
		}
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

	// === Kernel-state leak check ===
	// Cancel the watcher and wait for clean exit.
	cancel()
	select {
	case err := <-watchErrCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Logf("watcher stopped with: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("linkwatch goroutine did not stop within 2s (goroutine leak)")
	}

	// All mh-r71* interfaces (test veths) must be absent from the kernel. Link
	// deletion removes all qdiscs and filters; any surviving entry means harness
	// teardown failed or an unintended veth survived with our test prefix.
	out, _ := exec.Command("ip", "link", "show").CombinedOutput()
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, ": mh-r71") {
			t.Errorf("kernel state leak: interface still present after teardown: %s", strings.TrimSpace(line))
		}
	}
}

// hasIngressBPFFilter reports whether a direct-action BPF TC filter is present
// on the ingress hook of ifName. Used to verify EnsureAttached produced real
// kernel state, not just an in-process accounting update.
func hasIngressBPFFilter(ifName string) bool {
	out, err := exec.Command("tc", "filter", "show", "dev", ifName, "ingress").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "direct-action")
}

// tcAttacher wraps the real MER-57 TC attach manager with call-counting. Every
// EnsureAttached and Detach is delegated to the real manager (kernel path
// exercised) and recorded so the gate's 100 ms timing assertions can poll an
// in-process observable instead of re-running tc(8) in a busy loop.
type tcAttacher struct {
	real     *attach.TCManager
	mu       sync.Mutex
	current  map[string]bool
	detaches map[string]int
}

func (a *tcAttacher) EnsureAttached(ctx context.Context, ifName string) error {
	if err := a.real.EnsureAttached(ctx, ifName); err != nil {
		return err
	}
	a.mu.Lock()
	a.current[ifName] = true
	a.mu.Unlock()
	return nil
}

func (a *tcAttacher) Detach(ctx context.Context, ifName string) error {
	if err := a.real.Detach(ctx, ifName); err != nil {
		return err
	}
	a.mu.Lock()
	delete(a.current, ifName)
	a.detaches[ifName]++
	a.mu.Unlock()
	return nil
}

func (a *tcAttacher) isAttached(ifName string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.current[ifName]
}

func (a *tcAttacher) detachCount(ifName string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.detaches[ifName]
}
