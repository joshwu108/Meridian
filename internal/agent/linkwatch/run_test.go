package linkwatch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeAttacher records EnsureAttached/Detach calls in order and can be primed to
// fail for a given interface.
type fakeAttacher struct {
	mu     sync.Mutex
	calls  []string // e.g. "attach:vethA", "detach:vethA"
	failOn map[string]error
}

func (f *fakeAttacher) EnsureAttached(_ context.Context, ifName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "attach:"+ifName)
	return f.failOn["attach:"+ifName]
}

func (f *fakeAttacher) Detach(_ context.Context, ifName string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "detach:"+ifName)
	return f.failOn["detach:"+ifName]
}

func (f *fakeAttacher) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// fakeWatcher returns a fixed reconcile set and replays a scripted event stream.
type fakeWatcher struct {
	reconcile    []string
	reconcileErr error
	events       chan Event
	eventsErr    error
}

func (w *fakeWatcher) Reconcile(context.Context) ([]string, error) {
	return w.reconcile, w.reconcileErr
}

func (w *fakeWatcher) Events(context.Context) (<-chan Event, error) {
	return w.events, w.eventsErr
}

func TestRunReconcilesBeforeEventsThenDispatches(t *testing.T) {
	att := &fakeAttacher{failOn: map[string]error{}}
	events := make(chan Event, 4)
	w := &fakeWatcher{reconcile: []string{"vethA", "vethB"}, events: events}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, w, att, nil) }()

	// Drive events: a new veth appears, then one is removed.
	events <- Event{IfName: "vethC", Type: EventAdded}
	events <- Event{IfName: "vethA", Type: EventRemoved}

	// Wait until all four operations are observed.
	deadline := time.Now().Add(2 * time.Second)
	for len(att.snapshot()) < 4 && !time.Now().After(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run returned %v, want context.Canceled", err)
	}

	got := att.snapshot()
	// The two reconcile attaches MUST precede the event-driven ops.
	if len(got) < 4 {
		t.Fatalf("got %v, want >=4 ops", got)
	}
	if got[0] != "attach:vethA" || got[1] != "attach:vethB" {
		t.Fatalf("reconcile must attach existing ifaces first; got %v", got)
	}
	if got[2] != "attach:vethC" || got[3] != "detach:vethA" {
		t.Fatalf("event dispatch wrong; got %v", got)
	}
}

func TestRunReportsPerInterfaceErrorsAndContinues(t *testing.T) {
	att := &fakeAttacher{failOn: map[string]error{"attach:vethA": errors.New("boom")}}
	events := make(chan Event, 1)
	w := &fakeWatcher{reconcile: []string{"vethA"}, events: events}

	var mu sync.Mutex
	var reported []string
	onErr := func(op, ifName string, err error) {
		mu.Lock()
		reported = append(reported, op+":"+ifName)
		mu.Unlock()
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, w, att, onErr) }()

	// A subsequent good event must still be dispatched (loop did not abort).
	events <- Event{IfName: "vethB", Type: EventAdded}
	deadline := time.Now().Add(2 * time.Second)
	for len(att.snapshot()) < 2 && !time.Now().After(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 1 || reported[0] != "attach:vethA" {
		t.Fatalf("expected the failed attach reported (not swallowed); got %v", reported)
	}
	if got := att.snapshot(); len(got) < 2 || got[1] != "attach:vethB" {
		t.Fatalf("loop must continue after a per-iface error; got %v", got)
	}
}

func TestRunFatalOnReconcileError(t *testing.T) {
	w := &fakeWatcher{reconcileErr: errors.New("netlink down")}
	err := Run(context.Background(), w, &fakeAttacher{failOn: map[string]error{}}, nil)
	if err == nil {
		t.Fatalf("reconcile failure must be fatal")
	}
}

func TestRunStopsWhenEventChannelCloses(t *testing.T) {
	events := make(chan Event)
	w := &fakeWatcher{reconcile: nil, events: events}
	done := make(chan error, 1)
	go func() { done <- Run(context.Background(), w, &fakeAttacher{failOn: map[string]error{}}, nil) }()
	close(events)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("clean channel close should return nil, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Run did not return on event channel close")
	}
}
