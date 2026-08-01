package linkwatch

import (
	"context"
	"fmt"
)

// Attacher installs or removes the TC datapath on a single interface. It is the
// narrow seam the lifecycle loop drives; the production implementation is
// internal/agent/attach.TCManager (EnsureAttached / Detach). Keeping it an
// interface here lets the reconcile/dispatch logic be unit-tested without
// netlink or root.
type Attacher interface {
	EnsureAttached(ctx context.Context, ifName string) error
	Detach(ctx context.Context, ifName string) error
}

// AttachErrorFunc receives a per-interface attach/detach failure. The lifecycle
// loop reports the error and continues — a single interface failing must not tear
// down the whole watcher (state, not events, is truth: a missed attach is
// re-attempted on the next reconcile). op is "attach" or "detach".
type AttachErrorFunc func(op, ifName string, err error)

// Run drives the veth attach lifecycle. It performs a FULL interface reconcile —
// attaching every interface present now — BEFORE consuming the event stream, so
// links that appeared while the agent was down are not missed (ARCHITECTURE
// lifecycle: INTERFACE_RECONCILE before subscribe). It then attaches on
// EventAdded and detaches on EventRemoved until ctx is cancelled or the event
// channel closes. Attach/detach are assumed idempotent (TCManager is), so an
// add observed by both the reconcile and a racing event is harmless.
//
// onErr, if non-nil, receives per-interface attach/detach failures; the loop
// continues. A failure to reconcile or subscribe is fatal and returned.
func Run(ctx context.Context, w Watcher, a Attacher, onErr AttachErrorFunc) error {
	report := func(op, ifName string, err error) {
		if err != nil && onErr != nil {
			onErr(op, ifName, err)
		}
	}

	ifaces, err := w.Reconcile(ctx)
	if err != nil {
		return fmt.Errorf("linkwatch: initial reconcile: %w", err)
	}
	for _, ifName := range ifaces {
		report("attach", ifName, a.EnsureAttached(ctx, ifName))
	}

	events, err := w.Events(ctx)
	if err != nil {
		return fmt.Errorf("linkwatch: subscribe: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			switch ev.Type {
			case EventAdded:
				report("attach", ev.IfName, a.EnsureAttached(ctx, ev.IfName))
			case EventRemoved:
				report("detach", ev.IfName, a.Detach(ctx, ev.IfName))
			}
		}
	}
}
