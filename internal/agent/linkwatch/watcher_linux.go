//go:build linux

package linkwatch

import (
	"context"
	"fmt"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// vethKind is the rtnetlink link-kind string for a veth device. RTM_NEWLINK
// carries it reliably; RTM_DELLINK may omit the kind, so removals match on name
// alone (the orchestrator gates Detach by what it actually attached, so a
// non-veth that merely shares the prefix is never torn down spuriously).
const vethKind = "veth"

// updateBuffer sizes the channel the netlink library fills from the kernel
// socket. A burst of pod churn must not block the reader; on genuine overflow
// the kernel raises ENOBUFS, the library closes its channel, and the
// orchestrator re-reconciles (state, not events, is truth).
const updateBuffer = 64

// Selector decides whether an interface name belongs to the set of host-side
// pod veths the agent manages. Production passes a prefix matcher (the CNI's
// host-veth naming); the A-2 gate passes the harness prefix.
type Selector func(ifName string) bool

// PrefixSelector matches interface names beginning with prefix. An empty prefix
// matches nothing, so a misconfigured agent manages no interfaces rather than
// attaching to every link on the host (fail-closed).
func PrefixSelector(prefix string) Selector {
	return func(ifName string) bool {
		return prefix != "" && strings.HasPrefix(ifName, prefix)
	}
}

// NetlinkWatcher implements Watcher over the host's RTNLGRP_LINK multicast
// group. It is the only netlink-touching type in the package; the orchestrator
// (run.go) is platform-neutral and unit-tested with fakes.
type NetlinkWatcher struct {
	sel  Selector
	logf func(string, ...any)
}

var _ Watcher = (*NetlinkWatcher)(nil)

// WatcherOption configures a NetlinkWatcher.
type WatcherOption func(*NetlinkWatcher)

// WithWatcherLogf sets a log sink for non-fatal subscribe/decode errors.
func WithWatcherLogf(f func(string, ...any)) WatcherOption {
	return func(w *NetlinkWatcher) {
		if f != nil {
			w.logf = f
		}
	}
}

// NewNetlinkWatcher builds a Watcher reporting veths whose name satisfies sel.
// A nil selector matches nothing (fail-closed).
func NewNetlinkWatcher(sel Selector, opts ...WatcherOption) *NetlinkWatcher {
	if sel == nil {
		sel = func(string) bool { return false }
	}
	w := &NetlinkWatcher{sel: sel, logf: func(string, ...any) {}}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Reconcile lists every link and returns the host-side veths the selector
// accepts. This is the authoritative snapshot the orchestrator attaches before
// each (re)subscribe.
func (w *NetlinkWatcher) Reconcile(_ context.Context) ([]string, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("linkwatch: list links: %w", err)
	}
	var names []string
	for _, link := range links {
		name := link.Attrs().Name
		if link.Type() == vethKind && w.sel(name) {
			names = append(names, name)
		}
	}
	return names, nil
}

// Events subscribes to RTNLGRP_LINK and returns a channel of selector-matching
// add/remove events. The channel closes when ctx is cancelled (clean shutdown)
// or when the kernel stream resets (ENOBUFS overflow). The subscription socket
// is always torn down via the done channel, so no goroutine or fd leaks across
// resubscribes.
func (w *NetlinkWatcher) Events(ctx context.Context) (<-chan Event, error) {
	updates := make(chan netlink.LinkUpdate, updateBuffer)
	done := make(chan struct{})
	if err := netlink.LinkSubscribeWithOptions(updates, done, netlink.LinkSubscribeOptions{
		ErrorCallback: func(err error) { w.logf("linkwatch: link subscription: %v", err) },
	}); err != nil {
		close(done)
		return nil, fmt.Errorf("linkwatch: subscribe RTNLGRP_LINK: %w", err)
	}

	out := make(chan Event)
	go func() {
		defer close(out)
		defer close(done) // tears down the netlink socket on every exit path
		for {
			select {
			case <-ctx.Done():
				return
			case u, ok := <-updates:
				if !ok {
					return // ENOBUFS/close: orchestrator re-reconciles + resubscribes
				}
				ev, matched := w.classify(u)
				if !matched {
					continue
				}
				select {
				case out <- ev:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// classify maps a netlink link update to a managed Event, or reports no match.
// New links must be veths AND selector-accepted; deletions match on name alone
// because RTM_DELLINK may not carry the link kind.
func (w *NetlinkWatcher) classify(u netlink.LinkUpdate) (Event, bool) {
	name := u.Link.Attrs().Name
	if !w.sel(name) {
		return Event{}, false
	}
	switch u.Header.Type {
	case unix.RTM_NEWLINK:
		if u.Link.Type() != vethKind {
			return Event{}, false
		}
		return Event{IfName: name, Type: EventAdded}, true
	case unix.RTM_DELLINK:
		return Event{IfName: name, Type: EventRemoved}, true
	default:
		return Event{}, false
	}
}
