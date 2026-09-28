// Package proxyfeed implements atomic-snapshot delivery of compiled L4 policy
// from the ADS client to the node proxy. The proxy reads the latest snapshot
// via Current() on every new connection; the ADS client calls Publish on each
// ACKed update. No locking is needed in the hot path: the snapshot pointer is
// atomically swapped (no torn reads).
package proxyfeed

import (
	"context"
	"sync/atomic"

	"github.com/joshuawu/meridian/pkg/wire"
)

// Feed is a concurrency-safe publisher/subscriber pair for ProxyPolicySnapshot.
// Publish atomically replaces the snapshot; Current returns the latest version.
// It implements both Publisher (for the ADS client) and PolicySource (for the
// node proxy).
type Feed struct {
	ptr atomic.Pointer[wire.ProxyPolicySnapshot]
}

// NewFeed returns an empty Feed. Current() returns a zero-value snapshot until
// the first Publish call.
func NewFeed() *Feed {
	return &Feed{}
}

// Publish atomically replaces the current snapshot.
func (f *Feed) Publish(_ context.Context, snap wire.ProxyPolicySnapshot) error {
	f.ptr.Store(&snap)
	return nil
}

// Current returns the latest published snapshot, or a zero-value snapshot
// before the first Publish.
func (f *Feed) Current(_ context.Context) (wire.ProxyPolicySnapshot, error) {
	p := f.ptr.Load()
	if p == nil {
		return wire.ProxyPolicySnapshot{}, nil
	}
	return *p, nil
}
