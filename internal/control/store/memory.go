// Package store provides in-memory implementations of the control-plane
// persistence contracts defined in package control.
//
// Memory is the default backend for the CP-1 control plane (MER-53): it holds
// identities and compiled policies, returns immutable snapshots to callers, and
// exposes a coalescing Watch seam that the MER-54 ADS server consumes to drive
// snapshot pushes. Durable backends (etcd, MER-CP-5) implement the same
// control.Store interface.
package store

import (
	"context"
	"sync"

	"github.com/joshuawu/meridian/internal/control"
	"github.com/joshuawu/meridian/pkg/wire"
)

// watchBuffer is the per-subscriber channel depth. A depth of one makes Watch
// coalescing: while a notification is pending, further mutations do not block
// writers and do not queue — the subscriber re-reads current state on wake-up.
const watchBuffer = 1

// Memory is a concurrency-safe, in-memory control.Store. The zero value is not
// usable; construct with NewMemory.
type Memory struct {
	mu         sync.RWMutex
	identities map[wire.IdentityID]wire.Identity
	policies   map[wire.PolicyRuleKey]wire.PolicyRule
	watchers   map[chan control.StoreEvent]struct{}
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{
		identities: make(map[wire.IdentityID]wire.Identity),
		policies:   make(map[wire.PolicyRuleKey]wire.PolicyRule),
		watchers:   make(map[chan control.StoreEvent]struct{}),
	}
}

var _ control.Store = (*Memory)(nil)

// PutIdentity inserts or replaces an identity keyed by its ID.
func (m *Memory) PutIdentity(_ context.Context, identity wire.Identity) error {
	m.mu.Lock()
	m.identities[identity.ID] = identity
	m.mu.Unlock()
	m.notify(control.StoreEvent{Kind: control.StoreEventIdentityChanged})
	return nil
}

// DeleteIdentity removes the identity with the given ID. Deleting an absent ID
// is a no-op (idempotent), but still notifies watchers of a state change.
func (m *Memory) DeleteIdentity(_ context.Context, id wire.IdentityID) error {
	m.mu.Lock()
	delete(m.identities, id)
	m.mu.Unlock()
	m.notify(control.StoreEvent{Kind: control.StoreEventIdentityChanged})
	return nil
}

// ListIdentities returns an immutable snapshot of all identities. wire.Identity
// is a value type, so the returned slice shares no mutable state with the store.
func (m *Memory) ListIdentities(_ context.Context) ([]wire.Identity, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]wire.Identity, 0, len(m.identities))
	for _, identity := range m.identities {
		out = append(out, identity)
	}
	return out, nil
}

// PutPolicy inserts or replaces a compiled policy rule keyed by its key.
func (m *Memory) PutPolicy(_ context.Context, rule wire.PolicyRule) error {
	m.mu.Lock()
	m.policies[rule.Key] = rule
	m.mu.Unlock()
	m.notify(control.StoreEvent{Kind: control.StoreEventPolicyChanged})
	return nil
}

// DeletePolicy removes the policy rule with the given key. Deleting an absent
// key is a no-op (idempotent), but still notifies watchers.
func (m *Memory) DeletePolicy(_ context.Context, key wire.PolicyRuleKey) error {
	m.mu.Lock()
	delete(m.policies, key)
	m.mu.Unlock()
	m.notify(control.StoreEvent{Kind: control.StoreEventPolicyChanged})
	return nil
}

// ListPolicies returns an immutable snapshot of all compiled policy rules.
func (m *Memory) ListPolicies(_ context.Context) ([]wire.PolicyRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]wire.PolicyRule, 0, len(m.policies))
	for _, rule := range m.policies {
		out = append(out, rule)
	}
	return out, nil
}

// Watch registers a subscriber and returns a coalescing notification channel.
// The channel emits a control.StoreEvent after each committed mutation and is
// closed when ctx is done. Slow subscribers may coalesce events (see
// watchBuffer); they never block a writer and never observe a stale view.
func (m *Memory) Watch(ctx context.Context) <-chan control.StoreEvent {
	ch := make(chan control.StoreEvent, watchBuffer)

	m.mu.Lock()
	m.watchers[ch] = struct{}{}
	m.mu.Unlock()

	go func() {
		<-ctx.Done()
		m.mu.Lock()
		if _, ok := m.watchers[ch]; ok {
			delete(m.watchers, ch)
			close(ch)
		}
		m.mu.Unlock()
	}()

	return ch
}

// notify delivers ev to every live subscriber without blocking. Sends are
// non-blocking: if a subscriber's buffer is full, the event is dropped because
// a pending notification already tells it to re-read current state.
func (m *Memory) notify(ev control.StoreEvent) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for ch := range m.watchers {
		select {
		case ch <- ev:
		default:
		}
	}
}
