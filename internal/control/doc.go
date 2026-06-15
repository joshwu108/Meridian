// Package control defines control-plane service contracts and package stubs.
//
// P0-002 introduces interface-only scaffolding; protocol and storage
// implementations land in subsequent tickets.
package control

import (
	"context"

	"github.com/joshuawu/meridian/pkg/wire"
)

// StoreEventKind classifies a store mutation for Watch subscribers.
type StoreEventKind int

const (
	// StoreEventIdentityChanged signals an identity put or delete.
	StoreEventIdentityChanged StoreEventKind = iota
	// StoreEventPolicyChanged signals a policy put or delete.
	StoreEventPolicyChanged
)

// StoreEvent is the change notification delivered to Watch subscribers. It
// carries only the kind of change, not the mutated value: subscribers re-read
// the authoritative state from the Store (the MER-54 ADS push re-snapshots on
// any signal), so the seam stays a coalescing wake-up rather than a delta log.
type StoreEvent struct {
	Kind StoreEventKind
}

// Store abstracts control-plane persistence backends (memory, etcd, ...).
//
// Watch returns a channel that emits a StoreEvent after each committed
// mutation and closes when ctx is done. It is a coalescing seam — a slow
// subscriber may observe fewer events than there were mutations, but never a
// stale view, because every event is a prompt to re-read current state. The
// MER-54 ADS server consumes Watch to drive snapshot pushes.
type Store interface {
	PutIdentity(context.Context, wire.Identity) error
	DeleteIdentity(context.Context, wire.IdentityID) error
	ListIdentities(context.Context) ([]wire.Identity, error)
	PutPolicy(context.Context, wire.PolicyRule) error
	DeletePolicy(context.Context, wire.PolicyRuleKey) error
	ListPolicies(context.Context) ([]wire.PolicyRule, error)
	Watch(context.Context) <-chan StoreEvent
}

// Compiler compiles declarative policy into datapath-ready rules.
type Compiler interface {
	Compile(context.Context) ([]wire.PolicyRule, error)
}

// SnapshotPublisher publishes compiled snapshots to agents.
type SnapshotPublisher interface {
	Publish(context.Context, wire.PolicySnapshot) error
}
