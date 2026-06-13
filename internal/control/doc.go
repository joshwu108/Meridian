// Package control defines control-plane service contracts and package stubs.
//
// P0-002 introduces interface-only scaffolding; protocol and storage
// implementations land in subsequent tickets.
package control

import (
	"context"

	"github.com/joshuawu/meridian/pkg/wire"
)

// Store abstracts control-plane persistence backends (memory, etcd, ...).
type Store interface {
	PutIdentity(context.Context, wire.Identity) error
	DeleteIdentity(context.Context, wire.IdentityID) error
	ListIdentities(context.Context) ([]wire.Identity, error)
	PutPolicy(context.Context, wire.PolicyRule) error
	DeletePolicy(context.Context, wire.PolicyRuleKey) error
	ListPolicies(context.Context) ([]wire.PolicyRule, error)
}

// Compiler compiles declarative policy into datapath-ready rules.
type Compiler interface {
	Compile(context.Context) ([]wire.PolicyRule, error)
}

// SnapshotPublisher publishes compiled snapshots to agents.
type SnapshotPublisher interface {
	Publish(context.Context, wire.PolicySnapshot) error
}
