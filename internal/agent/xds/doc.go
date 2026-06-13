// Package xds defines control-plane stream and apply contracts for the agent.
package xds

import (
	"context"

	"github.com/joshuawu/meridian/pkg/wire"
)

// Client receives latest desired policy snapshots for this node.
type Client interface {
	Recv(context.Context) (wire.PolicySnapshot, error)
	Ack(context.Context, wire.PolicySnapshotVersion) error
	Nack(context.Context, wire.PolicySnapshotVersion, string) error
}

// Applier validates and applies one snapshot atomically.
type Applier interface {
	Apply(context.Context, wire.PolicySnapshot) error
}
