// Package proxyfeed defines how agent policy state is pushed to the node proxy.
package proxyfeed

import (
	"context"

	"github.com/joshuawu/meridian/pkg/wire"
)

// Publisher publishes policy snapshots consumable by the node proxy.
type Publisher interface {
	Publish(context.Context, wire.ProxyPolicySnapshot) error
}
