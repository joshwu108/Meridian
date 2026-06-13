// Package identitytable defines identity lookup contracts shared in the agent.
package identitytable

import (
	"context"

	"github.com/joshuawu/meridian/pkg/wire"
)

// Resolver resolves workload identity metadata by numeric identity.
type Resolver interface {
	Resolve(context.Context, wire.IdentityID) (wire.Identity, bool, error)
}
