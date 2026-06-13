package identitytable

import (
	"context"

	"github.com/joshuawu/meridian/pkg/wire"
)

// YAMLResolver resolves identities loaded from the agent stub YAML set.
//
// It is immutable after construction: all entries are copied into an internal
// map and never mutated, so concurrent Resolve calls are safe.
type YAMLResolver struct {
	byID map[wire.IdentityID]wire.Identity
}

// NewYAMLResolver builds an immutable resolver from parsed identities.
func NewYAMLResolver(identities []wire.Identity) *YAMLResolver {
	byID := make(map[wire.IdentityID]wire.Identity, len(identities))
	for _, identity := range identities {
		byID[identity.ID] = identity
	}
	return &YAMLResolver{byID: byID}
}

// Resolve returns (identity, true, nil) on hit and (zero, false, nil) on miss.
func (r *YAMLResolver) Resolve(_ context.Context, id wire.IdentityID) (wire.Identity, bool, error) {
	if r == nil {
		return wire.Identity{}, false, nil
	}
	identity, ok := r.byID[id]
	if !ok {
		return wire.Identity{}, false, nil
	}
	return identity, true, nil
}
