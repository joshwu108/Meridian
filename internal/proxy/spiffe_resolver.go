package proxy

import (
	"sync"

	"github.com/joshuawu/meridian/pkg/wire"
)

// SpiffeIDResolver resolves a SPIFFE URI to a numeric wire.IdentityID for use
// in L4 authz evaluation. The proxy uses this to look up src_identity from the
// mTLS peer cert's SPIFFE URI (shortcoming #3 / ADR-0006 D-D note).
type SpiffeIDResolver interface {
	ResolveSpiffeID(spiffeID string) (wire.IdentityID, bool)
}

// MapSpiffeIDResolver implements SpiffeIDResolver backed by an in-memory map
// populated from the identity table (wire.Identity slice). It is refreshed
// atomically when the ADS snapshot is applied.
type MapSpiffeIDResolver struct {
	mu      sync.RWMutex
	byURI   map[string]wire.IdentityID // spiffe URI → numeric ID
}

// NewMapSpiffeIDResolver returns an empty resolver. Call Update to populate it.
func NewMapSpiffeIDResolver() *MapSpiffeIDResolver {
	return &MapSpiffeIDResolver{byURI: make(map[string]wire.IdentityID)}
}

// Update atomically replaces the internal map with the identities in snap.
// Called each time the ADS snapshot is applied.
func (r *MapSpiffeIDResolver) Update(identities []wire.Identity) {
	m := make(map[string]wire.IdentityID, len(identities))
	for _, id := range identities {
		if id.SpiffeID != "" {
			m[id.SpiffeID] = id.ID
		}
	}
	r.mu.Lock()
	r.byURI = m
	r.mu.Unlock()
}

// ResolveSpiffeID returns the numeric identity ID for spiffeID, or
// (wire.IdentityUnknown, false) if not found.
func (r *MapSpiffeIDResolver) ResolveSpiffeID(spiffeID string) (wire.IdentityID, bool) {
	r.mu.RLock()
	id, ok := r.byURI[spiffeID]
	r.mu.RUnlock()
	return id, ok
}
