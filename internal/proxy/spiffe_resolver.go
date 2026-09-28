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

// SpiffeIDLookup is the reverse resolver: it maps a numeric identity to its
// SPIFFE URI. The outbound handler uses this to cross-check the mTLS peer
// certificate against the expected dst_identity (shortcoming #5).
type SpiffeIDLookup interface {
	LookupID(id wire.IdentityID) (string, bool)
}

// MapSpiffeIDResolver implements SpiffeIDResolver and SpiffeIDLookup backed by
// in-memory maps populated from the identity table (wire.Identity slice). It
// is refreshed atomically when the ADS snapshot is applied.
type MapSpiffeIDResolver struct {
	mu    sync.RWMutex
	byURI map[string]wire.IdentityID // spiffe URI → numeric ID
	byID  map[wire.IdentityID]string // numeric ID → spiffe URI
}

// NewMapSpiffeIDResolver returns an empty resolver. Call Update to populate it.
func NewMapSpiffeIDResolver() *MapSpiffeIDResolver {
	return &MapSpiffeIDResolver{
		byURI: make(map[string]wire.IdentityID),
		byID:  make(map[wire.IdentityID]string),
	}
}

// Update atomically replaces the internal maps with the identities in snap.
// Called each time the ADS snapshot is applied.
func (r *MapSpiffeIDResolver) Update(identities []wire.Identity) {
	byURI := make(map[string]wire.IdentityID, len(identities))
	byID := make(map[wire.IdentityID]string, len(identities))
	for _, id := range identities {
		if id.SpiffeID != "" {
			byURI[id.SpiffeID] = id.ID
			byID[id.ID] = id.SpiffeID
		}
	}
	r.mu.Lock()
	r.byURI = byURI
	r.byID = byID
	r.mu.Unlock()
}

// LookupID returns the SPIFFE URI for the numeric identity id, or ("", false)
// if the identity is unknown or carries no URI.
func (r *MapSpiffeIDResolver) LookupID(id wire.IdentityID) (string, bool) {
	r.mu.RLock()
	uri, ok := r.byID[id]
	r.mu.RUnlock()
	return uri, ok
}

// ResolveSpiffeID returns the numeric identity ID for spiffeID, or
// (wire.IdentityUnknown, false) if not found.
func (r *MapSpiffeIDResolver) ResolveSpiffeID(spiffeID string) (wire.IdentityID, bool) {
	r.mu.RLock()
	id, ok := r.byURI[spiffeID]
	r.mu.RUnlock()
	return id, ok
}
