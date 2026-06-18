// Package identity implements the control plane's monotonic allocator for the
// cluster-global uint32 workload identity space (CC-3).
//
// The control plane is the SOLE allocator of identity IDs: they are allocated
// strictly monotonically, never reused within a single process lifetime, and
// ID 0 (wire.IdentityUnknown) is reserved and never handed out. Releasing a
// name frees the name→ID mapping but never the numeric ID, so a later
// allocation of the same name receives a fresh, higher ID.
package identity

import (
	"fmt"
	"sync"

	"github.com/joshuawu/meridian/pkg/wire"
)

// firstID is the first allocatable identity. ID 0 is reserved for "unknown"
// (wire.IdentityUnknown) and is never allocated.
const firstID wire.IdentityID = 1

// Registry allocates and tracks monotonic workload identities. The zero value
// is not usable; construct with NewRegistry. All methods are safe for
// concurrent use.
type Registry struct {
	mu     sync.Mutex
	next   wire.IdentityID
	byName map[string]wire.IdentityID
	byID   map[wire.IdentityID]string
}

// NewRegistry returns an empty Registry whose first allocation yields ID 1.
func NewRegistry() *Registry {
	return &Registry{
		next:   firstID,
		byName: make(map[string]wire.IdentityID),
		byID:   make(map[wire.IdentityID]string),
	}
}

// Allocate returns the identity ID for name, assigning a new monotonic ID the
// first time a name is seen. Re-allocating an already-known name returns its
// existing ID (allocation is idempotent and the name↔ID binding is stable).
// The empty name is rejected; ID 0 is never returned.
func (r *Registry) Allocate(name string) (wire.IdentityID, error) {
	if name == "" {
		return wire.IdentityUnknown, fmt.Errorf("identity: cannot allocate an ID for an empty name")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if id, ok := r.byName[name]; ok {
		return id, nil
	}

	id := r.next
	r.next++ // monotonic: never decremented, even across Release.
	r.byName[name] = id
	r.byID[id] = name
	return id, nil
}

// LookupByName returns the ID currently bound to name, if any.
func (r *Registry) LookupByName(name string) (wire.IdentityID, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, ok := r.byName[name]
	return id, ok
}

// LookupByID returns the name currently bound to id, if any.
func (r *Registry) LookupByID(id wire.IdentityID) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name, ok := r.byID[id]
	return name, ok
}

// Release removes the name↔ID binding for name. The numeric ID is NOT returned
// to the pool — a subsequent Allocate(name) receives a fresh, higher ID (CC-3:
// never reused within a process lifetime). Releasing an unknown name is a no-op.
func (r *Registry) Release(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id, ok := r.byName[name]; ok {
		delete(r.byName, name)
		delete(r.byID, id)
	}
}
