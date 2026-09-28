package proxy

import (
	"fmt"
	"sync"
	"testing"

	"github.com/joshuawu/meridian/pkg/wire"
)

func TestMapSpiffeIDResolverEmpty(t *testing.T) {
	r := NewMapSpiffeIDResolver()

	if id, ok := r.ResolveSpiffeID("spiffe://cluster.local/ns/a/sa/b"); ok {
		t.Fatalf("empty resolver resolved to %d, want miss", id)
	}
	if uri, ok := r.LookupID(wire.IdentityID(1)); ok {
		t.Fatalf("empty resolver looked up %q, want miss", uri)
	}
}

func TestMapSpiffeIDResolverUpdateAndLookup(t *testing.T) {
	r := NewMapSpiffeIDResolver()
	r.Update([]wire.Identity{
		{ID: 10, SpiffeID: "spiffe://cluster.local/ns/a/sa/web"},
		{ID: 20, SpiffeID: "spiffe://cluster.local/ns/b/sa/api"},
		{ID: 30, SpiffeID: ""}, // no URI — must not be indexed
	})

	// Forward: URI → ID.
	if id, ok := r.ResolveSpiffeID("spiffe://cluster.local/ns/a/sa/web"); !ok || id != 10 {
		t.Fatalf("ResolveSpiffeID = (%d, %v), want (10, true)", id, ok)
	}

	// Reverse: ID → URI.
	if uri, ok := r.LookupID(20); !ok || uri != "spiffe://cluster.local/ns/b/sa/api" {
		t.Fatalf("LookupID(20) = (%q, %v), want (spiffe://cluster.local/ns/b/sa/api, true)", uri, ok)
	}
	if _, ok := r.LookupID(30); ok {
		t.Fatal("LookupID(30) hit for identity with empty SpiffeID, want miss")
	}
	if _, ok := r.LookupID(99); ok {
		t.Fatal("LookupID(99) hit for unknown identity, want miss")
	}
}

func TestMapSpiffeIDResolverUpdateReplaces(t *testing.T) {
	r := NewMapSpiffeIDResolver()
	r.Update([]wire.Identity{{ID: 1, SpiffeID: "spiffe://cluster.local/ns/old/sa/gone"}})
	r.Update([]wire.Identity{{ID: 2, SpiffeID: "spiffe://cluster.local/ns/new/sa/here"}})

	if _, ok := r.ResolveSpiffeID("spiffe://cluster.local/ns/old/sa/gone"); ok {
		t.Fatal("stale URI survived Update, want full replacement")
	}
	if _, ok := r.LookupID(1); ok {
		t.Fatal("stale ID survived Update, want full replacement")
	}
	if uri, ok := r.LookupID(2); !ok || uri != "spiffe://cluster.local/ns/new/sa/here" {
		t.Fatalf("LookupID(2) = (%q, %v) after replace", uri, ok)
	}
}

// TestMapSpiffeIDResolverConcurrent exercises Update racing readers under -race.
func TestMapSpiffeIDResolverConcurrent(t *testing.T) {
	r := NewMapSpiffeIDResolver()
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(2)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				r.Update([]wire.Identity{{
					ID:       wire.IdentityID(n),
					SpiffeID: fmt.Sprintf("spiffe://cluster.local/ns/x/sa/%d", n),
				}})
			}
		}(g)
		go func(n int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				r.LookupID(wire.IdentityID(n))
				r.ResolveSpiffeID("spiffe://cluster.local/ns/x/sa/0")
			}
		}(g)
	}
	wg.Wait()
}
