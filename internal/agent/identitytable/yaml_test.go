package identitytable

import (
	"context"
	"sync"
	"testing"

	"github.com/joshuawu/meridian/pkg/wire"
)

func TestYAMLResolverResolveHitAndMiss(t *testing.T) {
	resolver := NewYAMLResolver([]wire.Identity{
		{
			ID:       101,
			SpiffeID: "spiffe://cluster.local/ns/default/sa/frontend",
			Name:     "frontend",
		},
	})

	got, ok, err := resolver.Resolve(context.Background(), 101)
	if err != nil {
		t.Fatalf("resolve hit returned error: %v", err)
	}
	if !ok {
		t.Fatal("resolve hit reported miss")
	}
	if got.SpiffeID != "spiffe://cluster.local/ns/default/sa/frontend" {
		t.Fatalf("hit SpiffeID = %q", got.SpiffeID)
	}

	zero, ok, err := resolver.Resolve(context.Background(), 999)
	if err != nil {
		t.Fatalf("resolve miss returned error: %v", err)
	}
	if ok {
		t.Fatal("resolve miss reported hit")
	}
	if zero != (wire.Identity{}) {
		t.Fatalf("resolve miss returned non-zero identity: %#v", zero)
	}
}

func TestYAMLResolverImmutableAfterConstruction(t *testing.T) {
	source := []wire.Identity{
		{
			ID:       7,
			SpiffeID: "spiffe://cluster.local/ns/default/sa/a",
		},
	}
	resolver := NewYAMLResolver(source)

	// Mutating the source slice after construction must not affect resolver data.
	source[0].SpiffeID = "spiffe://cluster.local/ns/default/sa/mutated"

	got, ok, err := resolver.Resolve(context.Background(), 7)
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if !ok {
		t.Fatal("expected resolve hit")
	}
	if got.SpiffeID != "spiffe://cluster.local/ns/default/sa/a" {
		t.Fatalf("resolver observed post-construction mutation: %q", got.SpiffeID)
	}
}

func TestYAMLResolverConcurrentResolve(t *testing.T) {
	resolver := NewYAMLResolver([]wire.Identity{
		{ID: 1, SpiffeID: "spiffe://cluster.local/ns/default/sa/one"},
		{ID: 2, SpiffeID: "spiffe://cluster.local/ns/default/sa/two"},
	})

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				if _, _, err := resolver.Resolve(context.Background(), 1); err != nil {
					t.Errorf("resolve(1): %v", err)
					return
				}
				if _, _, err := resolver.Resolve(context.Background(), 999); err != nil {
					t.Errorf("resolve(999): %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}
