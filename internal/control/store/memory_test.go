package store

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/joshuawu/meridian/internal/control"
	"github.com/joshuawu/meridian/pkg/wire"
)

func sampleIdentity(id wire.IdentityID, name string) wire.Identity {
	return wire.Identity{ID: id, Name: name, SpiffeID: "spiffe://example/" + name}
}

func samplePolicy(src, dst wire.IdentityID, port uint16) wire.PolicyRule {
	return wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: src,
			DstIdentity: dst,
			DstPort:     port,
			Protocol:    6,
			Direction:   wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	}
}

func TestIdentityCRUDRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	id := sampleIdentity(1, "svc-a")
	if err := m.PutIdentity(ctx, id); err != nil {
		t.Fatalf("PutIdentity error: %v", err)
	}

	got, err := m.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities error: %v", err)
	}
	if len(got) != 1 || got[0] != id {
		t.Fatalf("ListIdentities = %+v, want [%+v]", got, id)
	}

	if err := m.DeleteIdentity(ctx, id.ID); err != nil {
		t.Fatalf("DeleteIdentity error: %v", err)
	}
	got, err = m.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListIdentities after delete = %+v, want empty", got)
	}
}

func TestPolicyCRUDRoundTrip(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	rule := samplePolicy(1, 2, 8080)
	if err := m.PutPolicy(ctx, rule); err != nil {
		t.Fatalf("PutPolicy error: %v", err)
	}

	got, err := m.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies error: %v", err)
	}
	if len(got) != 1 || got[0] != rule {
		t.Fatalf("ListPolicies = %+v, want [%+v]", got, rule)
	}

	if err := m.DeletePolicy(ctx, rule.Key); err != nil {
		t.Fatalf("DeletePolicy error: %v", err)
	}
	got, err = m.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListPolicies after delete = %+v, want empty", got)
	}
}

func TestPutReplacesByKey(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	if err := m.PutIdentity(ctx, sampleIdentity(1, "old")); err != nil {
		t.Fatalf("PutIdentity error: %v", err)
	}
	if err := m.PutIdentity(ctx, sampleIdentity(1, "new")); err != nil {
		t.Fatalf("PutIdentity (replace) error: %v", err)
	}
	got, err := m.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities error: %v", err)
	}
	if len(got) != 1 || got[0].Name != "new" {
		t.Fatalf("replace by ID failed: got %+v", got)
	}
}

// TestListReturnsImmutableSnapshot proves callers cannot mutate stored state by
// writing into a returned slice.
func TestListReturnsImmutableSnapshot(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	if err := m.PutIdentity(ctx, sampleIdentity(1, "svc-a")); err != nil {
		t.Fatalf("PutIdentity error: %v", err)
	}

	snap, err := m.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities error: %v", err)
	}
	snap[0].Name = "mutated"

	again, err := m.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities error: %v", err)
	}
	if again[0].Name != "svc-a" {
		t.Fatalf("store mutated through returned slice: got %q", again[0].Name)
	}
}

func TestWatchReceivesMutationEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMemory()

	ch := m.Watch(ctx)

	tests := []struct {
		name     string
		mutate   func() error
		wantKind control.StoreEventKind
	}{
		{
			name:     "identity put",
			mutate:   func() error { return m.PutIdentity(ctx, sampleIdentity(1, "svc-a")) },
			wantKind: control.StoreEventIdentityChanged,
		},
		{
			name:     "policy put",
			mutate:   func() error { return m.PutPolicy(ctx, samplePolicy(1, 2, 80)) },
			wantKind: control.StoreEventPolicyChanged,
		},
		{
			name:     "identity delete",
			mutate:   func() error { return m.DeleteIdentity(ctx, 1) },
			wantKind: control.StoreEventIdentityChanged,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.mutate(); err != nil {
				t.Fatalf("mutate error: %v", err)
			}
			select {
			case ev := <-ch:
				if ev.Kind != tc.wantKind {
					t.Fatalf("event kind = %d, want %d", ev.Kind, tc.wantKind)
				}
			case <-time.After(time.Second):
				t.Fatalf("no Watch event within timeout")
			}
		})
	}
}

func TestWatchClosesOnContextDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m := NewMemory()
	ch := m.Watch(ctx)

	cancel()

	select {
	case _, open := <-ch:
		// Drain a possibly-buffered event, then require closure.
		if open {
			select {
			case _, open2 := <-ch:
				if open2 {
					t.Fatalf("Watch channel still open after ctx cancel")
				}
			case <-time.After(time.Second):
				t.Fatalf("Watch channel not closed after ctx cancel")
			}
		}
	case <-time.After(time.Second):
		t.Fatalf("Watch channel not closed after ctx cancel")
	}
}

// TestConcurrentMutationsAndReads exercises the store under -race.
func TestConcurrentMutationsAndReads(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = m.PutIdentity(ctx, sampleIdentity(wire.IdentityID(i+1), "svc"))
			_ = m.PutPolicy(ctx, samplePolicy(wire.IdentityID(i+1), 99, uint16(i+1)))
			_, _ = m.ListIdentities(ctx)
			_, _ = m.ListPolicies(ctx)
		}(i)
	}
	wg.Wait()

	ids, err := m.ListIdentities(ctx)
	if err != nil {
		t.Fatalf("ListIdentities error: %v", err)
	}
	if len(ids) != 50 {
		t.Fatalf("identities = %d, want 50", len(ids))
	}
}

// TestWatchDoesNotBlockWriters proves a never-drained subscriber cannot wedge
// the store: many mutations complete despite the buffer being full.
func TestWatchDoesNotBlockWriters(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := NewMemory()
	_ = m.Watch(ctx) // subscribe but never read

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			_ = m.PutPolicy(ctx, samplePolicy(1, 2, uint16(i%65535+1)))
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("writer blocked on a full Watch buffer")
	}
}
