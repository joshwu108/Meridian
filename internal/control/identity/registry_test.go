package identity

import (
	"strconv"
	"sync"
	"testing"

	"github.com/joshuawu/meridian/pkg/wire"
)

func TestAllocateIsMonotonicAndStartsAtOne(t *testing.T) {
	r := NewRegistry()

	tests := []struct {
		name   string
		wantID wire.IdentityID
	}{
		{"svc-a", 1},
		{"svc-b", 2},
		{"svc-c", 3},
	}
	for _, tc := range tests {
		got, err := r.Allocate(tc.name)
		if err != nil {
			t.Fatalf("Allocate(%q) error: %v", tc.name, err)
		}
		if got != tc.wantID {
			t.Fatalf("Allocate(%q) = %d, want %d", tc.name, got, tc.wantID)
		}
	}
}

func TestAllocateIsIdempotentPerName(t *testing.T) {
	r := NewRegistry()

	first, err := r.Allocate("svc-a")
	if err != nil {
		t.Fatalf("first Allocate error: %v", err)
	}
	// Interleave another allocation so a non-stable impl would drift.
	if _, err := r.Allocate("svc-b"); err != nil {
		t.Fatalf("Allocate(svc-b) error: %v", err)
	}
	again, err := r.Allocate("svc-a")
	if err != nil {
		t.Fatalf("second Allocate error: %v", err)
	}
	if first != again {
		t.Fatalf("Allocate(svc-a) not stable: first=%d again=%d", first, again)
	}
}

func TestAllocateNeverReturnsZero(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 100; i++ {
		id, err := r.Allocate(string(rune('a'+i%26)) + string(rune('0'+i/26)))
		if err != nil {
			t.Fatalf("Allocate error: %v", err)
		}
		if id == wire.IdentityUnknown {
			t.Fatalf("Allocate handed out reserved ID 0")
		}
	}
}

func TestAllocateRejectsEmptyName(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Allocate(""); err == nil {
		t.Fatalf("Allocate(\"\") = nil error, want rejection")
	}
}

func TestReleaseDoesNotReuseID(t *testing.T) {
	r := NewRegistry()

	first, err := r.Allocate("svc-a")
	if err != nil {
		t.Fatalf("Allocate error: %v", err)
	}
	r.Release("svc-a")
	if _, ok := r.LookupByName("svc-a"); ok {
		t.Fatalf("LookupByName(svc-a) still resolves after Release")
	}

	reallocated, err := r.Allocate("svc-a")
	if err != nil {
		t.Fatalf("re-Allocate error: %v", err)
	}
	if reallocated <= first {
		t.Fatalf("ID reused/decremented after Release: first=%d reallocated=%d (CC-3 violation)", first, reallocated)
	}
}

func TestLookupRoundTrips(t *testing.T) {
	r := NewRegistry()
	id, err := r.Allocate("svc-a")
	if err != nil {
		t.Fatalf("Allocate error: %v", err)
	}

	gotID, ok := r.LookupByName("svc-a")
	if !ok || gotID != id {
		t.Fatalf("LookupByName(svc-a) = (%d,%t), want (%d,true)", gotID, ok, id)
	}
	gotName, ok := r.LookupByID(id)
	if !ok || gotName != "svc-a" {
		t.Fatalf("LookupByID(%d) = (%q,%t), want (svc-a,true)", id, gotName, ok)
	}

	if _, ok := r.LookupByName("absent"); ok {
		t.Fatalf("LookupByName(absent) reported found")
	}
	if _, ok := r.LookupByID(wire.IdentityUnknown); ok {
		t.Fatalf("LookupByID(0) reported found")
	}
}

func TestAllocateConcurrentUniqueAndNonZero(t *testing.T) {
	r := NewRegistry()

	const n = 200
	var wg sync.WaitGroup
	ids := make([]wire.IdentityID, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id, err := r.Allocate(uniqueName(i))
			if err != nil {
				t.Errorf("Allocate error: %v", err)
				return
			}
			ids[i] = id
		}(i)
	}
	wg.Wait()

	seen := make(map[wire.IdentityID]struct{}, n)
	for i, id := range ids {
		if id == wire.IdentityUnknown {
			t.Fatalf("goroutine %d got reserved ID 0", i)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID %d allocated under concurrency", id)
		}
		seen[id] = struct{}{}
	}
	if len(seen) != n {
		t.Fatalf("allocated %d unique IDs, want %d", len(seen), n)
	}
}

func uniqueName(i int) string {
	return "svc-" + strconv.Itoa(i)
}
