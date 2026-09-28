package bpfobj

// T1 restart-survival seam tests (no kernel, any OS): exercise the
// load-or-reopen discipline — preparePinDir's pre-existing snapshot and
// reconcileSchema's fail-closed contract — against an in-memory stand-in for
// bpffs. The kernel-backed equivalents live in loader_test.go (T2, tag bpf).

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testSchemaV is the schema version the fake "build" expects. The real
// constant is bpf2go-sourced and Linux-only; these tests pin their own value
// because they verify the reconciliation logic, not the binding.
const testSchemaV = uint32(2)

// fakeMap is an in-memory pinned BPF ARRAY: zero-initialized, Lookup always
// succeeds (matching kernel ARRAY semantics for schema_sentinel_map).
type fakeMap struct {
	name string
	vals map[uint32]uint32
}

func newFakeMap(name string) *fakeMap {
	return &fakeMap{name: name, vals: make(map[uint32]uint32)}
}

func (m *fakeMap) Lookup(key, valueOut any) error {
	*(valueOut.(*uint32)) = m.vals[key.(uint32)]
	return nil
}

func (m *fakeMap) Put(key, value any) error {
	m.vals[key.(uint32)] = value.(uint32)
	return nil
}

// fakeBpffs simulates the bpffs pin registry: maps pinned by name outlive the
// process (agent restart = new load against the same registry and pin dir).
type fakeBpffs struct {
	maps map[string]*fakeMap
}

func newFakeBpffs() *fakeBpffs {
	return &fakeBpffs{maps: make(map[string]*fakeMap)}
}

// loadFake mirrors the production load sequence (LoadCounter/LoadTcIngress):
// snapshot pre-existing BEFORE any map is opened, open-or-reopen each pinned
// map by name (never recreate an existing pin), then reconcile the schema
// sentinel — failing closed without adopting the maps on any mismatch.
func loadFake(t *testing.T, pinDir string, fs *fakeBpffs, version uint32, names ...string) (map[string]*fakeMap, error) {
	t.Helper()
	preExisting, err := preparePinDir(pinDir)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*fakeMap)
	for _, name := range append([]string{"schema_sentinel_map"}, names...) {
		m, ok := fs.maps[name]
		if !ok {
			m = newFakeMap(name)
			fs.maps[name] = m
			// The pin file is what the next load's preparePinDir sees.
			if err := os.WriteFile(filepath.Join(pinDir, name), nil, 0o600); err != nil {
				t.Fatalf("write fake pin %s: %v", name, err)
			}
		}
		out[name] = m
	}
	if err := reconcileSchema(out["schema_sentinel_map"], preExisting, version); err != nil {
		return nil, err
	}
	return out, nil
}

// TestReOpenDoesNotRecreate: a second load against the same pin dir must hand
// back the SAME underlying map handles (re-open), and must not re-stamp the
// already-stamped sentinel.
func TestReOpenDoesNotRecreate(t *testing.T) {
	pinDir := t.TempDir()
	fs := newFakeBpffs()

	first, err := loadFake(t, pinDir, fs, testSchemaV, "policy_map")
	if err != nil {
		t.Fatalf("fresh load: %v", err)
	}
	second, err := loadFake(t, pinDir, fs, testSchemaV, "policy_map")
	if err != nil {
		t.Fatalf("re-open load: %v", err)
	}

	for _, name := range []string{"schema_sentinel_map", "policy_map"} {
		if first[name] != second[name] {
			t.Fatalf("map %q was recreated on re-open; want the same underlying handle", name)
		}
	}
	var v uint32
	if err := second["schema_sentinel_map"].Lookup(uint32(0), &v); err != nil {
		t.Fatalf("read sentinel: %v", err)
	}
	if v != testSchemaV {
		t.Fatalf("sentinel = %d after re-open, want %d (stamped exactly once on fresh creation)", v, testSchemaV)
	}
}

// TestPolicyStateSurvivesRestart: entries written before an agent "restart"
// must still be visible through the handle the second load returns.
func TestPolicyStateSurvivesRestart(t *testing.T) {
	pinDir := t.TempDir()
	fs := newFakeBpffs()

	first, err := loadFake(t, pinDir, fs, testSchemaV, "policy_map")
	if err != nil {
		t.Fatalf("fresh load: %v", err)
	}
	entries := map[uint32]uint32{10: 1, 20: 2, 30: 1}
	for k, v := range entries {
		if err := first["policy_map"].Put(k, v); err != nil {
			t.Fatalf("write policy entry %d: %v", k, err)
		}
	}

	// "Restart": drop the first handles, load again against the same pins.
	second, err := loadFake(t, pinDir, fs, testSchemaV, "policy_map")
	if err != nil {
		t.Fatalf("restart load: %v", err)
	}
	for k, want := range entries {
		var got uint32
		if err := second["policy_map"].Lookup(k, &got); err != nil {
			t.Fatalf("lookup policy entry %d after restart: %v", k, err)
		}
		if got != want {
			t.Fatalf("policy entry %d = %d after restart, want %d (state lost)", k, got, want)
		}
	}
}

// TestSchemaVersionMismatchRefusesStart: pins stamped by a different build's
// schema version must be refused, not adopted or re-stamped.
func TestSchemaVersionMismatchRefusesStart(t *testing.T) {
	pinDir := t.TempDir()
	fs := newFakeBpffs()

	if _, err := loadFake(t, pinDir, fs, testSchemaV, "policy_map"); err != nil {
		t.Fatalf("fresh load: %v", err)
	}

	_, err := loadFake(t, pinDir, fs, testSchemaV+1, "policy_map")
	if err == nil {
		t.Fatalf("load with schema version %d accepted pins stamped %d; want fail-closed", testSchemaV+1, testSchemaV)
	}
	if errors.Is(err, ErrPartialPinSet) {
		t.Fatalf("error = %v, want version-mismatch refusal, not ErrPartialPinSet", err)
	}
	if !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("error %q does not state the fail-closed refusal", err)
	}
	// The sentinel must not have been re-stamped by the refused load.
	var v uint32
	_ = fs.maps["schema_sentinel_map"].Lookup(uint32(0), &v)
	if v != testSchemaV {
		t.Fatalf("sentinel = %d after refused load, want untouched %d", v, testSchemaV)
	}
}

// TestPartialPinSetRefusesStart: pins that exist but whose sentinel is still
// 0 (a prior load crashed mid-init) must be refused with ErrPartialPinSet.
func TestPartialPinSetRefusesStart(t *testing.T) {
	pinDir := t.TempDir()
	fs := newFakeBpffs()

	// Simulate the crash window: maps pinned, sentinel never stamped.
	fs.maps["schema_sentinel_map"] = newFakeMap("schema_sentinel_map")
	if err := os.WriteFile(filepath.Join(pinDir, "schema_sentinel_map"), nil, 0o600); err != nil {
		t.Fatalf("write fake pin: %v", err)
	}

	_, err := loadFake(t, pinDir, fs, testSchemaV)
	if !errors.Is(err, ErrPartialPinSet) {
		t.Fatalf("error = %v, want ErrPartialPinSet for an unstamped pre-existing pin set", err)
	}
}
