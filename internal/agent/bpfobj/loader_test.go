//go:build bpf

package bpfobj

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/test/harness"
)

// TestSchemaVersionSingleSourced closes MER-33 / review D-1: the loader must
// read MERIDIAN_SCHEMA_VERSION from bpf2go-generated bindings, not a
// hand-mirrored Go literal. A drift between C and Go would otherwise only be
// caught by humans.
func TestSchemaVersionSingleSourced(t *testing.T) {
	want := uint32(bpf.CounterMeridianSchemaVersionMERIDIAN_SCHEMA_VERSION)
	if want == 0 {
		t.Fatal("bpf2go exported MERIDIAN_SCHEMA_VERSION is 0 — enum not in BTF?")
	}
	if schemaVersion != want {
		t.Fatalf("loader schemaVersion = %d, want bpf2go constant %d", schemaVersion, want)
	}
	if want != 2 {
		t.Fatalf("MERIDIAN_SCHEMA_VERSION = %d, want 2 (Phase 1 contract freeze)", want)
	}
}

// TestSchemaSentinelFailsClosedOnV1Pins closes review T-2 via MER-33: a pin set
// stamped with schema v1 must be refused by the v2 build. Distinct from the
// partial-init case (ErrPartialPinSet) and from an arbitrary foreign version.
func TestSchemaSentinelFailsClosedOnV1Pins(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	pinDir := harness.PinDir(t)

	objs, err := LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("fresh load: %v", err)
	}
	const v1 uint32 = 1
	if err := objs.SchemaSentinelMap.Put(uint32(0), v1); err != nil {
		objs.Close()
		t.Fatalf("overwrite sentinel to v1: %v", err)
	}
	objs.Close()

	reopened, err := LoadCounter(pinDir)
	if err == nil {
		reopened.Close()
		t.Fatal("LoadCounter accepted v1 pins on a v2 build; want fail-closed")
	}
	if errors.Is(err, ErrPartialPinSet) {
		t.Fatalf("LoadCounter error = %v, want version-mismatch fail-closed, not ErrPartialPinSet", err)
	}
}
