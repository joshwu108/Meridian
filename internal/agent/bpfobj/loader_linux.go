//go:build linux

package bpfobj

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"

	"github.com/joshuawu/meridian/bpf"
)

// schemaVersion mirrors MERIDIAN_SCHEMA_VERSION in bpf/include/meridian_types.h.
// The loader writes it into schema_sentinel_map on first load and verifies it
// on re-open; a mismatch means the pinned maps were created by an
// incompatible build, and we fail closed rather than misinterpret layouts.
// v2 = Phase 1 contract freeze (MER-14); v1 pins are refused (D15) — wipe
// the pin dir to upgrade.
//
// TODO(MER-33): replace this literal with the bpf2go-generated
// MERIDIAN_SCHEMA_VERSION constant once the regenerated bindings land, then
// delete the hand-mirrored value.
const schemaVersion uint32 = 2

// LoadCounter loads the Phase 0 counter objects, pinning all maps by name
// under pinDir (which must be on a bpffs mount). Maps that are already pinned
// there are RE-OPENED, not re-created — this is the restart-survival contract.
func LoadCounter(pinDir string) (*bpf.CounterObjects, error) {
	if pinDir == "" {
		return nil, errors.New("bpfobj: pinDir is required (maps use LIBBPF_PIN_BY_NAME)")
	}
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		return nil, fmt.Errorf("bpfobj: create pin dir %s: %w", pinDir, err)
	}

	var objs bpf.CounterObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}
	if err := bpf.LoadCounterObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("bpfobj: load counter objects: %w", err)
	}

	if err := checkOrStampSchema(objs.SchemaSentinelMap); err != nil {
		objs.Close()
		return nil, err
	}
	return &objs, nil
}

// checkOrStampSchema writes the schema version on first load and verifies it
// on re-open of pre-existing pins. Index 0 is the only slot.
func checkOrStampSchema(sentinel *ebpf.Map) error {
	var current uint32
	if err := sentinel.Lookup(uint32(0), &current); err != nil {
		return fmt.Errorf("bpfobj: read schema sentinel: %w", err)
	}
	switch current {
	case 0: // freshly created map: ARRAY values are zero-initialised
		if err := sentinel.Put(uint32(0), schemaVersion); err != nil {
			return fmt.Errorf("bpfobj: stamp schema sentinel: %w", err)
		}
		return nil
	case schemaVersion:
		return nil
	default:
		return fmt.Errorf(
			"bpfobj: pinned maps have schema version %d, this build expects %d — refusing to start (fail closed)",
			current, schemaVersion)
	}
}
