//go:build linux

package bpfobj

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"

	"github.com/joshuawu/meridian/bpf"
)

// schemaVersion is bpf2go-sourced from enum meridian_schema_version in
// bpf/include/meridian_types.h (MER-33 / review D-1). The loader writes it into
// schema_sentinel_map exactly once — on a verified fresh pin set — and verifies
// it on every re-open; a mismatch means the pinned maps were created by an
// incompatible build, and we fail closed rather than misinterpret layouts.
// v2 = Phase 1 contract freeze (MER-14); v1 pins are refused (D15) — wipe the
// pin dir to upgrade. Never hand-mirror this number (CC-6).
const schemaVersion = uint32(bpf.CounterMeridianSchemaVersionMERIDIAN_SCHEMA_VERSION)

// ErrPartialPinSet is returned when LoadCounter re-opens a pin directory that
// already holds Meridian pinned state but whose schema sentinel is still
// unstamped (version 0). That state is only reachable if a previous load
// crashed between creating/pinning the maps and stamping the sentinel
// (review D-9). The pinned maps may have been created by an older,
// layout-incompatible build, so we refuse to either adopt them or silently
// stamp the current version over them.
//
// Recover by wiping the pin directory (remove the bpffs subtree the pins live
// under) so the next start creates a clean, fully-initialized set.
var ErrPartialPinSet = errors.New(
	"bpfobj: pinned maps exist but the schema sentinel is unstamped — partially-initialized pin set from a crashed prior load; refusing to start (fail closed). Wipe the pin dir to recover")

func preparePinDir(pinDir string) (preExisting bool, err error) {
	if pinDir == "" {
		return false, errors.New("bpfobj: pinDir is required (maps use LIBBPF_PIN_BY_NAME)")
	}
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		return false, fmt.Errorf("bpfobj: create pin dir %s: %w", pinDir, err)
	}
	// Ordering proof for the schema stamp (closes review D-9). Decide, BEFORE
	// any map is opened, whether this pin set already exists on disk. Stamping
	// the sentinel is sound ONLY on a from-scratch creation: if the pin dir
	// already holds Meridian state we are re-opening, and an unstamped sentinel
	// then means a prior load crashed mid-init. We must fail closed on that
	// rather than stamp the current version over maps an older build may have
	// created. This snapshot must be taken before Load*Objects, which is what
	// (re)creates and pins the maps.
	return pinDirPopulated(pinDir)
}

// LoadCounter loads the Phase 0 counter objects, pinning all maps by name
// under pinDir (which must be on a bpffs mount). Maps that are already pinned
// there are RE-OPENED, not re-created — this is the restart-survival contract.
func LoadCounter(pinDir string) (*bpf.CounterObjects, error) {
	preExisting, err := preparePinDir(pinDir)
	if err != nil {
		return nil, err
	}

	var objs bpf.CounterObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}
	if err := bpf.LoadCounterObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("bpfobj: load counter objects: %w", err)
	}

	if err := reconcileSchema(objs.SchemaSentinelMap, preExisting); err != nil {
		objs.Close()
		return nil, err
	}
	return &objs, nil
}

// LoadTcIngress loads the Phase 1 tc_ingress objects, pinning all shared maps
// by name under pinDir. Re-open semantics match LoadCounter — the production
// policy datapath and MER-29 restart assertions depend on pinned map survival.
func LoadTcIngress(pinDir string) (*bpf.TcIngressObjects, error) {
	preExisting, err := preparePinDir(pinDir)
	if err != nil {
		return nil, err
	}

	var objs bpf.TcIngressObjects
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}
	if err := bpf.LoadTcIngressObjects(&objs, opts); err != nil {
		return nil, fmt.Errorf("bpfobj: load tc_ingress objects: %w", err)
	}

	if err := reconcileSchema(objs.SchemaSentinelMap, preExisting); err != nil {
		objs.Close()
		return nil, err
	}
	return &objs, nil
}

// pinDirPopulated reports whether pinDir already contains any pinned entry.
// bpfobj is the sole opener of this directory (see doc.go), so any entry —
// a pinned map or the program pin a prior run left behind — proves an earlier
// load already created state here and this load is a re-open, not a fresh
// creation. That single bit is what reconcileSchema needs to decide whether
// stamping the sentinel is sound; it deliberately errs toward "pre-existing"
// (fail-closed) because the dangerous direction is stamping when we should not.
func pinDirPopulated(pinDir string) (bool, error) {
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		return false, fmt.Errorf("bpfobj: scan pin dir %s: %w", pinDir, err)
	}
	return len(entries) > 0, nil
}

// reconcileSchema enforces the schema contract across loads. It is the SOLE
// writer of schema_sentinel_map and writes only on a verified-fresh pin set —
// the ordering proof that closes review D-9. Index 0 is the only slot.
//
//   - Fresh creation (preExisting == false): the kernel zero-inits the ARRAY,
//     so the sentinel reads 0 and no other build has touched these maps. Stamp
//     it with this build's schema version.
//   - Re-open (preExisting == true): the sentinel MUST already carry this
//     build's version. A value of 0 means a prior load crashed between map
//     creation and the stamp — a partially-initialized set (ErrPartialPinSet),
//     fail closed. Any other value means the pins were created by an
//     incompatible build — fail closed. We never stamp on a re-open.
func reconcileSchema(sentinel *ebpf.Map, preExisting bool) error {
	var current uint32
	if err := sentinel.Lookup(uint32(0), &current); err != nil {
		return fmt.Errorf("bpfobj: read schema sentinel: %w", err)
	}

	if !preExisting {
		if err := sentinel.Put(uint32(0), schemaVersion); err != nil {
			return fmt.Errorf("bpfobj: stamp schema sentinel: %w", err)
		}
		return nil
	}

	switch current {
	case schemaVersion:
		return nil
	case 0:
		return fmt.Errorf("%w (pin dir state: maps pinned, sentinel still 0)", ErrPartialPinSet)
	default:
		return fmt.Errorf(
			"bpfobj: pinned maps have schema version %d, this build expects %d — refusing to start (fail closed)",
			current, schemaVersion)
	}
}
