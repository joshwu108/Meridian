package bpfobj

// Platform-independent core of the load-or-reopen discipline: the pin-dir
// pre-existing snapshot and the schema-sentinel reconciliation. The Linux
// loaders (loader_linux.go, sockmap_linux.go) call these against real pinned
// maps; T1 tests (restart_test.go) exercise the same fail-closed logic on any
// OS through the sentinelMap seam.

import (
	"errors"
	"fmt"
	"os"
)

// ErrPartialPinSet is returned when a load re-opens a pin directory that
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

// sentinelMap is the narrow surface of *ebpf.Map that schema reconciliation
// needs. It exists so the fail-closed logic is testable without a kernel.
type sentinelMap interface {
	Lookup(key, valueOut any) error
	Put(key, value any) error
}

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
//     it with this build's schema version (want).
//   - Re-open (preExisting == true): the sentinel MUST already carry this
//     build's version. A value of 0 means a prior load crashed between map
//     creation and the stamp — a partially-initialized set (ErrPartialPinSet),
//     fail closed. Any other value means the pins were created by an
//     incompatible build — fail closed. We never stamp on a re-open.
func reconcileSchema(sentinel sentinelMap, preExisting bool, want uint32) error {
	var current uint32
	if err := sentinel.Lookup(uint32(0), &current); err != nil {
		return fmt.Errorf("bpfobj: read schema sentinel: %w", err)
	}

	if !preExisting {
		if err := sentinel.Put(uint32(0), want); err != nil {
			return fmt.Errorf("bpfobj: stamp schema sentinel: %w", err)
		}
		return nil
	}

	switch current {
	case want:
		return nil
	case 0:
		return fmt.Errorf("%w (pin dir state: maps pinned, sentinel still 0)", ErrPartialPinSet)
	default:
		return fmt.Errorf(
			"bpfobj: pinned maps have schema version %d, this build expects %d — refusing to start (fail closed)",
			current, want)
	}
}
