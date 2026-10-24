package main

import "fmt"

// Mirror of the runtime_config_map contract in bpf/include/meridian_maps.h
// and the MERIDIAN_CFG_* bits in bpf/include/meridian_consts.h. These are
// C preprocessor #defines, not enums, so bpf2go does not generate Go
// constants for them — unlike the schema version, they must be hand-mirrored.
// test/bpf and test/integration mirror the same two values.
const (
	// cfgSlotRuntimeFlags is the single ARRAY slot holding the flag word.
	cfgSlotRuntimeFlags = uint32(0)
	// cfgFallOpenUnknownBit is MERIDIAN_CFG_FALLOPEN_UNKNOWN: set = a flow
	// whose source or destination identity is absent from identity_map is
	// ALLOWED. Unset (the zero value a freshly created map already has) =
	// fail closed.
	cfgFallOpenUnknownBit = uint32(1 << 0)
)

// configMapPutter is the write seam over the pinned runtime_config_map.
// *ebpf.Map satisfies it; tests substitute a recorder. Keeping it here, in a
// file with no build tag and no eBPF import, is what makes the seeding policy
// T1-testable on a non-Linux host.
type configMapPutter interface {
	Put(key, value any) error
}

// runtimeConfigWord returns the full runtime_config_map[0] word for the
// requested posture. The whole word is written rather than OR'd into the
// existing value, deliberately: pins survive agent restarts, so a run started
// WITHOUT --policy-fallopen must clear a bit a previous run set. Making the
// flag authoritative keeps the posture a function of the current flags alone.
// FALLOPEN_UNKNOWN is currently the only defined bit; a second one would have
// to be folded in here rather than written independently.
func runtimeConfigWord(fallOpen bool) uint32 {
	if fallOpen {
		return cfgFallOpenUnknownBit
	}
	return 0
}

// fallOpenLogLine is the startup banner describing the chosen posture. The
// posture decides whether unknown traffic flows or is dropped on the floor,
// so it is logged unconditionally — including the fail-closed default, which
// is the case operators misread as "enforcement is broken".
func fallOpenLogLine(fallOpen bool) string {
	if fallOpen {
		return "policy fallopen: unknown identities will be ALLOWED (--policy-fallopen=true)"
	}
	return "policy fallopen: unknown identities DENIED (default fail-closed)"
}

// seedRuntimeConfig writes the posture word into runtime_config_map[0].
func seedRuntimeConfig(put configMapPutter, fallOpen bool) error {
	if put == nil {
		return fmt.Errorf("seed runtime config: nil runtime_config_map handle")
	}
	word := runtimeConfigWord(fallOpen)
	if err := put.Put(any(cfgSlotRuntimeFlags), any(word)); err != nil {
		return fmt.Errorf("seed runtime_config_map[%d]=%#x: %w", cfgSlotRuntimeFlags, word, err)
	}
	return nil
}
