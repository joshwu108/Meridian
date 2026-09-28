//go:build linux

package bpfobj

import (
	"fmt"

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

// ErrPartialPinSet, preparePinDir, and reconcileSchema live in schema.go
// (platform-independent) so the fail-closed logic is T1-testable on any OS.

// CounterObjects is the bpf2go-generated counter collection. Re-exported so
// callers reach through bpfobj (the sole opener) without importing bpf/ directly.
type CounterObjects = bpf.CounterObjects

// TcIngressObjects is the bpf2go-generated tc_ingress collection.
type TcIngressObjects = bpf.TcIngressObjects

// AsCounterObjects unwraps an opaque startup handle into the counter collection.
func AsCounterObjects(opaque any) (*CounterObjects, error) {
	objs, ok := opaque.(*CounterObjects)
	if !ok || objs == nil {
		return nil, fmt.Errorf("bpfobj: opaque is %T, want *CounterObjects", opaque)
	}
	return objs, nil
}

// AsTcIngressObjects unwraps an opaque startup handle into the tc_ingress collection.
func AsTcIngressObjects(opaque any) (*TcIngressObjects, error) {
	objs, ok := opaque.(*TcIngressObjects)
	if !ok || objs == nil {
		return nil, fmt.Errorf("bpfobj: opaque is %T, want *TcIngressObjects", opaque)
	}
	return objs, nil
}

// LoadCounter loads the Phase 0 counter objects, pinning all maps by name
// under pinDir (which must be on a bpffs mount). Maps that are already pinned
// there are RE-OPENED, not re-created — this is the restart-survival contract.
func LoadCounter(pinDir string) (*CounterObjects, error) {
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

	if err := reconcileSchema(objs.SchemaSentinelMap, preExisting, schemaVersion); err != nil {
		objs.Close()
		return nil, err
	}
	return &objs, nil
}

// LoadTcIngress loads the Phase 1 tc_ingress objects, pinning all shared maps
// by name under pinDir. Re-open semantics match LoadCounter — the production
// policy datapath and MER-29 restart assertions depend on pinned map survival.
func LoadTcIngress(pinDir string) (*TcIngressObjects, error) {
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

	if err := reconcileSchema(objs.SchemaSentinelMap, preExisting, schemaVersion); err != nil {
		objs.Close()
		return nil, err
	}
	return &objs, nil
}
