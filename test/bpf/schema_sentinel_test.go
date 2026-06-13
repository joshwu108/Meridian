//go:build bpf

package bpftest

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/test/harness"
)

// seedUnstampedPinSet creates and pins the full counter map set under pinDir
// WITHOUT stamping the schema sentinel, then drops the Go handles. bpfobj — not
// the raw loader — is what stamps the sentinel, so loading the objects directly
// and closing them reproduces exactly the on-bpffs state a load that crashed
// after LoadAndAssign but before the stamp would leave behind (review D-9's
// crash-between-create-and-stamp window). The pins survive Close; only the
// per-test PinDir cleanup (or the reaper) unpins them.
func seedUnstampedPinSet(t *testing.T, pinDir string) {
	t.Helper()
	var raw bpf.CounterObjects
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}
	if err := bpf.LoadCounterObjects(&raw, opts); err != nil {
		t.Fatalf("seed pin set: load+pin counter objects: %v", err)
	}
	defer raw.Close()

	// Confirm the precondition: the sentinel is genuinely unstamped (the kernel
	// zero-inits ARRAY values). If this ever reads non-zero, the seeding no
	// longer models the crash window and the test below would be vacuous.
	var v uint32
	if err := raw.SchemaSentinelMap.Lookup(uint32(0), &v); err != nil {
		t.Fatalf("seed pin set: read sentinel: %v", err)
	}
	if v != 0 {
		t.Fatalf("seed pin set: sentinel = %d, want 0 (unstamped) — seeding no longer models the crash window", v)
	}
}

// TestSchemaSentinelFailsClosedOnPartialPinSet is the MER-36 / review D-9
// regression: a crash between map creation and the sentinel stamp must NOT let
// the next start silently stamp the current schema version over maps an older
// build may have created. The next open must fail closed.
func TestSchemaSentinelFailsClosedOnPartialPinSet(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	pinDir := harness.PinDir(t)
	seedUnstampedPinSet(t, pinDir)

	objs, err := bpfobj.LoadCounter(pinDir)
	if err == nil {
		objs.Close()
		t.Fatal("LoadCounter adopted a partially-initialized pin set; want fail-closed (ErrPartialPinSet)")
	}
	if !errors.Is(err, bpfobj.ErrPartialPinSet) {
		t.Fatalf("LoadCounter error = %v, want ErrPartialPinSet", err)
	}
}

// TestSchemaSentinelStampsFreshThenSurvivesRestart proves the happy path the
// fail-closed guard must not regress: a from-scratch load stamps the sentinel,
// and a subsequent re-open of the same pins (the agent-restart contract)
// succeeds because the sentinel already matches.
func TestSchemaSentinelStampsFreshThenSurvivesRestart(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	pinDir := harness.PinDir(t)

	first, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("fresh load: %v", err)
	}
	first.Close() // pins persist on bpffs; this models the agent process exiting

	second, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("re-open of stamped pin set (restart survival): %v", err)
	}
	second.Close()
}

// TestSchemaSentinelFailsClosedOnVersionMismatch closes review T-2: a pin set
// stamped with a different (incompatible) schema version is refused on re-open,
// and the error is a version mismatch — distinct from the partial-init case.
func TestSchemaSentinelFailsClosedOnVersionMismatch(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	pinDir := harness.PinDir(t)

	objs, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		t.Fatalf("fresh load: %v", err)
	}
	// Simulate maps left by an incompatible build.
	const foreignVersion uint32 = 99
	if err := objs.SchemaSentinelMap.Put(uint32(0), foreignVersion); err != nil {
		objs.Close()
		t.Fatalf("overwrite sentinel: %v", err)
	}
	objs.Close()

	reopened, err := bpfobj.LoadCounter(pinDir)
	if err == nil {
		reopened.Close()
		t.Fatal("LoadCounter accepted a foreign-schema pin set; want fail-closed")
	}
	if errors.Is(err, bpfobj.ErrPartialPinSet) {
		t.Fatalf("LoadCounter error = %v, want a version-mismatch error, not ErrPartialPinSet", err)
	}
}
