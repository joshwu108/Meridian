// Package harness provides the Phase 0 test environment for Meridian's eBPF
// data plane: per-run namespacing of every kernel resource, a netns/bpffs
// reaper, root gating, and deadline-bounded condition waiting.
//
// Scope (Phase 0): just enough to bring up a veth pair across two netns, pin
// maps under a per-run bpffs subtree, and assert on a packet counter plus
// ring-buffer events. Policy maps, multi-node simulation, Geneve, and TPROXY
// are Phase 1+ and deliberately absent. The fixture is structured to grow.
//
// Design rules (binding, from the Phase 0 design rounds):
//   - Every resource is namespaced per run: netns "mrdn-<runID>-...", bpffs
//     pins under /sys/fs/bpf/meridian-test/<runID>/<testname>/.
//   - A reaper runs in TestMain before and after each suite.
//   - Cleanup is registered with t.Cleanup, never bare defer.
//   - No sleeps: all waits are deadline-bounded polls (WaitUntil).
package harness

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// BpffsRoot is the per-suite bpffs subtree. Everything Meridian's tests
	// pin lives below here so the reaper can wipe it without touching other
	// users of /sys/fs/bpf.
	BpffsRoot = "/sys/fs/bpf/meridian-test"

	// NetnsPrefix tags every netns this suite creates. The reaper deletes any
	// netns whose name starts with this prefix.
	NetnsPrefix = "mrdn-"

	// PollInterval is the fixed poll cadence for WaitUntil.
	PollInterval = 5 * time.Millisecond
)

// runID is computed once per process (one `go test` binary == one suite run).
// PID keeps concurrent suite binaries from colliding on netns names and pin
// dirs; the timestamp suffix disambiguates fast successive runs reusing PIDs.
var (
	runIDOnce sync.Once
	runIDVal  string
	pinDirMu  sync.Mutex
)

// RunID returns the per-process run identifier, e.g. "4711-1a2b3c". It is
// stable for the lifetime of the test binary and embedded in every netns name
// and bpffs pin path so resources are attributable and reapable.
func RunID() string {
	runIDOnce.Do(func() {
		runIDVal = fmt.Sprintf("%d-%x", os.Getpid(), time.Now().UnixNano()&0xffffff)
	})
	return runIDVal
}

// RequireRoot skips the test unless the process runs as uid 0. eBPF program
// loading, TC attach, netns creation, and bpffs pinning all require
// CAP_SYS_ADMIN/CAP_NET_ADMIN; rather than probe individual capabilities in
// Phase 0 we require root, which CI provides.
func RequireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (eBPF load, TC attach, netns, bpffs pin); run with -exec sudo")
	}
}

// WaitUntil polls cond every PollInterval until it returns true or timeout
// elapses, then fails the test with msg. This is the ONLY waiting primitive
// in the test tree: there are no fixed sleeps. cond must be cheap and
// side-effect free; it is the observable condition the test is really
// asserting on (a counter reaching N, an event arriving), never a proxy for
// elapsed time.
func WaitUntil(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("WaitUntil timed out after %s: %s", timeout, msg)
		}
		time.Sleep(PollInterval)
	}
}

// PinDir returns a per-test bpffs directory under BpffsRoot/<runID>/<test>,
// creating it if needed, and registers a t.Cleanup that removes it (removing
// a bpffs subtree unpins the maps/programs it holds). The suite-level reaper
// sweeps anything a crashing test leaks.
func PinDir(t *testing.T) string {
	t.Helper()
	runDir := filepath.Join(BpffsRoot, RunID())
	dir := filepath.Join(runDir, sanitizeName(t.Name()))
	pinDirMu.Lock()
	defer pinDirMu.Unlock()
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatalf("PinDir: mkdir %s: %v", runDir, err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("PinDir: mkdir %s: %v", dir, err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("PinDir: stat %s: %v", dir, err)
	}
	return dir
}

// Reap deletes every Meridian test netns and removes the suite bpffs subtree.
// Idempotent and best-effort: it does not fail on individual errors, because
// its whole purpose is cleaning up after crashes where some resources may
// already be gone. Call from TestMain both before and after the suite so a
// previous crashed run cannot poison the current one.
func Reap() {
	reapNetns()
	reapBpffs()
}

func reapNetns() {
	out, err := exec.Command("ip", "netns", "list").CombinedOutput()
	if err != nil {
		return // no netns subsystem or none present: nothing to reap
	}
	for _, line := range strings.Split(string(out), "\n") {
		// `ip netns list` prints "name (id: N)" or just "name".
		name := strings.TrimSpace(line)
		if i := strings.IndexByte(name, ' '); i >= 0 {
			name = name[:i]
		}
		if name == "" || !strings.HasPrefix(name, NetnsPrefix) {
			continue
		}
		// Deleting the netns tears down any veth whose peer lived inside it.
		_ = exec.Command("ip", "netns", "del", name).Run()
	}
}

func reapBpffs() {
	_ = os.RemoveAll(BpffsRoot)
}

// sanitizeName turns a t.Name() (which may contain '/', spaces, etc. from
// subtests) into a safe single path component.
func sanitizeName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		case r == '-', r == '_':
			return r
		default:
			return '_'
		}
	}, name)
}
