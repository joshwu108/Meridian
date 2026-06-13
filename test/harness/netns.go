package harness

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

// VethPair is the Phase 0 network fixture: one netns ("mrdn-<run>-<name>")
// holding the peer end of a veth pair with an IP assigned, and the host end
// left in the root namespace, brought up, with a clsact qdisc installed so a
// TC BPF filter can later be attached to it.
//
// Topology:
//
//	 root netns                          mrdn-<run>-<name>
//	┌────────────────────┐              ┌────────────────────┐
//	│  HostVeth (up)      │═══ veth ════│  PeerVeth (PeerIP)  │
//	│  clsact qdisc       │              │  loopback up        │
//	└────────────────────┘              └────────────────────┘
//
// The counter program under test attaches to HostVeth's clsact ingress: every
// packet the peer sends toward the host is counted. Phase 1 grows this into
// the two-"node" pod-to-pod topology by adding pairs and routing.
//
// Implementation note: Phase 0 drives the `ip` and `tc` binaries via os/exec
// rather than vishvananda/netlink. It keeps the test tree free of a netlink
// dependency, and the commands are exactly what an operator would run, so
// failures reproduce by hand. The agent owns real netlink attach in Phase 1;
// this fixture can swap mechanisms behind the same method signatures.
type VethPair struct {
	Name     string // short fixture name (e.g. "p0")
	Netns    string // full namespace name: mrdn-<run>-<name>
	HostVeth string // root-namespace interface; TC filters attach here
	PeerVeth string // in-namespace interface, carrying PeerIP
	HostAddr string // address on HostVeth in the root namespace
	PeerIP   string // address on PeerVeth inside the netns

	t *testing.T
}

// NewVethPair brings up the fixture and registers teardown via t.Cleanup. It
// fails the test immediately (with the offending command line and stderr) if
// any step fails. The 169.254.<octet>.0/30 link-local block avoids clashing
// with real addressing; octet keeps concurrent pairs disjoint.
func NewVethPair(t *testing.T, name string, octet byte) *VethPair {
	t.Helper()
	v := &VethPair{
		Name:     name,
		Netns:    fmt.Sprintf("%s%s-%s", NetnsPrefix, RunID(), name),
		HostVeth: "mh-" + name,
		PeerVeth: "mp-" + name,
		HostAddr: fmt.Sprintf("169.254.%d.1", octet),
		PeerIP:   fmt.Sprintf("169.254.%d.2", octet),
		t:        t,
	}

	// Register teardown FIRST so a failure partway through bring-up is still
	// cleaned up. Close() is idempotent and best-effort.
	t.Cleanup(v.Close)

	v.setup()
	return v
}

func (v *VethPair) setup() {
	v.t.Helper()

	v.run("ip", "netns", "add", v.Netns)
	v.run("ip", "link", "add", v.HostVeth, "type", "veth", "peer", "name", v.PeerVeth)
	v.run("ip", "link", "set", v.PeerVeth, "netns", v.Netns)
	v.run("ip", "addr", "add", v.HostAddr+"/30", "dev", v.HostVeth)
	v.run("ip", "link", "set", v.HostVeth, "up")
	v.run("ip", "netns", "exec", v.Netns, "ip", "addr", "add", v.PeerIP+"/30", "dev", v.PeerVeth)
	v.run("ip", "netns", "exec", v.Netns, "ip", "link", "set", v.PeerVeth, "up")
	v.run("ip", "netns", "exec", v.Netns, "ip", "link", "set", "lo", "up")
	v.run("tc", "qdisc", "add", "dev", v.HostVeth, "clsact")
}

// ExecInNS runs a one-shot command inside the namespace via `ip netns exec`
// and returns its combined output, failing the test on non-zero exit. Use for
// workload generators (ping, nc); long-lived processes the harness must
// control will use setns with a locked OS thread (Phase 1+).
func (v *VethPair) ExecInNS(t *testing.T, cmd ...string) string {
	t.Helper()
	full := append([]string{"netns", "exec", v.Netns}, cmd...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("ExecInNS failed: ip %s\n  err: %v\n  output: %s",
			strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out)
}

// TryExecInNS is ExecInNS for commands that are EXPECTED to fail (e.g. a
// denied connection in later phases): it returns the error instead of
// failing the test.
func (v *VethPair) TryExecInNS(cmd ...string) (string, error) {
	full := append([]string{"netns", "exec", v.Netns}, cmd...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	return string(out), err
}

// AttachTC attaches an already-pinned BPF program to the host veth's clsact
// ingress in direct-action mode and registers removal via t.Cleanup.
// pinnedProg is the absolute bpffs path of the program (pin it under
// PinDir(t) first) — `tc filter add ... object-pinned` consumes a pin path,
// not a raw fd, which is why Phase 0 pins programs before attach.
func (v *VethPair) AttachTC(t *testing.T, pinnedProg string) {
	t.Helper()
	v.run("tc", "filter", "add", "dev", v.HostVeth, "ingress",
		"bpf", "direct-action", "object-pinned", pinnedProg)
	t.Cleanup(func() {
		_ = exec.Command("tc", "filter", "del", "dev", v.HostVeth, "ingress").Run()
	})
}

// Close tears the fixture down: deleting the host veth removes both ends,
// and deleting the namespace cleans the rest. Best-effort and idempotent —
// safe to call twice, safe after a partial setup.
func (v *VethPair) Close() {
	_ = exec.Command("tc", "qdisc", "del", "dev", v.HostVeth, "clsact").Run()
	_ = exec.Command("ip", "link", "del", v.HostVeth).Run()
	_ = exec.Command("ip", "netns", "del", v.Netns).Run()
}

// run executes a command, failing the test with the full command line and
// combined output on any non-zero exit. Every `ip`/`tc` invocation in the
// harness is checked — no silent failures.
func (v *VethPair) run(name string, args ...string) {
	v.t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		v.t.Fatalf("command failed: %s %s\n  err: %v\n  output: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}
