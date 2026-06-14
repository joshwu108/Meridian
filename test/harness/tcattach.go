package harness

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// EnsureClsact installs (or replaces) a clsact qdisc on ifName inside netns.
func EnsureClsact(t *testing.T, netns, ifName string) {
	t.Helper()
	runInNetNSNetOnly(t, netns, "tc", "qdisc", "replace", "dev", ifName, "clsact")
}

// AttachTCIngress attaches a pinned BPF program to ifName's clsact ingress hook
// inside netns and registers cleanup that removes the filter.
func AttachTCIngress(t *testing.T, netns, ifName, pinnedProg string) {
	t.Helper()
	EnsureClsact(t, netns, ifName)
	runInNetNSNetOnly(t, netns, "tc", "filter", "add", "dev", ifName, "ingress",
		"bpf", "direct-action", "object-pinned", pinnedProg)
	t.Cleanup(func() {
		_, _ = runInNetNSNetOnlyQuiet(netns, "tc", "filter", "del", "dev", ifName, "ingress")
	})
}

// AttachTCEgress attaches a pinned BPF program to ifName's clsact egress hook
// inside netns and registers cleanup that removes the filter.
func AttachTCEgress(t *testing.T, netns, ifName, pinnedProg string) {
	t.Helper()
	EnsureClsact(t, netns, ifName)
	runInNetNSNetOnly(t, netns, "tc", "filter", "add", "dev", ifName, "egress",
		"bpf", "direct-action", "object-pinned", pinnedProg)
	t.Cleanup(func() {
		_, _ = runInNetNSNetOnlyQuiet(netns, "tc", "filter", "del", "dev", ifName, "egress")
	})
}

// AttachTCEgressHost attaches egress BPF on ifName in the root network namespace.
func AttachTCEgressHost(t *testing.T, ifName, pinnedProg string) {
	t.Helper()
	runHost(t, "tc", "qdisc", "replace", "dev", ifName, "clsact")
	runHost(t, "tc", "filter", "add", "dev", ifName, "egress",
		"bpf", "direct-action", "object-pinned", pinnedProg)
	t.Cleanup(func() {
		_, _ = exec.Command("tc", "filter", "del", "dev", ifName, "egress").CombinedOutput()
	})
}

// AttachTCIngressHost attaches ingress BPF on ifName in the root network namespace.
func AttachTCIngressHost(t *testing.T, ifName, pinnedProg string) {
	t.Helper()
	runHost(t, "tc", "qdisc", "replace", "dev", ifName, "clsact")
	runHost(t, "tc", "filter", "add", "dev", ifName, "ingress",
		"bpf", "direct-action", "object-pinned", pinnedProg)
	t.Cleanup(func() {
		_, _ = exec.Command("tc", "filter", "del", "dev", ifName, "ingress").CombinedOutput()
	})
}

func runHost(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s\n  err: %v\n  output: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

// runInNetNSNetOnly executes a command in netns's network namespace while
// keeping the caller's mount namespace. ip netns exec also switches mount ns,
// which gives each netns an empty /sys/fs/bpf and breaks object-pinned tc
// attach paths created from the host mount.
func runInNetNSNetOnly(t *testing.T, netns string, name string, args ...string) {
	t.Helper()
	out, err := runInNetNSNetOnlyQuiet(netns, name, args...)
	if err != nil {
		full := append([]string{"--net=" + netnsPath(netns), name}, args...)
		t.Fatalf("command failed: nsenter %s\n  err: %v\n  output: %s",
			strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
}

func runInNetNSNetOnlyQuiet(netns, name string, args ...string) (string, error) {
	full := append([]string{"--net=" + netnsPath(netns), name}, args...)
	out, err := exec.Command("nsenter", full...).CombinedOutput()
	return string(out), err
}

func netnsPath(netns string) string {
	return filepath.Join("/var/run/netns", netns)
}
