package harness

import (
	"os/exec"
	"strings"
	"testing"
)

// EnsureClsact installs (or replaces) a clsact qdisc on ifName inside netns.
func EnsureClsact(t *testing.T, netns, ifName string) {
	t.Helper()
	runInNetns(t, netns, "tc", "qdisc", "replace", "dev", ifName, "clsact")
}

// AttachTCIngress attaches a pinned BPF program to ifName's clsact ingress hook
// inside netns and registers cleanup that removes the filter.
func AttachTCIngress(t *testing.T, netns, ifName, pinnedProg string) {
	t.Helper()
	EnsureClsact(t, netns, ifName)
	runInNetns(t, netns, "tc", "filter", "add", "dev", ifName, "ingress",
		"bpf", "direct-action", "object-pinned", pinnedProg)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", netns,
			"tc", "filter", "del", "dev", ifName, "ingress").Run()
	})
}

// AttachTCEgress attaches a pinned BPF program to ifName's clsact egress hook
// inside netns and registers cleanup that removes the filter.
func AttachTCEgress(t *testing.T, netns, ifName, pinnedProg string) {
	t.Helper()
	EnsureClsact(t, netns, ifName)
	runInNetns(t, netns, "tc", "filter", "add", "dev", ifName, "egress",
		"bpf", "direct-action", "object-pinned", pinnedProg)
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "exec", netns,
			"tc", "filter", "del", "dev", ifName, "egress").Run()
	})
}

func runInNetns(t *testing.T, netns string, args ...string) {
	t.Helper()
	full := append([]string{"netns", "exec", netns}, args...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: ip %s\n  err: %v\n  output: %s",
			strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
}
