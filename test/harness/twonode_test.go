//go:build integration

package harness

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	Reap()
	code := m.Run()
	Reap()
	os.Exit(code)
}

func TestTwoNodeTopologyCreation(t *testing.T) {
	RequireRoot(t)

	top := NewTwoNode(t, "topology", 40)

	assertNamespaceExists(t, top.NodeA.Namespace)
	assertNamespaceExists(t, top.NodeB.Namespace)
	assertLinkExists(t, top.HostVethA)
	assertLinkExists(t, top.HostVethB)
	assertLinkExistsInNS(t, top.NodeA.Namespace, top.NodeA.Veth)
	assertLinkExistsInNS(t, top.NodeB.Namespace, top.NodeB.Veth)
	assertLinkExistsInNS(t, top.NodeA.Namespace, geneveDeviceName)
	assertLinkExistsInNS(t, top.NodeB.Namespace, geneveDeviceName)

	aGeneve := top.ExecInNode(t, top.NodeA, "ip", "-d", "link", "show", geneveDeviceName)
	if !strings.Contains(aGeneve, "geneve id "+strconv.Itoa(geneveVNI)) {
		t.Fatalf("node A geneve device missing expected VNI: %s", strings.TrimSpace(aGeneve))
	}
}

func TestTwoNodeRoutingValidation(t *testing.T) {
	RequireRoot(t)

	top := NewTwoNode(t, "routing", 50)

	WaitUntil(t, 3*time.Second, func() bool {
		_, err := top.TryExecInNode(top.NodeA, "ping", "-c", "1", "-W", "1", top.NodeB.UnderlayIP)
		return err == nil
	}, "node A could not reach node B underlay address")

	WaitUntil(t, 3*time.Second, func() bool {
		_, err := top.TryExecInNode(top.NodeA, "ping", "-c", "1", "-W", "1", top.NodeB.OverlayIP)
		return err == nil
	}, "node A could not reach node B overlay address over Geneve")

	WaitUntil(t, 3*time.Second, func() bool {
		_, err := top.TryExecInNode(top.NodeB, "ping", "-c", "1", "-W", "1", top.NodeA.UnderlayIP)
		return err == nil
	}, "node B could not reach node A underlay address")

	WaitUntil(t, 3*time.Second, func() bool {
		_, err := top.TryExecInNode(top.NodeB, "ping", "-c", "1", "-W", "1", top.NodeA.OverlayIP)
		return err == nil
	}, "node B could not reach node A overlay address over Geneve")
}

func TestTwoNodeCleanupValidation(t *testing.T) {
	RequireRoot(t)

	top := NewTwoNode(t, "cleanup", 60)
	nodeA := top.NodeA.Namespace
	nodeB := top.NodeB.Namespace
	hostA := top.HostVethA
	hostB := top.HostVethB

	top.Close()
	// NewTwoNode also registered cleanup; this explicit call lets us assert
	// teardown effects in-test while keeping t.Cleanup as a crash backstop.

	WaitUntil(t, 2*time.Second, func() bool {
		return !namespaceExists(nodeA) && !namespaceExists(nodeB)
	}, "topology namespaces were not cleaned up")

	WaitUntil(t, 2*time.Second, func() bool {
		return !linkExists(hostA) && !linkExists(hostB)
	}, "topology host links were not cleaned up")
}

func TestTrafficHelpers(t *testing.T) {
	RequireRoot(t)

	top := NewTwoNode(t, "traffic", 70)
	AssertAllowed(t, top.NodeA.Namespace, top.NodeB.Namespace, top.NodeB.OverlayIP, 18080)
	// This negative path validates helper behavior before policy-map deny tests
	// land (MER-29+). It is routing-denied, not policy-denied.
	AssertDenied(t, top.NodeA.Namespace, top.NodeB.Namespace, "10.255.255.254", 18081)
}

func assertNamespaceExists(t *testing.T, ns string) {
	t.Helper()
	if !namespaceExists(ns) {
		t.Fatalf("namespace %q does not exist", ns)
	}
}

func assertLinkExists(t *testing.T, name string) {
	t.Helper()
	if !linkExists(name) {
		t.Fatalf("link %q does not exist", name)
	}
}

func assertLinkExistsInNS(t *testing.T, netns, link string) {
	t.Helper()
	out, err := exec.Command("ip", "netns", "exec", netns, "ip", "link", "show", "dev", link).CombinedOutput()
	if err != nil {
		t.Fatalf("link %q missing in ns %q: %v output=%s", link, netns, err, strings.TrimSpace(string(out)))
	}
}

func namespaceExists(ns string) bool {
	out, err := exec.Command("ip", "netns", "list").CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		name := strings.TrimSpace(line)
		if i := strings.IndexByte(name, ' '); i >= 0 {
			name = name[:i]
		}
		if name == ns {
			return true
		}
	}
	return false
}

func linkExists(name string) bool {
	return exec.Command("ip", "link", "show", "dev", name).Run() == nil
}
