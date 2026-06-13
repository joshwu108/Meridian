package harness

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	geneveDeviceName = "gnv0"
	genevePort       = 6081
	geneveVNI        = 100
)

// TwoNode models the Phase 1 integration topology:
// - two virtual nodes (two netns)
// - two root<->node veth pairs (underlay)
// - node-to-node routing through the root namespace
// - a Geneve tunnel between node namespaces
//
// Topology for baseOctet=N:
//
//	root netns
//	  172.31.N.1/30 (HostVethA) ───── 172.31.N.2/30 (NodeA underlay)
//	  172.31.N+1.1/30 (HostVethB) ─── 172.31.N+1.2/30 (NodeB underlay)
//	                          route via root                  route via root
//	node-a ns ------------------------------------------------------------- node-b ns
//	    gnv0: 10.200.N.1/24 <======= Geneve VNI 100 / UDP 6081 =======> gnv0: 10.200.N.2/24
//
// All resources are per-run namespaced and cleaned up automatically.
type TwoNode struct {
	Name string

	NodeA Node
	NodeB Node

	HostVethA string
	HostVethB string

	t *testing.T
}

var (
	ipForwardMu       sync.Mutex
	ipForwardRefCount int
	ipForwardOriginal string
)

// Node describes one virtual node namespace in the TwoNode fixture.
type Node struct {
	Namespace string
	Veth      string

	UnderlayIP string
	OverlayIP  string
}

// NewTwoNode creates and wires a deterministic two-node topology.
// baseOctet must be <= 250 so baseOctet+1 remains valid.
func NewTwoNode(t *testing.T, name string, baseOctet byte) *TwoNode {
	t.Helper()
	if baseOctet > 250 {
		t.Fatalf("baseOctet must be <= 250 (got %d)", baseOctet)
	}

	sfx := shortSuffix(name)
	top := &TwoNode{
		Name:      name,
		HostVethA: "mha-" + sfx,
		HostVethB: "mhb-" + sfx,
		NodeA: Node{
			Namespace: fmt.Sprintf("%s%s-%s-a", NetnsPrefix, RunID(), name),
			Veth:      "nva-" + sfx,
			UnderlayIP: fmt.Sprintf("172.31.%d.2", baseOctet),
			OverlayIP:  fmt.Sprintf("10.200.%d.1", baseOctet),
		},
		NodeB: Node{
			Namespace: fmt.Sprintf("%s%s-%s-b", NetnsPrefix, RunID(), name),
			Veth:      "nvb-" + sfx,
			UnderlayIP: fmt.Sprintf("172.31.%d.2", baseOctet+1),
			OverlayIP:  fmt.Sprintf("10.200.%d.2", baseOctet),
		},
		t: t,
	}

	t.Cleanup(top.Close)
	top.setup(baseOctet)
	return top
}

func (t2 *TwoNode) setup(baseOctet byte) {
	t2.t.Helper()

	hostAUnderlay := fmt.Sprintf("172.31.%d.1", baseOctet)
	hostBUnderlay := fmt.Sprintf("172.31.%d.1", baseOctet+1)

	// Namespaces.
	t2.run("ip", "netns", "add", t2.NodeA.Namespace)
	t2.run("ip", "netns", "add", t2.NodeB.Namespace)

	// Underlay links: root <-> node A.
	t2.run("ip", "link", "add", t2.HostVethA, "type", "veth", "peer", "name", t2.NodeA.Veth)
	t2.run("ip", "link", "set", t2.NodeA.Veth, "netns", t2.NodeA.Namespace)
	t2.run("ip", "addr", "add", hostAUnderlay+"/30", "dev", t2.HostVethA)
	t2.run("ip", "link", "set", t2.HostVethA, "up")
	t2.runIn(t2.NodeA.Namespace, "ip", "addr", "add", t2.NodeA.UnderlayIP+"/30", "dev", t2.NodeA.Veth)
	t2.runIn(t2.NodeA.Namespace, "ip", "link", "set", t2.NodeA.Veth, "up")
	t2.runIn(t2.NodeA.Namespace, "ip", "link", "set", "lo", "up")

	// Underlay links: root <-> node B.
	t2.run("ip", "link", "add", t2.HostVethB, "type", "veth", "peer", "name", t2.NodeB.Veth)
	t2.run("ip", "link", "set", t2.NodeB.Veth, "netns", t2.NodeB.Namespace)
	t2.run("ip", "addr", "add", hostBUnderlay+"/30", "dev", t2.HostVethB)
	t2.run("ip", "link", "set", t2.HostVethB, "up")
	t2.runIn(t2.NodeB.Namespace, "ip", "addr", "add", t2.NodeB.UnderlayIP+"/30", "dev", t2.NodeB.Veth)
	t2.runIn(t2.NodeB.Namespace, "ip", "link", "set", t2.NodeB.Veth, "up")
	t2.runIn(t2.NodeB.Namespace, "ip", "link", "set", "lo", "up")

	// Routing between nodes through root namespace.
	t2.enableIPForwarding()
	t2.runIn(t2.NodeA.Namespace, "ip", "route", "replace", t2.NodeB.UnderlayIP+"/32", "via", hostAUnderlay, "dev", t2.NodeA.Veth)
	t2.runIn(t2.NodeB.Namespace, "ip", "route", "replace", t2.NodeA.UnderlayIP+"/32", "via", hostBUnderlay, "dev", t2.NodeB.Veth)

	// Geneve tunnel.
	t2.runIn(t2.NodeA.Namespace, "ip", "link", "add", geneveDeviceName, "type", "geneve",
		"id", strconv.Itoa(geneveVNI),
		"remote", t2.NodeB.UnderlayIP,
		"local", t2.NodeA.UnderlayIP,
		"dstport", strconv.Itoa(genevePort))
	t2.runIn(t2.NodeB.Namespace, "ip", "link", "add", geneveDeviceName, "type", "geneve",
		"id", strconv.Itoa(geneveVNI),
		"remote", t2.NodeA.UnderlayIP,
		"local", t2.NodeB.UnderlayIP,
		"dstport", strconv.Itoa(genevePort))
	t2.runIn(t2.NodeA.Namespace, "ip", "addr", "add", t2.NodeA.OverlayIP+"/24", "dev", geneveDeviceName)
	t2.runIn(t2.NodeB.Namespace, "ip", "addr", "add", t2.NodeB.OverlayIP+"/24", "dev", geneveDeviceName)
	t2.runIn(t2.NodeA.Namespace, "ip", "link", "set", geneveDeviceName, "up")
	t2.runIn(t2.NodeB.Namespace, "ip", "link", "set", geneveDeviceName, "up")

	// Explicit host routes over Geneve for deterministic pathing.
	t2.runIn(t2.NodeA.Namespace, "ip", "route", "replace", t2.NodeB.OverlayIP+"/32", "dev", geneveDeviceName)
	t2.runIn(t2.NodeB.Namespace, "ip", "route", "replace", t2.NodeA.OverlayIP+"/32", "dev", geneveDeviceName)
}

// ExecInNode runs a command in the selected node namespace and fails the test
// on non-zero exit.
func (t2 *TwoNode) ExecInNode(t *testing.T, node Node, cmd ...string) string {
	t.Helper()
	full := append([]string{"netns", "exec", node.Namespace}, cmd...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	if err != nil {
		t.Fatalf("ExecInNode failed: ip %s\n  err: %v\n  output: %s",
			strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out)
}

// TryExecInNode runs a command in the selected node namespace and returns the
// output and error without failing the test.
func (t2 *TwoNode) TryExecInNode(node Node, cmd ...string) (string, error) {
	full := append([]string{"netns", "exec", node.Namespace}, cmd...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	return string(out), err
}

// AssertAllowed asserts a TCP connect from src namespace to dstIP:port
// succeeds. It starts an nc listener in dst namespace and waits via WaitUntil
// (no sleeps).
func AssertAllowed(t *testing.T, srcNS, dstNS, dstIP string, port int) {
	t.Helper()
	stop := startNetcatListener(t, dstNS, port)
	defer stop()

	waitForListenerReady(t, dstNS, port)
	WaitUntil(t, 3*time.Second, func() bool {
		_, err := tryConnect(srcNS, dstIP, port)
		return err == nil
	}, fmt.Sprintf("expected connect to succeed: src=%s dst=%s:%d", srcNS, dstIP, port))
}

// AssertDenied asserts a TCP connect from src namespace to dstIP:port fails.
// It verifies listener readiness first so failures are not listener-start races.
// (Whether a failure is routing-level or policy-level is determined by caller
// topology and policy setup.)
func AssertDenied(t *testing.T, srcNS, dstNS, dstIP string, port int) {
	t.Helper()
	stop := startNetcatListener(t, dstNS, port)
	defer stop()

	waitForListenerReady(t, dstNS, port)
	WaitUntil(t, 3*time.Second, func() bool {
		_, err := tryConnect(srcNS, dstIP, port)
		return err != nil
	}, fmt.Sprintf("expected connect to fail: src=%s dst=%s:%d", srcNS, dstIP, port))
}

func waitForListenerReady(t *testing.T, netns string, port int) {
	t.Helper()
	WaitUntil(t, 2*time.Second, func() bool {
		_, err := tryConnect(netns, "127.0.0.1", port)
		return err == nil
	}, fmt.Sprintf("nc listener in %s never became ready on port %d", netns, port))
}

func tryConnect(netns, ip string, port int) (string, error) {
	args := []string{
		"netns", "exec", netns,
		"nc", "-z", "-w", "1", ip, strconv.Itoa(port),
	}
	out, err := exec.Command("ip", args...).CombinedOutput()
	return string(out), err
}

func startNetcatListener(t *testing.T, netns string, port int) func() {
	t.Helper()
	// Loop to keep a listener present across retries from WaitUntil.
	cmd := exec.Command("ip", "netns", "exec", netns, "sh", "-c",
		fmt.Sprintf("while true; do nc -l -p %d >/dev/null 2>&1 || true; done", port))
	if err := cmd.Start(); err != nil {
		t.Fatalf("start listener failed (netns=%s, port=%d): %v", netns, port, err)
	}
	return func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}
}

// Close tears down the two-node fixture. Best-effort and idempotent.
func (t2 *TwoNode) Close() {
	_ = exec.Command("ip", "netns", "del", t2.NodeA.Namespace).Run()
	_ = exec.Command("ip", "netns", "del", t2.NodeB.Namespace).Run()
	_ = exec.Command("ip", "link", "del", t2.HostVethA).Run()
	_ = exec.Command("ip", "link", "del", t2.HostVethB).Run()
	t2.restoreIPForwarding()
}

func (t2 *TwoNode) run(name string, args ...string) {
	t2.t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t2.t.Fatalf("command failed: %s %s\n  err: %v\n  output: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

func (t2 *TwoNode) runIn(netns, name string, args ...string) {
	t2.t.Helper()
	full := append([]string{"netns", "exec", netns, name}, args...)
	out, err := exec.Command("ip", full...).CombinedOutput()
	if err != nil {
		t2.t.Fatalf("command failed: ip %s\n  err: %v\n  output: %s",
			strings.Join(full, " "), err, strings.TrimSpace(string(out)))
	}
}

func shortSuffix(name string) string {
	clean := sanitizeName(name)
	if len(clean) > 5 {
		clean = clean[:5]
	}
	run := RunID()
	if len(run) > 3 {
		run = run[len(run)-3:]
	}
	s := clean + run
	if len(s) > 8 {
		return s[:8]
	}
	return s
}

func (t2 *TwoNode) enableIPForwarding() {
	t2.t.Helper()

	ipForwardMu.Lock()
	defer ipForwardMu.Unlock()

	const path = "/proc/sys/net/ipv4/ip_forward"
	if ipForwardRefCount == 0 {
		current, err := os.ReadFile(path)
		if err != nil {
			t2.t.Fatalf("read %s: %v", path, err)
		}
		ipForwardOriginal = strings.TrimSpace(string(current))
		if ipForwardOriginal != "1" {
			if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
				t2.t.Fatalf("enable ip_forward: %v", err)
			}
		}
	}
	ipForwardRefCount++
}

func (t2 *TwoNode) restoreIPForwarding() {
	ipForwardMu.Lock()
	defer ipForwardMu.Unlock()

	if ipForwardRefCount == 0 {
		return
	}
	ipForwardRefCount--
	if ipForwardRefCount != 0 {
		return
	}
	if ipForwardOriginal == "" || ipForwardOriginal == "1" {
		return
	}
	_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(ipForwardOriginal+"\n"), 0o644)
}
