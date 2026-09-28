//go:build integration

package integration

// TestTPROXYNetnsIsolation validates the ADR-0006 D-B claim that TPROXY rules
// and IP_TRANSPARENT listeners are netns-scoped: two "nodes" (netns) each run
// a TPROXY rule and a transparent listener on the SAME port (15008) without
// cross-talk (closes shortcoming #10 in orig_dest_test.go).
//
// Topology (root namespace is the client):
//
//	root netns ── veth A ──▶ node-A netns: TPROXY :8080 → :15008, listener A
//	           ── veth B ──▶ node-B netns: TPROXY :8080 → :15008, listener B
//
//	route 169.254.230.1/32 via veth A     route 169.254.231.1/32 via veth B
//
// Both TPROXY rules match ANY tcp dport 8080 (no dst filter) — the strongest
// form of the claim: only the namespace a packet enters may grab it.
//
// Assertions:
//  1. each listener receives only traffic routed into its own netns
//  2. no cross-talk between the two same-port TPROXY listeners
//  3. orig-dst recovered in each netns equals the address the client dialled

import (
	"context"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/vishvananda/netns"

	"github.com/joshuawu/meridian/internal/proxy"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	// Non-existent service addresses: reachable only via TPROXY redirection.
	isoServiceA  = "169.254.230.1"
	isoServiceB  = "169.254.231.1"
	isoSvcPort   = "8080"
	isoProxyPort = "15008" // deliberately identical in both netns
	isoMark      = "0x1"
	isoTable     = "142"
)

func TestTPROXYNetnsIsolation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux (netns + TPROXY)")
	}
	harness.RequireRoot(t)

	nodeA := harness.NewVethPair(t, "tpa", 216)
	nodeB := harness.NewVethPair(t, "tpb", 217)

	// Root-namespace routes: each service IP is reachable only through its
	// node's veth, so the packet enters exactly one namespace.
	addServiceRoute(t, isoServiceA, nodeA.PeerIP)
	addServiceRoute(t, isoServiceB, nodeB.PeerIP)

	// Identical TPROXY setup inside BOTH namespaces (the collision claim).
	// No cleanup needed: rules, routes, and iptables state die with the netns.
	for _, v := range []*harness.VethPair{nodeA, nodeB} {
		v.ExecInNS(t, "ip", "rule", "add", "fwmark", isoMark, "lookup", isoTable)
		v.ExecInNS(t, "ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", isoTable)
		v.ExecInNS(t, "iptables", "-t", "mangle", "-A", "PREROUTING",
			"-p", "tcp", "--dport", isoSvcPort,
			"-j", "TPROXY", "--tproxy-mark", isoMark, "--on-port", isoProxyPort)
	}

	lnA := listenTransparentInNS(t, nodeA.Netns, "0.0.0.0:"+isoProxyPort)
	lnB := listenTransparentInNS(t, nodeB.Netns, "0.0.0.0:"+isoProxyPort)
	evA := collectAccepts(t, lnA)
	evB := collectAccepts(t, lnB)

	// Dial service A: only listener A may see it, with A's orig-dst.
	dialService(t, isoServiceA+":"+isoSvcPort)
	assertReceived(t, "listener A", evA, isoServiceA+":"+isoSvcPort)
	assertQuiet(t, "listener B (traffic was for node A)", evB)

	// Dial service B: only listener B may see it, with B's orig-dst.
	dialService(t, isoServiceB+":"+isoSvcPort)
	assertReceived(t, "listener B", evB, isoServiceB+":"+isoSvcPort)
	assertQuiet(t, "listener A (traffic was for node B)", evA)

	t.Logf("netns isolation PASS: two TPROXY listeners on :%s, no cross-talk, orig-dst correct in both", isoProxyPort)
}

// addServiceRoute routes serviceIP/32 via the node's in-namespace veth address
// and registers removal (root-namespace state outlives the netns).
func addServiceRoute(t *testing.T, serviceIP, via string) {
	t.Helper()
	run(t, "ip", "route", "replace", serviceIP+"/32", "via", via)
	t.Cleanup(func() {
		_ = exec.Command("ip", "route", "del", serviceIP+"/32").Run()
	})
}

// listenTransparentInNS opens an IP_TRANSPARENT listener inside the named
// netns: it pins the goroutine to its OS thread, switches the thread's network
// namespace, listens, and switches back. The listener keeps working after the
// switch-back — a socket belongs to the namespace it was created in.
func listenTransparentInNS(t *testing.T, nsName, addr string) net.Listener {
	t.Helper()
	runtime.LockOSThread()
	locked := true
	defer func() {
		if locked {
			runtime.UnlockOSThread()
		}
	}()

	orig, err := netns.Get()
	if err != nil {
		t.Fatalf("get current netns: %v", err)
	}
	defer orig.Close()
	target, err := netns.GetFromName(nsName)
	if err != nil {
		t.Fatalf("get netns %q: %v", nsName, err)
	}
	defer target.Close()

	if err := netns.Set(target); err != nil {
		t.Fatalf("enter netns %q: %v", nsName, err)
	}
	ln, lnErr := proxy.ListenTransparent(context.Background(), addr)
	if err := netns.Set(orig); err != nil {
		// The thread is stuck in the wrong namespace. Leave it locked so
		// Goexit (t.Fatalf) terminates the OS thread instead of returning a
		// poisoned thread to the scheduler pool.
		locked = false
		t.Fatalf("return to original netns: %v", err)
	}
	if lnErr != nil {
		t.Fatalf("ListenTransparent in %q: %v", nsName, lnErr)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

type acceptEvent struct {
	origDst netip.AddrPort
	err     error
}

// collectAccepts drains ln, reporting each accepted connection's recovered
// original destination.
func collectAccepts(t *testing.T, ln net.Listener) <-chan acceptEvent {
	t.Helper()
	ch := make(chan acceptEvent, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			ap, err := proxy.OrigDstFromConn(conn)
			ch <- acceptEvent{origDst: ap, err: err}
			_ = conn.Close()
		}
	}()
	return ch
}

// dialService connects from the root namespace (the "client") and sends one
// byte. Connection errors are tolerated — the listener side closing first is
// expected; the assertions are on what the listeners observed.
func dialService(t *testing.T, addr string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v — TPROXY redirect did not fire", addr, err)
	}
	_, _ = conn.Write([]byte("x"))
	_ = conn.Close()
}

func assertReceived(t *testing.T, who string, ch <-chan acceptEvent, wantOrigDst string) {
	t.Helper()
	select {
	case ev := <-ch:
		if ev.err != nil {
			t.Fatalf("%s: OrigDstFromConn: %v", who, ev.err)
		}
		want := netip.MustParseAddrPort(wantOrigDst)
		if ev.origDst != want {
			t.Fatalf("%s: orig_dst = %s, want %s", who, ev.origDst, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s never accepted a connection — TPROXY redirect did not reach it", who)
	}
}

func assertQuiet(t *testing.T, who string, ch <-chan acceptEvent) {
	t.Helper()
	select {
	case ev := <-ch:
		t.Fatalf("CROSS-TALK: %s accepted a connection (orig_dst=%s, err=%v) for traffic routed to the other netns",
			who, ev.origDst, ev.err)
	case <-time.After(500 * time.Millisecond):
	}
}
