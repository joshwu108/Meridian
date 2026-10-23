//go:build integration

package integration

// TestPolicyEnforcementGate_P8 is the Phase-8 exit gate for the whole
// enforcement chain: a policy created on the control plane's REST surface must
// change what the kernel actually does to a real TCP connection. Every hop is
// the shipped component — nothing is stubbed, and the assertions are on
// connect(2) outcomes, not on map contents:
//
//	rest.Server → store.Memory → ads.Server ──ADS/gRPC──▶ xds.Client
//	  → datapath.Writer → pinned policy_map → meridian_tc_ingress on lo
//
// Topology — loopback. 127.0.0.1 is the client identity, 127.0.0.2 the server
// identity (both covered by lo's 127.0.0.1/8; ensureLoopbackIdentityAddr adds
// a /32 via netlink only if that ever stops being true). The server listens on
// 127.0.0.2:9999 and the client dials it from a fixed source port.
//
// Three properties of the loopback datapath shape this test:
//
//  1. `lo` carries BOTH directions of a loopback conversation, so the server's
//     SYN-ACK is itself an ingress flow needing a verdict. The return path is
//     admitted once, up front, for each probe's client source port; it is never
//     touched again, so the only thing that changes between the allow and deny
//     probes is the forward verdict under test.
//
//  2. Each probe uses its own client source port, reserved at run time, making
//     the two attempts independent 4-tuples. The denied_flows_map corroboration
//     below can then key on the exact 5-tuple of the denied attempt rather than
//     on anything the allowed connection left behind. The ports are reserved
//     rather than hardcoded because a probe that connects leaves its source port
//     in TIME_WAIT for ~60 s, which would make the test unre-runnable.
//
//  3. `lo` is shared with the rest of the host, so the fail-open-unknown
//     posture (MERIDIAN_CFG_FALLOPEN_UNKNOWN) is seeded into the pinned
//     runtime_config_map BEFORE the program is attached — otherwise the window
//     between attach and the first ADS snapshot, where identity_map is still
//     empty, would drop every loopback packet on the box. That bit governs
//     identity MISSES only; it has no bearing on the explicit ALLOW/DENY
//     verdicts this gate asserts. Traffic between the two registered identities
//     is still fully default-deny.
//
// The control plane is driven in process and off the loopback datapath on
// purpose: the REST surface through its http.Handler, the ADS stream over an
// in-memory bufconn. A control plane reachable only over 127.0.0.1 would be
// subject to the very policy it is trying to install.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"

	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/supervisor"
	adsclient "github.com/joshuawu/meridian/internal/agent/xds"
	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/internal/control/rest"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	p8Iface    = "lo"
	p8ClientIP = "127.0.0.1"
	p8ServerIP = "127.0.0.2"

	p8ServerPort = 9999 // server listen port; the port the policy is written for

	p8ProtoTCP = uint8(syscall.IPPROTO_TCP)

	// MERIDIAN_CFG_FALLOPEN_UNKNOWN (bpf/include/meridian_consts.h).
	p8CfgFailOpenUnknown = uint32(1 << 0)

	// Budget for REST → store → ADS → agent → pinned map propagation. Generous
	// relative to the 500 ms CP-3/A-3 gates: this test asserts enforcement, and
	// MER-73 already owns the latency claim.
	p8Propagation = 5 * time.Second

	// A dropped SYN gives no RST, so the client retransmits until connect(2)
	// times out. Bound that wait ourselves rather than waiting out the kernel's
	// ~130 s SYN retry schedule.
	p8DialTimeout = 2 * time.Second
)

func TestPolicyEnforcementGate_P8(t *testing.T) {
	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}
	ctx := context.Background()
	pinDir := harness.PinDir(t)

	ensureLoopbackIdentityAddr(t, p8ServerIP)
	ensureLoopbackIdentityAddr(t, p8ClientIP)

	// Posture before attach — see note (3) in the file comment.
	seedFailOpenUnknown(t, pinDir)

	// Agent: the production supervisor loads tc_ingress against the pinned maps
	// and attaches it to lo. No PolicyFile: every identity and rule in this test
	// arrives through ADS, so the ADS client is the sole writer and the chain
	// under test has no YAML side door.
	runtime, err := supervisor.NewPolicyStartupRunner(supervisor.StartupOptions{
		PinDir:    pinDir,
		Interface: p8Iface,
	}).Startup(ctx)
	if err != nil {
		t.Fatalf("policy startup on %q: %v", p8Iface, err)
	}
	t.Cleanup(func() { _ = runtime.Close(context.Background()) })

	objs, err := runtime.TcIngressObjects()
	if err != nil {
		t.Fatalf("tc ingress objects: %v", err)
	}

	// Control plane, in process: REST handlers and the ADS server over one store.
	st := store.NewMemory()
	cp := rest.NewServer(st, identity.NewRegistry())

	clientID := p8CreateService(t, cp, "p8-client", "spiffe://p8/ns/test/sa/client", p8ClientIP)
	serverID := p8CreateService(t, cp, "p8-server", "spiffe://p8/ns/test/sa/server", p8ServerIP)
	if clientID == serverID {
		t.Fatalf("registry allocated the same ID %d to both services", clientID)
	}

	// Agent ADS client applying through the supervisor's writer into the pinned maps.
	conn := dialADS(t, st)
	agent := adsclient.NewClient(conn, runtime.Writer(), adsclient.WithLogf(func(string, ...any) {}))
	runCtx, cancel := context.WithCancel(ctx)
	t.Cleanup(cancel)
	go func() { _ = agent.Run(runCtx) }()

	harness.WaitUntil(t, p8Propagation, func() bool {
		return p8KernelIdentity(t, objs.IdentityMap, p8ClientIP) == clientID &&
			p8KernelIdentity(t, objs.IdentityMap, p8ServerIP) == serverID
	}, "ADS never applied both service identities into the kernel identity_map")

	// Return path, installed once — see notes (1) and (2) in the file comment.
	allowSrcPort := p8ReserveClientPort(t)
	denySrcPort := p8ReserveClientPort(t)
	if allowSrcPort == denySrcPort {
		t.Fatalf("reserved the same client source port %d for both probes", allowSrcPort)
	}
	for _, srcPort := range []uint16{allowSrcPort, denySrcPort} {
		p8PutPolicy(t, cp, p8Rule(serverID, clientID, srcPort, wire.PolicyActionAllow))
	}
	for _, srcPort := range []uint16{allowSrcPort, denySrcPort} {
		p8WaitKernelVerdict(t, objs.PolicyMap, p8Key(serverID, clientID, srcPort), wire.PolicyActionAllow,
			fmt.Sprintf("return-path ALLOW for server→client:%d never reached the kernel policy_map", srcPort))
	}

	listener, accepted := p8Listen(t, net.JoinHostPort(p8ServerIP, strconv.Itoa(p8ServerPort)))
	defer func() { _ = listener.Close() }()

	forwardKey := p8Key(clientID, serverID, p8ServerPort)

	// --- ALLOW: the policy admits the flow, so the connection must establish ---
	start := time.Now()
	p8PutPolicy(t, cp, p8Rule(clientID, serverID, p8ServerPort, wire.PolicyActionAllow))
	p8WaitKernelVerdict(t, objs.PolicyMap, forwardKey, wire.PolicyActionAllow,
		"ALLOW verdict never reached the kernel policy_map")
	t.Logf("REST→kernel ALLOW propagation: %v", time.Since(start))

	conn1, err := p8Dial(allowSrcPort)
	if err != nil {
		t.Fatalf("ALLOW verdict in the kernel policy_map did not admit the flow: dial %s:%d→%s:%d: %v",
			p8ClientIP, allowSrcPort, p8ServerIP, p8ServerPort, err)
	}
	p8AssertEcho(t, conn1)
	_ = conn1.Close()
	if n := accepted(); n != 1 {
		t.Fatalf("server accepted %d connections after the ALLOW probe, want 1", n)
	}

	// --- DENY: flip the same key's verdict; the same dial must now be dropped ---
	start = time.Now()
	p8PutPolicy(t, cp, p8Rule(clientID, serverID, p8ServerPort, wire.PolicyActionDeny))
	p8WaitKernelVerdict(t, objs.PolicyMap, forwardKey, wire.PolicyActionDeny,
		"DENY verdict never reached the kernel policy_map")
	t.Logf("REST→kernel DENY propagation: %v", time.Since(start))

	conn2, err := p8Dial(denySrcPort)
	if err == nil {
		_ = conn2.Close()
		t.Fatalf("DENY verdict in the kernel policy_map did not stop the flow: dial %s:%d→%s:%d succeeded",
			p8ClientIP, denySrcPort, p8ServerIP, p8ServerPort)
	}
	if !p8IsRefusedOrTimeout(err) {
		t.Fatalf("denied dial failed with an unexpected error (want connection refused or i/o timeout): %v", err)
	}
	if n := accepted(); n != 1 {
		t.Fatalf("server accepted %d connections in total, want 1 — the denied SYN reached the listener", n)
	}

	// Corroborate that the kernel dropped it for the policy reason, on the exact
	// 5-tuple of the denied probe, so the dial failure cannot be explained by
	// anything the allowed connection left behind.
	deniedKey := flowMapKey{
		SrcIP:   ipv4NetworkKey(t, p8ClientIP),
		DstIP:   ipv4NetworkKey(t, p8ServerIP),
		SrcPort: hostPortToFlowKey(denySrcPort),
		DstPort: hostPortToFlowKey(p8ServerPort),
		Proto:   p8ProtoTCP,
	}
	harness.WaitUntil(t, 3*time.Second, func() bool {
		var info denyInfo
		if err := objs.DeniedFlowsMap.Lookup(&deniedKey, &info); err != nil {
			return false
		}
		return info.Reason == dropReasonPolicyDeny && info.Count >= 1
	}, "denied_flows_map has no DROP_REASON_POLICY_DENY entry for the denied loopback 5-tuple")

	t.Logf("P8 PASS: REST policy flip ALLOW→DENY changed real TCP reachability %s→%s:%d via tc_ingress on %s",
		p8ClientIP, p8ServerIP, p8ServerPort, p8Iface)
}

// --- kernel map views -------------------------------------------------------

// p8PolicyMapKey mirrors struct policy_key (bpf/include/meridian_types.h) as
// datapath.translatePolicyRuleKey writes it: identity IDs and dst_port in host
// order, direction in the low byte. The test package is exempt from the
// wire↔bpf depguard rule, so it may read the kernel layout directly.
type p8PolicyMapKey struct {
	SrcID     uint32
	DstID     uint32
	DstPort   uint16
	Proto     uint8
	Direction uint8
}

// p8PolicyMapVerdict mirrors struct policy_verdict.
type p8PolicyMapVerdict struct {
	Action uint8
	Flags  uint8
	Pad    uint16
}

func p8Key(src, dst wire.IdentityID, dstPort uint16) p8PolicyMapKey {
	return p8PolicyMapKey{
		SrcID:     uint32(src),
		DstID:     uint32(dst),
		DstPort:   dstPort,
		Proto:     p8ProtoTCP,
		Direction: uint8(wire.DirectionIngress),
	}
}

func p8Rule(src, dst wire.IdentityID, dstPort uint16, action wire.PolicyAction) wire.PolicyRule {
	return wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: src,
			DstIdentity: dst,
			DstPort:     dstPort,
			Protocol:    p8ProtoTCP,
			Direction:   wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: action},
	}
}

func p8WaitKernelVerdict(t *testing.T, m *ebpf.Map, key p8PolicyMapKey, want wire.PolicyAction, msg string) {
	t.Helper()
	harness.WaitUntil(t, p8Propagation, func() bool {
		var verdict p8PolicyMapVerdict
		if err := m.Lookup(&key, &verdict); err != nil {
			return false
		}
		return verdict.Action == uint8(want)
	}, msg)
}

// p8KernelIdentity returns the identity_map value for ip, or IdentityUnknown
// when the key is absent.
func p8KernelIdentity(t *testing.T, m *ebpf.Map, ip string) wire.IdentityID {
	t.Helper()
	var id uint32
	key := ipv4NetworkKey(t, ip)
	if err := m.Lookup(&key, &id); err != nil {
		return wire.IdentityUnknown
	}
	return wire.IdentityID(id)
}

// seedFailOpenUnknown writes the fail-open-unknown bit into the pinned
// runtime_config_map before any program is attached. It pre-opens the pin set
// and closes it again; the pins survive (the restart-survival contract), so the
// supervisor's later load re-opens the same maps with the posture already set.
func seedFailOpenUnknown(t *testing.T, pinDir string) {
	t.Helper()
	objs, err := bpfobj.LoadTcIngress(pinDir)
	if err != nil {
		t.Fatalf("pre-open tc_ingress pin set: %v", err)
	}
	defer func() { _ = objs.Close() }()
	if err := objs.RuntimeConfigMap.Put(uint32(0), p8CfgFailOpenUnknown); err != nil {
		t.Fatalf("seed runtime_config_map fail-open-unknown: %v", err)
	}
}

// --- control-plane driving (in process, off the enforced datapath) ----------

func p8CreateService(t *testing.T, cp *rest.Server, name, spiffeID, podIPv4 string) wire.IdentityID {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"spiffeId":%q,"namespace":"p8","podIpv4":%q}`, name, spiffeID, podIPv4)
	rec := p8CallREST(t, cp, http.MethodPost, "/services", body, http.StatusCreated)

	var env struct{ Data wire.Identity }
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode POST /services response %q: %v", rec.Body.String(), err)
	}
	if env.Data.ID == wire.IdentityUnknown {
		t.Fatalf("POST /services allocated the reserved unknown identity for %q", name)
	}
	if env.Data.PodIPv4 != podIPv4 {
		t.Fatalf("POST /services stored podIpv4 %q, want %q", env.Data.PodIPv4, podIPv4)
	}
	return env.Data.ID
}

func p8PutPolicy(t *testing.T, cp *rest.Server, rule wire.PolicyRule) {
	t.Helper()
	body, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal policy rule: %v", err)
	}
	p8CallREST(t, cp, http.MethodPost, "/policies", string(body), http.StatusCreated)
}

func p8CallREST(t *testing.T, cp *rest.Server, method, path, body string, wantStatus int) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	cp.ServeHTTP(rec, req)
	if rec.Code != wantStatus {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, rec.Code, wantStatus, rec.Body.String())
	}
	return rec
}

// --- loopback data plane ----------------------------------------------------

// ensureLoopbackIdentityAddr makes ip a local address on lo. On Linux the
// 127.0.0.1/8 lo address already covers all of 127/8, in which case this is a
// no-op; the netlink /32 add is the fallback for a host configured otherwise.
func ensureLoopbackIdentityAddr(t *testing.T, ip string) {
	t.Helper()
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		t.Fatalf("parse loopback identity address %q: %v", ip, err)
	}
	link, err := netlink.LinkByName(p8Iface)
	if err != nil {
		t.Fatalf("link %q lookup: %v", p8Iface, err)
	}
	existing, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("list %q addresses: %v", p8Iface, err)
	}
	want := net.IP(addr.AsSlice())
	for _, have := range existing {
		if have.IPNet != nil && have.IPNet.Contains(want) {
			return
		}
	}
	add := &netlink.Addr{IPNet: &net.IPNet{IP: want, Mask: net.CIDRMask(32, 32)}}
	if err := netlink.AddrAdd(link, add); err != nil {
		t.Fatalf("add %s/32 to %q: %v", ip, p8Iface, err)
	}
	t.Cleanup(func() { _ = netlink.AddrDel(link, add) })
}

// p8Listen starts the "server" workload and returns the listener plus a
// snapshot function for how many connections it has accepted. Each accepted
// connection echoes one short read back, so the allowed probe can prove
// bidirectional data flow and not merely a completed handshake.
func p8Listen(t *testing.T, addr string) (net.Listener, func() int) {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}

	var mu sync.Mutex
	count := 0
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			mu.Lock()
			count++
			mu.Unlock()
			go func() {
				defer func() { _ = conn.Close() }()
				buf := make([]byte, 32)
				n, err := conn.Read(buf)
				if n > 0 && err == nil {
					_, _ = conn.Write(buf[:n])
				}
			}()
		}
	}()
	return ln, func() int {
		mu.Lock()
		defer mu.Unlock()
		return count
	}
}

// p8ReserveClientPort returns a currently-free TCP port on the client address.
// A listening socket that never accepted anything leaves no TIME_WAIT behind
// when closed, so this hands back a port that is immediately bindable — unlike
// a hardcoded one, which a prior run's successful probe may still be holding.
func p8ReserveClientPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(p8ClientIP, "0"))
	if err != nil {
		t.Fatalf("reserve a client source port on %s: %v", p8ClientIP, err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release reserved client source port %d: %v", port, err)
	}
	return uint16(port)
}

// p8Dial connects to the server from a fixed client source port so the flow's
// full 5-tuple — and therefore the policy keys covering both directions — is
// known in advance.
func p8Dial(srcPort uint16) (net.Conn, error) {
	dialer := net.Dialer{
		Timeout:   p8DialTimeout,
		LocalAddr: &net.TCPAddr{IP: net.ParseIP(p8ClientIP), Port: int(srcPort)},
	}
	return dialer.Dial("tcp", net.JoinHostPort(p8ServerIP, strconv.Itoa(p8ServerPort)))
}

func p8AssertEcho(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(p8DialTimeout)); err != nil {
		t.Fatalf("set echo deadline: %v", err)
	}
	const payload = "p8"
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write to allowed connection: %v", err)
	}
	buf := make([]byte, len(payload))
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read echo from allowed connection: %v", err)
	}
	if string(buf) != payload {
		t.Fatalf("echo = %q, want %q", buf, payload)
	}
}

// p8IsRefusedOrTimeout reports whether err is the shape a TC drop produces at
// the client: no RST means connect(2) times out, and ECONNREFUSED is accepted
// as the equivalent hard rejection.
func p8IsRefusedOrTimeout(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, context.DeadlineExceeded)
}
