//go:build bpf

package bpftest

import (
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/reference"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

// MER-48 (P2.1 core): sock_ops gated SOCKHASH population, the CC-5 insertion
// invariant (ADR-0007). The program attaches to the test's cgroup and, on TCP
// established, inserts a socket into `sockhash` ONLY when the flow's compiled
// policy_verdict is ALLOW carrying POLICY_FLAG_SOCKMAP_ELIGIBLE.
//
// This is the positive smoke (eligible flow present, DENY control absent). The
// exhaustive non-eligible matrix — L7-required, mTLS-required, REDIRECT,
// ALLOW-without-flag — is the permanent armed gate MER-49 (P2.1-N), not here.
//
// Distinct loopback IPs give the two ends distinct identities so the policy
// lookup is unambiguous: 127.0.0.1 = client (A), 127.0.0.2 = server (B).
func TestSockOpsGatedInsertion_MER48(t *testing.T) {
	const (
		clientIP = "127.0.0.1"
		serverIP = "127.0.0.2"
		idClient = 1001
		idServer = 2001
	)

	objs := loadSockOps(t)

	// Identities are flow-independent; seed once.
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(net.ParseIP(clientIP).To4()), idClient)
	seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(net.ParseIP(serverIP).To4()), idServer)

	cgPath := currentCgroupV2Path(t)
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: objs.MeridianSockOps,
	})
	if err != nil {
		t.Fatalf("attach sock_ops to cgroup %s: %v", cgPath, err)
	}
	t.Cleanup(func() { _ = l.Close() })

	eligible := wire.PolicyVerdict{
		Action: wire.PolicyActionAllow,
		Flags:  wire.PolicyFlagSockmapEligible,
	}
	deny := wire.PolicyVerdict{Action: wire.PolicyActionDeny}

	t.Run("eligible flow is inserted", func(t *testing.T) {
		serverPort, clientPort, closeConn := establish(t, objs, clientIP, serverIP, idClient, idServer, eligible)
		defer closeConn()

		// Passive (server) side: socket keyed by its own local addr 127.0.0.2:serverPort.
		if !waitKeyPresent(t, objs.Sockhash, sockKeyFor(serverIP, serverPort)) {
			t.Fatalf("eligible passive socket %s:%d absent from sockhash; gated insertion failed",
				serverIP, serverPort)
		}
		// Active (client) side: socket keyed by 127.0.0.1:clientPort. Exercises the
		// egress path + remote_port byte-order conversion.
		if !waitKeyPresent(t, objs.Sockhash, sockKeyFor(clientIP, clientPort)) {
			t.Fatalf("eligible active socket %s:%d absent from sockhash; gated insertion failed",
				clientIP, clientPort)
		}
	})

	t.Run("denied flow is not inserted", func(t *testing.T) {
		serverPort, _, closeConn := establish(t, objs, clientIP, serverIP, idClient, idServer, deny)
		defer closeConn()

		// Give any (erroneous) insertion time to land before asserting absence.
		time.Sleep(200 * time.Millisecond)
		if sockhashHasKey(t, objs.Sockhash, sockKeyFor(serverIP, serverPort)) {
			t.Fatalf("DENY socket %s:%d present in sockhash; CC-5 invariant violated",
				serverIP, serverPort)
		}
	})
}

// loadSockOps loads the sock_ops object with maps pinned under the test pin dir,
// sharing identity_map/policy_map/sockhash with the rest of the suite.
func loadSockOps(t *testing.T) *bpf.SockOpsObjects {
	t.Helper()
	bpfLoadMu.Lock()
	defer bpfLoadMu.Unlock()

	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	var objs bpf.SockOpsObjects
	if err := bpf.LoadSockOpsObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: harness.PinDir(t)},
	}); err != nil {
		t.Fatalf("load sock_ops objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return &objs
}

// establish seeds the policy for both directions of a (client→server) flow,
// then opens a real loopback TCP connection so the kernel fires the
// ACTIVE/PASSIVE established callbacks. Returns the negotiated ports and a
// closer that keeps both sockets alive until the caller is done inspecting.
func establish(t *testing.T, objs *bpf.SockOpsObjects, clientIP, serverIP string,
	idClient, idServer uint32, verdict wire.PolicyVerdict) (serverPort, clientPort int, closeConn func()) {
	t.Helper()

	ln, err := net.Listen("tcp", net.JoinHostPort(serverIP, "0"))
	if err != nil {
		t.Fatalf("listen %s: %v", serverIP, err)
	}
	serverPort = ln.Addr().(*net.TCPAddr).Port

	// The service port is the same on both ends of the flow; seed ingress
	// (server-side) and egress (client-side) so both sockets are eligible.
	for _, dir := range []uint8{reference.DirectionIngress, reference.DirectionEgress} {
		seedPolicy(t, objs.PolicyMap, reference.Rule{
			SrcIdentity: wire.IdentityID(idClient),
			DstIdentity: wire.IdentityID(idServer),
			DstPort:     uint16(serverPort),
			Protocol:    6,
			Direction:   dir,
			Verdict:     verdict,
		})
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr == nil {
			accepted <- c
		}
	}()

	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(clientIP)}}
	conn, err := d.Dial("tcp", net.JoinHostPort(serverIP, strconv.Itoa(serverPort)))
	if err != nil {
		_ = ln.Close()
		t.Fatalf("dial %s->%s:%d: %v", clientIP, serverIP, serverPort, err)
	}
	clientPort = conn.LocalAddr().(*net.TCPAddr).Port

	var srv net.Conn
	select {
	case srv = <-accepted:
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		_ = ln.Close()
		t.Fatal("server accept timed out")
	}

	return serverPort, clientPort, func() {
		_ = conn.Close()
		_ = srv.Close()
		_ = ln.Close()
	}
}

// sockKeyFor builds the sock_key the BPF program writes for a socket whose local
// address is ip:port — dst_ip and dst_port in network order, pad zero
// (ADR-0007). On a little-endian host this matches the kernel's in-memory key.
func sockKeyFor(ip string, port int) bpf.CounterSockKey {
	return bpf.CounterSockKey{
		DstIp:   keyFromIPv4Wire(net.ParseIP(ip).To4()),
		DstPort: hostToNet16(uint16(port)),
		Pad:     0,
	}
}

// hostToNet16 returns the uint16 whose native-endian marshaling (as ebpf encodes
// map keys) reproduces the network-order bytes of p — i.e. htons on a LE host.
func hostToNet16(p uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], p)
	return binary.NativeEndian.Uint16(b[:])
}

// waitKeyPresent polls for a key, tolerating the brief lag between the TCP
// handshake completing and the established callback running.
func waitKeyPresent(t *testing.T, m *ebpf.Map, want bpf.CounterSockKey) bool {
	t.Helper()
	for i := 0; i < 50; i++ {
		if sockhashHasKey(t, m, want) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// sockhashHasKey reports whether want is present, walking keys with NextKey only
// (SOCKHASH values are sockets and are not read here).
func sockhashHasKey(t *testing.T, m *ebpf.Map, want bpf.CounterSockKey) bool {
	t.Helper()
	var next bpf.CounterSockKey
	err := m.NextKey(nil, &next)
	for err == nil {
		if next == want {
			return true
		}
		cur := next
		err = m.NextKey(&cur, &next)
	}
	if !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("iterate sockhash: %v", err)
	}
	return false
}

// currentCgroupV2Path resolves the unified-hierarchy cgroup the test process is
// in, so attaching sock_ops there captures this process's own TCP connections.
func currentCgroupV2Path(t *testing.T) string {
	t.Helper()
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err != nil {
		t.Skipf("cgroup v2 unified hierarchy not mounted: %v", err)
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Fatalf("read /proc/self/cgroup: %v", err)
	}
	rel := "/"
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if strings.HasPrefix(line, "0::") {
			rel = strings.TrimPrefix(line, "0::")
			break
		}
	}
	p := filepath.Join("/sys/fs/cgroup", rel)
	if fi, err := os.Stat(p); err != nil || !fi.IsDir() {
		return "/sys/fs/cgroup"
	}
	return p
}
