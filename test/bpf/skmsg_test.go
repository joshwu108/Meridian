//go:build bpf

package bpftest

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/internal/reference"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

// TestSkMsgRedirect_MER50 proves the sk_msg SOCKHASH redirect fast path
// (ADR-0007): a sendmsg on an eligible flow — whose sockets sock_ops inserted
// into `sockhash` — is redirected to the peer (METRIC_FLOWS_REDIRECTED bumps and
// the bytes arrive), while a non-eligible flow (absent from sockhash) falls
// through the normal kernel path and never touches the redirect counter.
//
// sock_ops (writer, cgroup-attached) populates sockhash; sk_msg (reader,
// attached to the sockhash map with BPF_SK_MSG_VERDICT) consumes it. Both share
// the same pinned maps via the per-test PinDir.
func TestSkMsgRedirect_MER50(t *testing.T) {
	const (
		clientIP = "127.0.0.1"
		serverIP = "127.0.0.2"
		idClient = 1001
		idServer = 2001
	)

	pinDir := harness.PinDir(t)
	sockObjs := loadSockOps(t)
	skObjs := loadSkMsg(t, pinDir)

	seedIdentity(t, sockObjs.IdentityMap, keyFromIPv4Wire(net.ParseIP(clientIP).To4()), idClient)
	seedIdentity(t, sockObjs.IdentityMap, keyFromIPv4Wire(net.ParseIP(serverIP).To4()), idServer)

	cgPath := currentCgroupV2Path(t)
	cg, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: sockObjs.MeridianSockOps,
	})
	if err != nil {
		t.Fatalf("attach sock_ops to cgroup %s: %v", cgPath, err)
	}
	t.Cleanup(func() { _ = cg.Close() })

	skTarget := skObjs.Sockhash.FD()
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  skTarget,
		Program: skObjs.MeridianSkMsg,
		Attach:  ebpf.AttachSkMsgVerdict,
	}); err != nil {
		t.Fatalf("attach sk_msg to sockhash: %v", err)
	}
	t.Cleanup(func() {
		_ = link.RawDetachProgram(link.RawDetachProgramOptions{
			Target:  skTarget,
			Program: skObjs.MeridianSkMsg,
			Attach:  ebpf.AttachSkMsgVerdict,
		})
	})

	reader := metrics.NewMapReader(sockObjs.MetricsMap)

	t.Run("eligible flow is redirected", func(t *testing.T) {
		before := readRedirects(t, reader)

		verdict := wire.PolicyVerdict{Action: wire.PolicyActionAllow, Flags: wire.PolicyFlagSockmapEligible}
		c, s, serverPort, clientPort, closeFn := establishConns(t, sockObjs, clientIP, serverIP, idClient, idServer, verdict)
		defer closeFn()

		// Both sockets must be sockhash members before their sends are intercepted.
		if !waitKeyPresent(t, sockObjs.Sockhash, sockKeyFor(serverIP, serverPort)) ||
			!waitKeyPresent(t, sockObjs.Sockhash, sockKeyFor(clientIP, clientPort)) {
			t.Fatalf("eligible sockets absent from sockhash (server %s:%d / client %s:%d)",
				serverIP, serverPort, clientIP, clientPort)
		}

		payload := []byte("meridian-mer50")
		if _, err := c.Write(payload); err != nil {
			t.Fatalf("client write: %v", err)
		}
		if got := readN(t, s, len(payload)); string(got) != string(payload) {
			t.Fatalf("server got %q, want %q", got, payload)
		}
		if after := waitRedirectsAbove(t, reader, before); after <= before {
			t.Fatalf("METRIC_FLOWS_REDIRECTED did not increase (before=%d after=%d); redirect path did not run",
				before, after)
		}
	})

	t.Run("non-eligible flow falls through", func(t *testing.T) {
		before := readRedirects(t, reader)

		verdict := wire.PolicyVerdict{Action: wire.PolicyActionAllow} // no SOCKMAP_ELIGIBLE
		c, s, serverPort, _, closeFn := establishConns(t, sockObjs, clientIP, serverIP, idClient, idServer, verdict)
		defer closeFn()

		// MER-49 proves non-eligible never enters sockhash; reconfirm here so the
		// fall-through assertion is unambiguous.
		time.Sleep(200 * time.Millisecond)
		if sockhashHasKey(t, sockObjs.Sockhash, sockKeyFor(serverIP, serverPort)) {
			t.Fatalf("non-eligible server socket %s:%d unexpectedly in sockhash", serverIP, serverPort)
		}

		payload := []byte("normal-path")
		if _, err := c.Write(payload); err != nil {
			t.Fatalf("client write: %v", err)
		}
		if got := readN(t, s, len(payload)); string(got) != string(payload) {
			t.Fatalf("server got %q, want %q", got, payload)
		}
		// Let any stray redirect land, then assert the counter did not move.
		time.Sleep(200 * time.Millisecond)
		if after := readRedirects(t, reader); after != before {
			t.Fatalf("METRIC_FLOWS_REDIRECTED moved on a non-eligible flow (before=%d after=%d); SK_PASS fall-through broken",
				before, after)
		}
	})
}

func loadSkMsg(t *testing.T, pinDir string) *bpf.SkMsgObjects {
	t.Helper()
	bpfLoadMu.Lock()
	defer bpfLoadMu.Unlock()

	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}

	var objs bpf.SkMsgObjects
	if err := bpf.LoadSkMsgObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{PinPath: pinDir},
	}); err != nil {
		t.Fatalf("load sk_msg objects: %v", err)
	}
	t.Cleanup(func() { _ = objs.Close() })
	return &objs
}

// establishConns opens a real loopback TCP connection (seeding both directions
// of the policy first) and returns the live client/server conns so the caller
// can drive sendmsg through the attached sk_msg program. Unlike establish (MER-48)
// it exposes the conns rather than only a closer.
func establishConns(t *testing.T, objs *bpf.SockOpsObjects, clientIP, serverIP string,
	idClient, idServer uint32, verdict wire.PolicyVerdict) (client, server net.Conn, serverPort, clientPort int, closeFn func()) {
	t.Helper()

	ln, err := net.Listen("tcp", net.JoinHostPort(serverIP, "0"))
	if err != nil {
		t.Fatalf("listen %s: %v", serverIP, err)
	}
	serverPort = ln.Addr().(*net.TCPAddr).Port

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

	select {
	case server = <-accepted:
	case <-time.After(2 * time.Second):
		_ = conn.Close()
		_ = ln.Close()
		t.Fatal("server accept timed out")
	}

	return conn, server, serverPort, clientPort, func() {
		_ = conn.Close()
		_ = server.Close()
		_ = ln.Close()
	}
}

func readN(t *testing.T, c net.Conn, n int) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, n)
	got, err := io.ReadFull(c, buf)
	if err != nil {
		t.Fatalf("server read: %v (got %d/%d)", err, got, n)
	}
	return buf[:got]
}

func readRedirects(t *testing.T, r *metrics.MapReader) uint64 {
	t.Helper()
	v, err := r.Read(metrics.MetricFlowsRedirected)
	if err != nil {
		t.Fatalf("read METRIC_FLOWS_REDIRECTED: %v", err)
	}
	return v
}

func waitRedirectsAbove(t *testing.T, r *metrics.MapReader, base uint64) uint64 {
	t.Helper()
	var v uint64
	for i := 0; i < 50; i++ {
		if v = readRedirects(t, r); v > base {
			return v
		}
		time.Sleep(10 * time.Millisecond)
	}
	return v
}
