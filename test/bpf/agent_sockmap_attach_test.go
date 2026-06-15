//go:build bpf

package bpftest

import (
	"net"
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/internal/agent/attach"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/pkg/wire"
	"github.com/joshuawu/meridian/test/harness"
)

// TestAgentSockmapAttach_MER57 exercises the PRODUCTION attach path: the agent's
// bpfobj loaders (LoadSockOps/LoadSkMsg) plus the attach managers
// (CgroupSockOpsManager / SkMsgSockhashManager) that meridian-agent wires behind
// --cgroup. It proves the managers are idempotent and that, once they have
// attached sock_ops (cgroup) and sk_msg (sockhash), an eligible loopback flow is
// actually redirected — i.e. the production wiring reproduces the MER-48+MER-50
// behavior, not just "attach returned nil".
//
// Lives in test/bpf (run by `make test-bpf`) rather than internal/agent/attach,
// whose tests the gate runner does not execute; it reuses the shared sockops/
// skmsg harness (establishConns, readRedirects, currentCgroupV2Path).
func TestAgentSockmapAttach_MER57(t *testing.T) {
	const (
		clientIP = "127.0.0.1"
		serverIP = "127.0.0.2"
		idClient = 1001
		idServer = 2001
	)

	harness.RequireRoot(t)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatalf("remove memlock rlimit: %v", err)
	}
	pinDir := harness.PinDir(t)

	// Production loaders (depguard: agent code reaches bpf/ only via bpfobj).
	sockObjs, err := bpfobj.LoadSockOps(pinDir)
	if err != nil {
		t.Fatalf("bpfobj.LoadSockOps: %v", err)
	}
	t.Cleanup(func() { _ = sockObjs.Close() })
	skObjs, err := bpfobj.LoadSkMsg(pinDir)
	if err != nil {
		t.Fatalf("bpfobj.LoadSkMsg: %v", err)
	}
	t.Cleanup(func() { _ = skObjs.Close() })

	seedIdentity(t, sockObjs.IdentityMap, keyFromIPv4Wire(net.ParseIP(clientIP).To4()), idClient)
	seedIdentity(t, sockObjs.IdentityMap, keyFromIPv4Wire(net.ParseIP(serverIP).To4()), idServer)

	cgPath := currentCgroupV2Path(t)
	cgMgr := attach.NewCgroupSockOpsManager(sockObjs.MeridianSockOps)
	if err := cgMgr.EnsureAttached(cgPath); err != nil {
		t.Fatalf("cgroup EnsureAttached: %v", err)
	}
	if err := cgMgr.EnsureAttached(cgPath); err != nil {
		t.Fatalf("cgroup EnsureAttached not idempotent: %v", err)
	}
	t.Cleanup(func() { _ = cgMgr.Detach() })

	skMgr := attach.NewSkMsgSockhashManager(skObjs.MeridianSkMsg, skObjs.Sockhash.FD())
	if err := skMgr.EnsureAttached(); err != nil {
		t.Fatalf("sk_msg EnsureAttached: %v", err)
	}
	if err := skMgr.EnsureAttached(); err != nil {
		t.Fatalf("sk_msg EnsureAttached not idempotent: %v", err)
	}
	t.Cleanup(func() { _ = skMgr.Detach() })

	// Behavior: with the production managers attached, an eligible flow redirects.
	reader := metrics.NewMapReader(sockObjs.MetricsMap)
	before := readRedirects(t, reader)

	verdict := wire.PolicyVerdict{Action: wire.PolicyActionAllow, Flags: wire.PolicyFlagSockmapEligible}
	c, s, serverPort, clientPort, closeConn := establishConns(t, sockObjs, clientIP, serverIP, idClient, idServer, verdict)
	defer closeConn()

	if !waitKeyPresent(t, sockObjs.Sockhash, sockKeyFor(serverIP, serverPort)) ||
		!waitKeyPresent(t, sockObjs.Sockhash, sockKeyFor(clientIP, clientPort)) {
		t.Fatalf("eligible sockets absent from sockhash after manager attach")
	}

	payload := []byte("mer57-attach")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if got := readN(t, s, len(payload)); string(got) != string(payload) {
		t.Fatalf("server got %q, want %q", got, payload)
	}
	if after := waitRedirectsAbove(t, reader, before); after <= before {
		t.Fatalf("redirect counter flat after manager-driven attach (before=%d after=%d); attach path broken",
			before, after)
	}

	// Idempotent detach.
	if err := skMgr.Detach(); err != nil {
		t.Fatalf("sk_msg Detach: %v", err)
	}
	if err := skMgr.Detach(); err != nil {
		t.Fatalf("sk_msg Detach not idempotent: %v", err)
	}
	if err := cgMgr.Detach(); err != nil {
		t.Fatalf("cgroup Detach: %v", err)
	}
	if err := cgMgr.Detach(); err != nil {
		t.Fatalf("cgroup Detach not idempotent: %v", err)
	}
}
