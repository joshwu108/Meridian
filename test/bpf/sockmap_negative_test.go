//go:build bpf

package bpftest

import (
	"net"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/joshuawu/meridian/pkg/wire"
)

// TestSockmapNegativeGate_MER49 is the permanent P2.1-N gate (CC-5 / eBPF R2,
// ROADMAP top-risk #2): the kernel-side guard that a socket enters `sockhash`
// ONLY for a plain-L4 ALLOW carrying POLICY_FLAG_SOCKMAP_ELIGIBLE. For every
// other verdict class — DENY, ALLOW+L7_REQUIRED, ALLOW+MTLS_REQUIRED, REDIRECT,
// and ALLOW without the flag — a real established flow must leave `sockhash`
// untouched, or sk_msg (MER-50) could later redirect a socket that should have
// gone through mTLS / L7 / proxy / deny handling.
//
// The eligible control row asserts PRESENCE so the gate cannot pass trivially by
// never inserting anything. The test reuses the MER-48 sock_ops harness
// (loadSockOps / establish / currentCgroupV2Path / sockKeyFor / sockhashHasKey)
// and runs a real loopback connect per row. This test must never be deleted or
// skipped (manifest armed=yes); doing so re-opens CC-5.
func TestSockmapNegativeGate_MER49(t *testing.T) {
	const (
		clientIP = "127.0.0.1"
		serverIP = "127.0.0.2"
		idClient = 1001
		idServer = 2001
	)

	objs := loadSockOps(t)

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

	cases := []struct {
		name        string
		verdict     wire.PolicyVerdict
		wantPresent bool
	}{
		{"deny", wire.PolicyVerdict{Action: wire.PolicyActionDeny}, false},
		{"allow_l7_required", wire.PolicyVerdict{Action: wire.PolicyActionAllow, Flags: wire.PolicyFlagL7Required}, false},
		{"allow_mtls_required", wire.PolicyVerdict{Action: wire.PolicyActionAllow, Flags: wire.PolicyFlagMTLSRequired}, false},
		{"redirect_proxy", wire.PolicyVerdict{Action: wire.PolicyActionRedirectProxy}, false},
		{"allow_without_flag", wire.PolicyVerdict{Action: wire.PolicyActionAllow}, false},
		// Control: the only eligible class. Asserts presence so an always-absent
		// bug cannot make the negative rows pass for the wrong reason.
		{"allow_sockmap_eligible", wire.PolicyVerdict{Action: wire.PolicyActionAllow, Flags: wire.PolicyFlagSockmapEligible}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			serverPort, _, closeConn := establish(t, objs, clientIP, serverIP, idClient, idServer, tc.verdict)
			defer closeConn()

			key := sockKeyFor(serverIP, serverPort)

			if tc.wantPresent {
				if !waitKeyPresent(t, objs.Sockhash, key) {
					t.Fatalf("eligible control: server socket %s:%d absent from sockhash; gated insertion broken",
						serverIP, serverPort)
				}
				return
			}

			// Absence: let any erroneous insertion land before asserting it did not.
			time.Sleep(200 * time.Millisecond)
			if sockhashHasKey(t, objs.Sockhash, key) {
				t.Fatalf("non-eligible verdict %q: server socket %s:%d present in sockhash; CC-5 invariant violated",
					tc.name, serverIP, serverPort)
			}
		})
	}
}
