//go:build integration

package integration

// =============================================================================
// KNOWN LIMITATIONS — update this list as items are resolved
// =============================================================================
//
//  1. [SVID signing REST] RESOLVED (partial): POST /svid/sign REST endpoint implemented
//     (internal/control/rest/issuance.go). RemoteSigner client implemented
//     (internal/agent/svid/remote_signer.go). Not yet wired into the agent
//     startup loop — still using LocalSigner in meridian-agent binary.
//     Remaining: wire RemoteSigner in cmd/meridian-agent when --control-addr
//     flag is added; add mTLS dial to control plane in agent main loop.
//
//  2. [Workload API / go-spiffe] RESOLVED: full SPIFFE Workload API gRPC server
//     implemented with go-spiffe/v2 v2.7.0 (internal/agent/workloadapi/server.go);
//     X509Source-consumable, security header enforced.
//
//  3. [InboundHandler srcID] RESOLVED: SpiffeIDResolver seam implemented
//     (internal/proxy/spiffe_resolver.go). InboundHandler.WithSpiffeIDResolver
//     wires MapSpiffeIDResolver backed by the ADS identity snapshot. EvalPolicy
//     now receives the resolved srcID. Remaining: call resolver.Update() on
//     each ADS snapshot apply in the agent startup loop.
//
//  4. [MTLSDialer SNI] MTLSDialer sets ServerName = remote IP address.
//     Production deployments that use hostname-based certs (not SPIFFE) will
//     fail TLS verification. SPIFFE certs carry URI SANs, so IP-based SNI is
//     correct for SPIFFE — this is now documented on the MTLSDialer type
//     (internal/proxy/outbound.go): peer identity is verified against the URI
//     SAN, not DNS names, and no DNS resolution is required.
//
//  5. [Peer identity] RESOLVED: peer identity cross-check implemented via
//     WithOutboundSpiffeIDLookup and MapSpiffeIDResolver.LookupID
//     (internal/proxy/outbound.go); closes on mismatch, unknown dst proceeds.
//
//  6. [L7 enforcement] PARTIAL: L7 wire types (pkg/wire/l7.go) and MatchL7 matcher
//     (internal/proxy/l7_matcher.go, 14 tests) implemented. InboundHandler
//     does NOT yet call MatchL7 because HTTP framing (extract method/path from
//     raw stream) is deferred. Seam is ready: check PolicyFlagL7Required on
//     authz verdict and branch into MatchL7 before proxying bytes.
//     Exact seam: internal/proxy/inbound.go, the EvalPolicy call in
//     InboundHandler's authz step — marked there with
//     "// TODO(P8-L7): check PolicyFlagL7Required and call MatchL7 here".
//
//  7. [Circuit breaker] RESOLVED: per-upstream CB map implemented — WithCircuitBreaker
//     now takes a template, per-addr breakers via map[netip.Addr]*CircuitBreaker,
//     state exposed via CircuitStates(). Note: Prometheus gauge for per-upstream
//     CB state still pending.
//
//  8. [Tracing] RESOLVED: OTLP tracing implemented (internal/proxy/tracing.go:
//     NewTracerProvider, connSpan, injectTraceparent); noop unless
//     OTEL_EXPORTER_OTLP_ENDPOINT is set.
//
//  9. [TPROXY probe] internal/agent/tproxy/ProbeTPROXY cannot reliably
//     distinguish "module present, rule absent (iptables -C exit 1)" from
//     "module missing (modprobe fails)". The probe may report false negatives
//     on kernels where xt_TPROXY is built-in (not a loadable module).
//
// 10. [T3 netns isolation] RESOLVED: TestTPROXYNetnsIsolation
//     (tproxy_isolation_test.go) runs two netns, each with its own TPROXY
//     rule and IP_TRANSPARENT listener on the same :15008, and asserts no
//     cross-talk plus correct orig-dst in both — validating ADR-0006.
//     Runs and passes on Lima (T3); gate armed in test/gates/manifest.txt.
//
// 11. [CLI] RESOLVED: cmd/meridian implements status, policy list,
//     services list, cert inspect/verify/rotate, flows watch, map dump
//     subcommands. meridian cert rotate posts to the agent's /cert/rotate
//     admin endpoint, which calls SVIDManager.ForceRotate (bypassing the
//     2/3-TTL schedule; wired into cmd/meridian-agent startup via
//     admin.WithCertRotator). Remaining: meridian http watch (L7 trace
//     stream) and meridian doctor (probes TPROXY/BPF kernel features).
//
// 12. [K8s control plane] RESOLVED: etcd backend (internal/control/store/etcd.go),
//     K8s pod informer (internal/control/k8s/informers.go) and Helm chart
//     (deploy/helm/meridian/) were followed by Phase 7, which landed the
//     MeridianPolicy CRD + hand-written types and validating admission webhook
//     (internal/control/k8s/crd.go, deploy/helm/meridian/crds/meridianpolicy.yaml),
//     the dynamic-client PolicyWatcher informer (policy_informer.go), the
//     production PodResolver + webhook TLS mount + Helm webhook manifest, the
//     TokenReview bootstrap path (internal/control/ca/tokenreview.go,
//     bootstrap_rpc.go, cmd/meridian-agent/token_bootstrap.go), the etcd
//     integration test (test/integration/etcd_test.go) and the envtest K8s e2e
//     demo (test/e2e/k8s_demo_test.go).
//     See commits 5802fe4 (CRD/webhook/informer/TokenReview/BootstrapWithToken),
//     6092b1f (prod PodResolver, webhook TLS, Helm webhook) and 2c57c82
//     (agent-side BootstrapWithToken startup path).
//     Note: --webhook-addr and the ADS listener both default to :9443 — move one
//     when enabling webhook certs. Agent token bootstrap still dials the CA over
//     an insecure channel (tracked TODO in token_bootstrap.go).
//
// 13. [Control-plane mTLS wiring] RESOLVED: cmd/meridian-control now accepts
//     --tls-cert / --tls-key flags and wraps the gRPC server with
//     ServerTLSOption when they are provided. See cmd/meridian-control/main.go.
//
// 14. [Chaos/benchmarks] PARTIAL:
//     - Policy swap no-transient-deny test implemented (chaos_test.go).
//     - Agent restart pin-reopen test implemented (chaos_test.go).
//     - SOCKMAP eligibility verification implemented (chaos_test.go).
//     - Go benchmarks implemented (test/bench/): evaluator 7.6 ns/op,
//       L7 matcher 4.9 ns/op, CB 3.7 ns/op — all well within the performance targets.
//     - meridian doctor command implemented (internal/cli/doctor.go).
//     - Cert expiry chaos T1 variant implemented
//       (internal/agent/svid/expiry_chaos_test.go): fake-clock near-expiry
//       fail-closed, 2/3-TTL rotation, control-plane-down retry, and
//       make-before-break.
//     - Agent restart pin-reopen T1 seam variant implemented
//       (internal/agent/bpfobj/restart_test.go): re-open-not-recreate,
//       state survival, schema-mismatch and partial-pin-set fail-closed.
//     Remaining (MANUAL / needs dedicated infra):
//     - Network partition test (agent holds last-known-good for >10 min).
//     - Cert expiry chaos with live traffic (rotate CA mid-flight; ensure no
//       traffic drop — the T1 variant covers the manager, not the datapath).
//     - Ring-buffer drop rate benchmark at 1M pps (needs dedicated pinned host).
//     - RSS benchmark at 10k identities / 16k policies (dedicated host).
//     - Agent kill mid-connection survival (needs two-netns full proxy test;
//       the T1 seam variant covers pin re-open logic only).
//
// 15. [Workload API PEM protocol] RESOLVED: go-spiffe/v2 v2.7.0 is now a direct
//     dependency and internal/agent/workloadapi/server.go implements the full
//     SPIFFE Workload API gRPC server (FetchX509SVID / FetchX509Bundles streams,
//     security header enforced), so stock go-spiffe X509Source clients can
//     consume it. See also item 2.
//
// 16. [Binary wiring — RemoteSigner] cmd/meridian-agent SVID/proxy components
//     start correctly when --standalone or --control-addr+--bootstrap-cert are
//     given. The LocalSigner path (standalone) is fully functional. The
//     RemoteSigner path requires a running meridian-control with the CA
//     endpoint, which is now also wired (meridian-control --standalone starts
//     the CA). Remaining: end-to-end test of agent+control in Lima with the
//     new binary flags.
//
// 17. [SpiffeIDResolver update loop] RESOLVED: MapSpiffeIDResolver.Update()
//     is called via WithPostApply in the ADS client — fires after each ACKed
//     snapshot apply (cmd/meridian-agent/adswire.go).
//
// 18. [MeridianPolicy CRD] Kubernetes support requires a CRD for declarative policy in
//     Kubernetes. Needs controller-runtime or hand-written admission webhook.
//     Not started — deferred to a future milestone.
//
// =============================================================================

// TestOriginalDestinationGate_P41 is the TPROXY original-destination gate (ADR-0006):
// it proves that a TCP connection intercepted by TPROXY arrives at the proxy's
// IP_TRANSPARENT listener with the correct original destination address
// recoverable via getsockname() (conn.LocalAddr() in Go).
//
// Setup (no eBPF — TPROXY rules installed directly by the test):
//
//	pod netns  ─── veth ───  root netns
//	               │
//	               │  iptables mangle PREROUTING:
//	               │    TCP dst=SERVICE_IP:PORT → TPROXY mark=0x1 on-port=PROXY_PORT
//	               ▼
//	          ip rule fwmark 0x1 lookup 100
//	          ip route local 0.0.0.0/0 dev lo table 100
//	               │
//	               ▼
//	   ListenTransparent 0.0.0.0:PROXY_PORT (IP_TRANSPARENT)
//	               │
//	               └── conn.LocalAddr() == SERVICE_IP:PORT  ← assertion
//
// Gate: conn.LocalAddr() == intended service address (not the proxy's address).
// A failure means TPROXY/IP_TRANSPARENT is misconfigured.

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/joshuawu/meridian/internal/proxy"
	"github.com/joshuawu/meridian/test/harness"
)

const (
	// serviceIP is a link-local address that has no real host — deliberately
	// non-existent so the only way to reach it is via TPROXY redirection.
	serviceIP   = "169.254.201.1"
	servicePort = "8080"
	proxyPort   = "15041" // distinct port so this test doesn't clash with others
	tproxyMark  = "0x1"
	tproxyTable = "141"
)

func TestOriginalDestinationGate_P41(t *testing.T) {
	harness.RequireRoot(t)

	// Create the pod netns and a veth pair connecting it to the root namespace.
	// baseOctet 215 → underlay 169.254.215.x (disjoint from service IP range).
	v := harness.NewVethPair(t, "p41", 215)

	// Give the pod a route to the service IP via the root-namespace side of the
	// veth, so the pod's TCP SYN actually traverses the veth and hits iptables.
	run(t, "ip", "netns", "exec", v.Netns,
		"ip", "route", "add", serviceIP+"/32", "via", v.HostAddr)

	// Install TPROXY rules in the root namespace.
	// Step 1: ip rule — route fwmark packets to the local-delivery table.
	run(t, "ip", "rule", "add", "fwmark", tproxyMark, "lookup", tproxyTable)
	t.Cleanup(func() {
		_ = exec.Command("ip", "rule", "del",
			"fwmark", tproxyMark, "lookup", tproxyTable).Run()
	})

	// Step 2: local route — deliver locally (so TPROXY-redirected packets reach
	// the listener rather than being forwarded).
	run(t, "ip", "route", "add", "local", "0.0.0.0/0", "dev", "lo", "table", tproxyTable)
	t.Cleanup(func() {
		_ = exec.Command("ip", "route", "del", "local", "0.0.0.0/0",
			"dev", "lo", "table", tproxyTable).Run()
	})

	// Step 3: iptables mangle TPROXY — redirect TCP to serviceIP:servicePort to
	// the proxy's transparent listener. The TPROXY target simultaneously sets
	// the fwmark (picked up by ip rule above) and diverts the skb to the socket.
	run(t, "iptables", "-t", "mangle", "-A", "PREROUTING",
		"-p", "tcp",
		"-d", serviceIP, "--dport", servicePort,
		"-j", "TPROXY",
		"--tproxy-mark", tproxyMark,
		"--on-port", proxyPort)
	t.Cleanup(func() {
		_ = exec.Command("iptables", "-t", "mangle", "-D", "PREROUTING",
			"-p", "tcp",
			"-d", serviceIP, "--dport", servicePort,
			"-j", "TPROXY",
			"--tproxy-mark", tproxyMark,
			"--on-port", proxyPort).Run()
	})

	// Start the IP_TRANSPARENT listener — the proxy's transparent inbound port.
	ln, err := proxy.ListenTransparent(context.Background(), "0.0.0.0:"+proxyPort)
	if err != nil {
		t.Fatalf("ListenTransparent: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// Channel receives the orig dst the accepted connection reports.
	origDstCh := make(chan netip.AddrPort, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		ap, err := proxy.OrigDstFromConn(conn)
		if err != nil {
			t.Errorf("OrigDstFromConn: %v", err)
			return
		}
		origDstCh <- ap
		// Drain the connection so nc can exit cleanly.
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
	}()

	// Connect from inside the pod netns to the service address. `nc` exits
	// after sending stdin (empty here) and reading a response (or timeout).
	// -q 1 waits 1 s for a response then quits; -w 3 is the connect timeout.
	_, err = v.TryExecInNS(
		"sh", "-c",
		fmt.Sprintf("echo hi | nc -q 1 -w 3 %s %s", serviceIP, servicePort),
	)
	if err != nil {
		// nc returns non-zero if the server closes the connection first;
		// that is expected here — the proxy doesn't echo, just reads.
		// A genuine connection failure (ECONNREFUSED, EHOSTUNREACH) is a
		// different matter, but we can't easily distinguish — accept it if we
		// received the connection on our side.
	}

	// Wait for the proxy to accept and report the recovered original destination.
	var gotOrigDst netip.AddrPort
	select {
	case gotOrigDst = <-origDstCh:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy never accepted a connection — TPROXY redirect did not fire")
	}

	// Gate assertion (ADR-0006 testing requirement 1):
	// The recovered original destination MUST equal what the pod dialled.
	wantAddr := netip.MustParseAddrPort(serviceIP + ":" + servicePort)
	if gotOrigDst != wantAddr {
		t.Fatalf("orig_dst = %s, want %s\n"+
			"  If the proxy reports its own bound address instead of the service\n"+
			"  address, IP_TRANSPARENT is not set on the socket (check ListenTransparent)\n"+
			"  or the TPROXY rule was not matched.",
			gotOrigDst, wantAddr)
	}
	t.Logf("P4.1 gate PASS: proxy recovered orig_dst=%s correctly", gotOrigDst)
}

// run executes a host-namespace command, failing the test on non-zero exit.
func run(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s\n  err: %v\n  output: %s",
			name, fmt.Sprint(args), err, string(out))
	}
}

// Keep the net import referenced.
var _ net.Listener
