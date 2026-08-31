//go:build integration

package integration

// =============================================================================
// KNOWN SHORTCOMINGS — update this list as items are resolved
// =============================================================================
//
//  1. [PKI-3] RESOLVED (partial): POST /svid/sign REST endpoint implemented
//     (internal/control/rest/issuance.go). RemoteSigner client implemented
//     (internal/agent/svid/remote_signer.go). Not yet wired into the agent
//     startup loop — still using LocalSigner in meridian-agent binary.
//     Remaining: wire RemoteSigner in cmd/meridian-agent when --control-addr
//     flag is added; add mTLS dial to control plane in agent main loop.
//
//  2. [PKI-4 / go-spiffe] workloadapi.socketServer uses a custom PEM wire
//     protocol, not the SPIFFE Workload API gRPC spec. go-spiffe's X509Source
//     cannot consume it. The full gRPC server requires go-spiffe/v2 as a dep
//     (not yet in go.mod — no protoc toolchain; planned for Phase 4 polish).
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
//     correct for SPIFFE — but this should be documented and verified against
//     the peer's URI SAN, not DNS names.
//
//  5. [P4.4 peer identity] PARTIAL: OutboundHandler now calls SPIFFEIDFromCert
//     on the remote proxy's cert and logs the peer SPIFFE ID. However it does
//     not yet cross-check against the expected dst_identity (numeric ID → SPIFFE
//     URI lookup requires a reverse-lookup in the identity table). Add
//     SpiffeIDResolver.LookupID(dstID) → spiffeURI and compare post-handshake.
//
//  6. [P5.1] PARTIAL: L7 wire types (pkg/wire/l7.go) and MatchL7 matcher
//     (internal/proxy/l7_matcher.go, 14 tests) implemented. InboundHandler
//     does NOT yet call MatchL7 because HTTP framing (extract method/path from
//     raw stream) is deferred. Seam is ready: check PolicyFlagL7Required on
//     authz verdict and branch into MatchL7 before proxying bytes.
//
//  7. [P5.2] RESOLVED: CircuitBreaker implemented (internal/proxy/circuit_breaker.go,
//     9 tests, clock-injectable). Wired into OutboundHandler via
//     WithCircuitBreaker option. Remaining: expose per-upstream CB state as
//     Prometheus gauge and wire a per-upstream CB map (currently one global CB
//     is supported; needs map[netip.Addr]*CircuitBreaker for multi-upstream).
//
//  8. [P5.3] NOT STARTED: OTLP spans require go.opentelemetry.io/otel which
//     is not in go.mod. Per-request traces (src_identity, dst_identity,
//     latency, status, W3C traceparent propagation) deferred to Phase 5 polish.
//     Add once the otel dep is provisioned. Prometheus counters/histograms can
//     be added sooner (prometheus/client_golang already in go.mod).
//
//  9. [TPROXY probe] internal/agent/tproxy/ProbeTPROXY cannot reliably
//     distinguish "module present, rule absent (iptables -C exit 1)" from
//     "module missing (modprobe fails)". The probe may report false negatives
//     on kernels where xt_TPROXY is built-in (not a loadable module).
//
// 10. [T3 netns isolation] TestOriginalDestinationGate_P41 runs a single
//     TPROXY listener in the root namespace. ADR-0006 D-B claims rules are
//     netns-scoped so two nodes can run colliding :15001/:15008 listeners
//     without cross-talk. That claim is not yet validated by a T3 test.
//     A two-netns variant of this test should be added (similar to
//     test/harness/TwoNode topology) to arm the netns-isolation gate.
//
// 11. [Phase 6 CLI] RESOLVED: cmd/meridian implements status, policy list,
//     services list, cert inspect/verify, flows watch, map dump subcommands.
//     Remaining: meridian http watch (L7 trace stream, Phase 5), meridian doctor
//     (probes TPROXY/BPF kernel features, Phase 8), meridian cert rotate
//     (triggers RemoteSigner rotation RPC, PKI-3 completion).
//
// 12. [Phase 7 — K8s] PARTIAL: etcd backend implemented
//     (internal/control/store/etcd.go), K8s pod informer implemented
//     (internal/control/k8s/informers.go, tested with fake clientset),
//     Helm chart skeleton created (deploy/helm/meridian/).
//     Remaining: MeridianPolicy CRD (needs controller-runtime or code-gen),
//     TokenReview bootstrap PKI-2b (SVID issuance using projected SA tokens),
//     K8s e2e demo test (Kind cluster or envtest), etcd integration test.
//
// 13. [Phase 7 — CP-4 mTLS wiring] RESOLVED: cmd/meridian-control now accepts
//     --tls-cert / --tls-key flags and wraps the gRPC server with
//     ServerTLSOption when they are provided. See cmd/meridian-control/main.go.
//
// 14. [Phase 8 — Chaos/benchmarks] PARTIAL:
//     - Policy swap no-transient-deny test implemented (chaos_test.go).
//     - Agent restart pin-reopen test implemented (chaos_test.go).
//     - SOCKMAP eligibility verification implemented (chaos_test.go).
//     - Go benchmarks implemented (test/bench/): evaluator 7.6 ns/op,
//       L7 matcher 4.9 ns/op, CB 3.7 ns/op — all well within PRD NFRs.
//     - meridian doctor command implemented (internal/cli/doctor.go).
//     Remaining (MANUAL / needs dedicated infra):
//     - Network partition test (agent holds last-known-good for >10 min).
//     - Cert expiry chaos (rotate CA mid-flight; ensure no traffic drop).
//     - Ring-buffer drop rate benchmark at 1M pps (needs dedicated pinned host).
//     - RSS benchmark at 10k identities / 16k policies (dedicated host).
//     - Agent kill mid-connection survival (needs two-netns full proxy test).
//
// 15. [PKI-4 / go-spiffe] UNCHANGED: workloadapi.socketServer custom PEM
//     protocol cannot be consumed by go-spiffe X509Source. Full SPIFFE
//     Workload API gRPC needs go-spiffe/v2 in go.mod (no protoc required —
//     pre-compiled stubs ship with the module). Add to go.mod, replace
//     socketServer with the gRPC impl when the dep is provisioned.
//
// 16. [Binary wiring — RemoteSigner] cmd/meridian-agent Phase 4 components
//     start correctly when --standalone or --control-addr+--bootstrap-cert are
//     given. The LocalSigner path (standalone) is fully functional. The
//     RemoteSigner path requires a running meridian-control with the CA
//     endpoint, which is now also wired (meridian-control --standalone starts
//     the CA). Remaining: end-to-end test of agent+control in Lima with the
//     new binary flags.
//
// 17. [SpiffeIDResolver update loop] MapSpiffeIDResolver.Update() is not yet
//     called on each ADS snapshot apply in the agent startup loop. The seam
//     is ready; the agent's xds.Client needs a post-apply callback that calls
//     spiffeResolver.Update(identities) after each ACKed snapshot.
//
// 18. [MeridianPolicy CRD] Phase 7 requires a CRD for declarative policy in
//     Kubernetes. Needs controller-runtime or hand-written admission webhook.
//     Not started — deferred to a future milestone.
//
// =============================================================================

// TestOriginalDestinationGate_P41 is the CC-1 Phase-4 entry gate (ADR-0006):
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

// run is a test-fatal command runner that delegates to ExecInNS semantics for
// host commands (not inside a namespace).
func run(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s\n  err: %v\n  output: %s",
			name, fmt.Sprint(args), err, string(out))
	}
}

// Ensure net is imported (used by conn type assertion in OrigDstFromConn).
var _ net.Listener
