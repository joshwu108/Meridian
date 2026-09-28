//go:build linux

// meridian-agent — Phase 0 cut.
//
// Loads the counter eBPF objects (pinning maps under --pin-dir) and tails the
// flow_events ring buffer to stdout. The full agent (netlink
// lifecycle, xDS, SVID) arrives in Phases 1-4; this binary exists to exercise
// the Phase 0 pipeline end to end by hand:
//
//	sudo ./bin/meridian-agent --pin-dir /sys/fs/bpf/meridian --iface <veth>
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"

	adminserver "github.com/joshuawu/meridian/internal/agent/admin"
	"github.com/joshuawu/meridian/internal/agent/attach"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/linkwatch"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/internal/agent/supervisor"
	"github.com/joshuawu/meridian/internal/agent/telemetry"
)

func main() {
	pinDir := flag.String("pin-dir", "/sys/fs/bpf/meridian", "bpffs directory for map pins")
	iface := flag.String("iface", "", "interface to attach tc ingress program")
	policyFile := flag.String("policy-file", "", "optional static YAML policy snapshot to seed at startup")
	cgroup := flag.String("cgroup", "", "cgroup v2 path to attach the SOCKMAP fast path (sock_ops + sk_msg); empty = disabled")
	vethPrefix := flag.String("veth-prefix", "", "host-side pod veth name prefix for auto TC attach via RTNLGRP_LINK watcher (empty = disabled; e.g. 'mh-' or 'lxc')")

	// Phase 4 flags.
	standalone := flag.Bool("standalone", false, "run with an embedded ephemeral CA (dev mode)")
	controlAddr := flag.String("control-addr", "", "control-plane REST address for RemoteSigner (e.g. https://control:9443)")
	adsAddr := flag.String("ads-addr", "", "control-plane ADS gRPC address (e.g. control:9443); empty = ADS disabled")
	bootstrapCert := flag.String("bootstrap-cert", "", "path to node bootstrap certificate PEM (CC-4)")
	bootstrapKey := flag.String("bootstrap-key", "", "path to node bootstrap private key PEM (CC-4)")
	workloadSocket := flag.String("workload-api-socket", "/run/meridian/workload.sock", "SPIFFE Workload API Unix socket path")
	proxyIn := flag.Int("proxy-inbound-port", 15008, "inbound mTLS transparent listener port")
	proxyOut := flag.Int("proxy-outbound-port", 15001, "outbound CONNECT transparent listener port")
	adminAddr := flag.String("admin-addr", "127.0.0.1:9902", "agent admin HTTP address")
	flag.Parse()

	p4opts := phase4Options{
		workloadAPISocket: *workloadSocket,
		proxyInPort:       *proxyIn,
		proxyOutPort:      *proxyOut,
		controlAddr:       *controlAddr,
		bootstrapCert:     *bootstrapCert,
		bootstrapKey:      *bootstrapKey,
		standalone:        *standalone,
	}
	if err := run(*pinDir, *iface, *policyFile, *cgroup, *vethPrefix, *adminAddr, *adsAddr, p4opts); err != nil {
		log.Fatalf("meridian-agent: %v", err)
	}
}

func run(pinDir, iface, policyFile, cgroup, vethPrefix, adminAddr, adsAddr string, p4 phase4Options) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	opts := supervisor.StartupOptions{
		PinDir:     pinDir,
		Interface:  iface,
		PolicyFile: policyFile,
	}
	if vethPrefix != "" {
		opts.LinkWatcher = linkwatch.NewNetlinkWatcher(
			linkwatch.PrefixSelector(vethPrefix),
			linkwatch.WithWatcherLogf(func(f string, a ...any) { log.Printf(f, a...) }),
		)
		opts.LinkWatchOnError = func(op, ifName string, err error) {
			log.Printf("linkwatch: %s %s: %v", op, ifName, err)
		}
	}

	startupRunner := supervisor.NewDefaultStartupRunner(opts)
	startupRuntime, err := startupRunner.Startup(ctx)
	if err != nil {
		return fmt.Errorf("startup runner: %w", err)
	}
	defer func() {
		_ = startupRuntime.Close(context.Background())
	}()

	objs, err := startupRuntime.CounterObjects()
	if err != nil {
		return fmt.Errorf("startup runner objects: %w", err)
	}

	// The supervisor constructs and owns the consumer (its fd is released by
	// startupRuntime.Close above); we only drive Run here.
	consumer, err := startupRuntime.Consumer()
	if err != nil {
		return fmt.Errorf("startup runner consumer: %w", err)
	}

	metricsServer := metrics.NewServer(":9901", metrics.NewRegistry(metrics.NewMapReader(objs.MetricsMap)))
	metricsErr := make(chan error, 1)
	go func() {
		if serveErr := metricsServer.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			metricsErr <- serveErr
			cancel()
		}
	}()
	log.Printf("serving metrics endpoint on %s/metrics", metricsServer.Addr)

	// Run the supervisor alongside the consumer loop. When --veth-prefix is set
	// the supervisor drives the RTNLGRP_LINK watcher (with ENOBUFS-resilient
	// retry) so every matching pod veth is automatically TC-attached. Without
	// --veth-prefix the supervisor blocks on ctx and handles static interface
	// teardown on shutdown. Either way we wait for its clean exit before metrics
	// shutdown to preserve detach ordering.
	supervisorDone := make(chan error, 1)
	go func() { supervisorDone <- startupRunner.Run(ctx) }()

	if iface != "" {
		log.Printf("attached tc ingress program on iface=%s", iface)
	}
	if vethPrefix != "" {
		log.Printf("linkwatch: watching pod veths with prefix %q for auto TC attach", vethPrefix)
	}

	// Phase-2 SOCKMAP fast path (MER-57): when --cgroup is set, load the sock_ops
	// and sk_msg programs (sharing the already-pinned maps) and attach them — the
	// gated SOCKHASH population (MER-48) and intra-node redirect (MER-50). Loaders
	// live in bpfobj because depguard forbids cmd/ from importing bpf/ directly.
	if cgroup != "" {
		sockObjs, err := bpfobj.LoadSockOps(pinDir)
		if err != nil {
			return fmt.Errorf("load sock_ops for cgroup attach: %w", err)
		}
		defer func() { _ = sockObjs.Close() }()

		skObjs, err := bpfobj.LoadSkMsg(pinDir)
		if err != nil {
			return fmt.Errorf("load sk_msg for sockhash attach: %w", err)
		}
		defer func() { _ = skObjs.Close() }()

		cgMgr := attach.NewCgroupSockOpsManager(sockObjs.MeridianSockOps)
		if err := cgMgr.EnsureAttached(cgroup); err != nil {
			return fmt.Errorf("attach sock_ops: %w", err)
		}
		defer func() { _ = cgMgr.Detach() }()

		skMgr := attach.NewSkMsgSockhashManager(skObjs.MeridianSkMsg, skObjs.Sockhash.FD())
		if err := skMgr.EnsureAttached(); err != nil {
			return fmt.Errorf("attach sk_msg: %w", err)
		}
		defer func() { _ = skMgr.Detach() }()

		log.Printf("attached SOCKMAP fast path: sock_ops on cgroup=%s, sk_msg on sockhash", cgroup)
	}

	// Phase 4: proxy, SVID, TPROXY, Workload API.
	spiffeRes, svidMgr, err := startPhase4(ctx, p4)
	if err != nil {
		log.Printf("phase4 startup error (continuing without proxy): %v", err)
	}

	// ADS client (A-3): stream desired state from the control plane and apply
	// it to the kernel maps via the datapath writer. The post-apply hook keeps
	// the proxy's SPIFFE ID resolver in lockstep with the applied identities.
	if adsAddr != "" {
		if err := startADSClient(ctx, adsAddr, startupRuntime.Writer(), spiffeRes, p4); err != nil {
			log.Printf("ads client startup error (continuing without ADS): %v", err)
		}
	}

	// Admin HTTP server (phase 6).
	if adminAddr != "" {
		adminOpts := []adminserver.Option{adminserver.WithLogf(log.Printf)}
		// Guard: a nil *svid.SVIDManager in a CertRotator interface would be
		// non-nil, so only attach the rotator when SVID rotation is enabled.
		if svidMgr != nil {
			adminOpts = append(adminOpts, adminserver.WithCertRotator(svidMgr))
		}
		adminSrv := adminserver.NewServer(adminAddr, nil, adminOpts...)
		go func() { _ = adminSrv.Serve(ctx) }()
		log.Printf("admin server: %s", adminAddr)
	}

	log.Printf("consuming flow events (pin dir %s); Ctrl-C to exit", pinDir)
	runErr := consumer.Run(ctx, func(ev telemetry.Event) {
		fmt.Printf("%s  %s:%d -> %s:%d  proto=%d verdict=%d bytes=%d\n",
			ev.Timestamp.Format("15:04:05.000000"),
			ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort,
			ev.Proto, ev.Verdict, ev.Bytes)
	})
	cancel()
	<-supervisorDone // wait for clean watcher/attacher shutdown before tearing down SOCKMAP

	if shutdownErr := metrics.Shutdown(metricsServer); shutdownErr != nil {
		return fmt.Errorf("shutdown metrics server: %w", shutdownErr)
	}
	select {
	case serveErr := <-metricsErr:
		return fmt.Errorf("metrics endpoint failed: %w", serveErr)
	default:
	}
	return runErr
}
