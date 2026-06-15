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

	"github.com/joshuawu/meridian/internal/agent/attach"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/internal/agent/supervisor"
	"github.com/joshuawu/meridian/internal/agent/telemetry"
)

func main() {
	pinDir := flag.String("pin-dir", "/sys/fs/bpf/meridian", "bpffs directory for map pins")
	iface := flag.String("iface", "", "interface to attach tc ingress program")
	policyFile := flag.String("policy-file", "", "optional static YAML policy snapshot to seed at startup")
	cgroup := flag.String("cgroup", "", "cgroup v2 path to attach the SOCKMAP fast path (sock_ops + sk_msg); empty = disabled")
	flag.Parse()

	if err := run(*pinDir, *iface, *policyFile, *cgroup); err != nil {
		log.Fatalf("meridian-agent: %v", err)
	}
}

func run(pinDir, iface, policyFile, cgroup string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

	startupRunner := supervisor.NewDefaultStartupRunner(supervisor.StartupOptions{
		PinDir:     pinDir,
		Interface:  iface,
		PolicyFile: policyFile,
	})
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

	if iface != "" {
		log.Printf("attached tc ingress program on iface=%s", iface)
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

	log.Printf("consuming flow events (pin dir %s); Ctrl-C to exit", pinDir)
	runErr := consumer.Run(ctx, func(ev telemetry.Event) {
		fmt.Printf("%s  %s:%d -> %s:%d  proto=%d verdict=%d bytes=%d\n",
			ev.Timestamp.Format("15:04:05.000000"),
			ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort,
			ev.Proto, ev.Verdict, ev.Bytes)
	})
	cancel()
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
