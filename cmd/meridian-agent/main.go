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
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf/rlimit"

	"github.com/joshuawu/meridian/internal/agent/attach"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/metrics"
	"github.com/joshuawu/meridian/internal/agent/telemetry"
)

func main() {
	pinDir := flag.String("pin-dir", "/sys/fs/bpf/meridian", "bpffs directory for map pins")
	iface := flag.String("iface", "", "interface to attach tc ingress program")
	flag.Parse()

	if err := run(*pinDir, *iface); err != nil {
		log.Fatalf("meridian-agent: %v", err)
	}
}

func run(pinDir, iface string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock rlimit: %w", err)
	}

	objs, err := bpfobj.LoadCounter(pinDir)
	if err != nil {
		return err
	}
	defer objs.Close()

	consumer, err := telemetry.New(objs.FlowEvents)
	if err != nil {
		return err
	}

	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithCancel(signalCtx)
	defer cancel()

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
		mgr := attach.NewManager(objs.MeridianCounter, filepath.Join(pinDir, "counter_prog"))
		if err := mgr.EnsureAttached(ctx, iface); err != nil {
			return fmt.Errorf("attach on %s: %w", iface, err)
		}
		defer func() {
			// Cleanup is best effort so SIGINT/SIGTERM path never blocks shutdown.
			_ = mgr.Detach(context.Background(), iface)
		}()
		log.Printf("attached tc ingress program on iface=%s", iface)
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
