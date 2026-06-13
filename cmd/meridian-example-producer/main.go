package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joshuawu/meridian/internal/agent/telemetry"
)

func main() {
	interval := flag.Duration("interval", 500*time.Millisecond, "emit interval")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	producer := telemetry.NewExampleProducer(*interval)
	log.Printf("emitting synthetic flow events every %s; Ctrl-C to exit", *interval)
	if err := producer.Run(ctx, func(ev telemetry.Event) {
		fmt.Printf("%s  %s:%d -> %s:%d  proto=%d verdict=%d bytes=%d\n",
			ev.Timestamp.Format("15:04:05.000000"),
			ev.SrcIP, ev.SrcPort, ev.DstIP, ev.DstPort,
			ev.Proto, ev.Verdict, ev.Bytes)
	}); err != nil {
		log.Fatalf("example producer: %v", err)
	}
}
