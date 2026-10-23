// Command meridian is the Meridian CLI.
//
// Usage:
//
//	meridian status
//	meridian policy list
//	meridian services list
//	meridian cert inspect <cert.pem>
//	meridian cert verify  <cert.pem> <ca.pem>
//	meridian flows watch
//	meridian http watch
//	meridian map dump
//	meridian doctor
//
// The CLI contacts the control plane REST API (--control) and the agent admin
// server (--agent) via plain HTTP. Both servers are loopback-only by design;
// the CLI never needs mTLS against them.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/joshuawu/meridian/internal/cli"
)

func main() {
	cfg := cli.DefaultConfig()
	flag.StringVar(&cfg.ControlAddr, "control", cfg.ControlAddr, "control-plane REST address")
	flag.StringVar(&cfg.AgentAddr, "agent", cfg.AgentAddr, "agent admin address")
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, args); err != nil {
		fmt.Fprintf(os.Stderr, "meridian: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg cli.Config, args []string) error {
	switch args[0] {
	case "status":
		return cli.Status(cfg, os.Stdout)

	case "policy":
		if len(args) < 2 {
			return fmt.Errorf("usage: meridian policy list")
		}
		switch args[1] {
		case "list":
			return cli.PolicyList(cfg, os.Stdout)
		default:
			return fmt.Errorf("unknown policy subcommand %q", args[1])
		}

	case "services":
		if len(args) < 2 {
			return fmt.Errorf("usage: meridian services list")
		}
		switch args[1] {
		case "list":
			return cli.ServicesList(cfg, os.Stdout)
		default:
			return fmt.Errorf("unknown services subcommand %q", args[1])
		}

	case "cert":
		if len(args) < 2 {
			return fmt.Errorf("usage: meridian cert inspect|verify|rotate <args>")
		}
		switch args[1] {
		case "inspect":
			if len(args) < 3 {
				return fmt.Errorf("usage: meridian cert inspect <cert.pem>")
			}
			return cli.CertInspect(args[2], os.Stdout)
		case "verify":
			if len(args) < 4 {
				return fmt.Errorf("usage: meridian cert verify <cert.pem> <ca.pem>")
			}
			return cli.CertVerify(args[2], args[3], os.Stdout)
		case "rotate":
			return cli.CertRotate(cfg, os.Stdout)
		default:
			return fmt.Errorf("unknown cert subcommand %q", args[1])
		}

	case "flows":
		if len(args) < 2 || args[1] != "watch" {
			return fmt.Errorf("usage: meridian flows watch")
		}
		return cli.FlowsWatch(ctx, cfg, os.Stdout)

	case "map":
		if len(args) < 2 || args[1] != "dump" {
			return fmt.Errorf("usage: meridian map dump")
		}
		return cli.MapDump(cfg, os.Stdout)

	case "http":
		if len(args) < 2 || args[1] != "watch" {
			return fmt.Errorf("usage: meridian http watch")
		}
		return cli.HTTPWatch(ctx, cfg, os.Stdout)

	case "doctor":
		return cli.DoctorCheck(ctx, cfg, os.Stdout)

	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: meridian [flags] <command>

Commands:
  status                   show agent + control-plane status
  policy list              list compiled L4 policy rules
  services list            list registered service identities
  cert inspect <cert.pem>  display certificate details
  cert verify <cert.pem> <ca.pem>  verify certificate chain
  cert rotate              trigger immediate SVID rotation on the agent
  flows watch              stream live flow events from agent
  http watch               stream L7 trace events from agent
  map dump                 dump identity and policy maps from agent
  doctor                   run data plane pre-flight probes (kernel, bpffs,
                           cgroup v2, TPROXY, capabilities)

Flags:`)
	flag.PrintDefaults()
}
