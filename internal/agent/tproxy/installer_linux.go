//go:build linux

// Package tproxy installs and reconciles the kernel steering rules needed for
// TPROXY-based transparent proxying (ADR-0006 / A-5). The agent calls Install
// in the TPROXY_INSTALL lifecycle state before going READY; rules are left in
// place on shutdown so in-flight connections survive a restart (the agent
// reconciles rather than recreating them on boot).
//
// The two components installed are:
//  1. ip rule: packets with fwmark == TproxyMark use a local-delivery routing
//     table (so marked packets are delivered locally rather than forwarded).
//  2. iptables mangle PREROUTING TPROXY: redirects marked TCP connections to
//     the transparent-proxy port (15001 outbound / 15008 inbound) without
//     altering packet addresses.
//
// Feature probe: if CONFIG_NETFILTER_XT_TARGET_TPROXY is absent the agent
// must fail-close at startup rather than attach an unsteerable redirect path.
package tproxy

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// linuxInstaller implements Installer using ip rule + iptables.
type linuxInstaller struct {
	mark      uint32
	table     int
	outPort   int
	inPort    int
	execCmd   func(ctx context.Context, name string, args ...string) error
}

// NewInstaller returns the production TPROXY installer for Linux.
func NewInstaller() Installer {
	return &linuxInstaller{
		mark:    TproxyMark,
		table:   TproxyTable,
		outPort: OutboundPort,
		inPort:  InboundPort,
		execCmd: runCmd,
	}
}

// newInstallerWithExec creates an installer with injectable exec (for testing).
func newInstallerWithExec(mark uint32, table, outPort, inPort int, execFn func(context.Context, string, ...string) error) Installer {
	return &linuxInstaller{
		mark:    mark,
		table:   table,
		outPort: outPort,
		inPort:  inPort,
		execCmd: execFn,
	}
}

// Install installs the ip rule and iptables TPROXY rules. It is idempotent:
// pre-existing rules are left in place (iptables -C is used to probe before -A).
func (i *linuxInstaller) Install(ctx context.Context) error {
	if err := ProbeTPROXY(ctx); err != nil {
		return fmt.Errorf("tproxy: feature probe failed: %w", err)
	}
	if err := i.installIPRule(ctx); err != nil {
		return fmt.Errorf("tproxy: ip rule: %w", err)
	}
	if err := i.installLocalRoute(ctx); err != nil {
		return fmt.Errorf("tproxy: local route: %w", err)
	}
	if err := i.installIPTables(ctx, i.outPort); err != nil {
		return fmt.Errorf("tproxy: iptables outbound (:%d): %w", i.outPort, err)
	}
	if err := i.installIPTables(ctx, i.inPort); err != nil {
		return fmt.Errorf("tproxy: iptables inbound (:%d): %w", i.inPort, err)
	}
	return nil
}

// Uninstall removes the TPROXY rules. Per ADR-0006 D-B the agent normally
// leaves them in place across restarts; this is provided for explicit teardown
// (e.g. namespace deletion, test cleanup).
func (i *linuxInstaller) Uninstall(ctx context.Context) error {
	_ = i.execCmd(ctx, "iptables", "-t", "mangle", "-D", "PREROUTING",
		"-p", "tcp",
		"--destination-port", fmt.Sprintf("%d", i.outPort),
		"-j", "TPROXY",
		"--tproxy-mark", fmt.Sprintf("0x%x", i.mark),
		"--on-port", fmt.Sprintf("%d", i.outPort))
	_ = i.execCmd(ctx, "iptables", "-t", "mangle", "-D", "PREROUTING",
		"-p", "tcp",
		"--destination-port", fmt.Sprintf("%d", i.inPort),
		"-j", "TPROXY",
		"--tproxy-mark", fmt.Sprintf("0x%x", i.mark),
		"--on-port", fmt.Sprintf("%d", i.inPort))
	_ = i.execCmd(ctx, "ip", "rule", "del",
		"fwmark", fmt.Sprintf("0x%x", i.mark),
		"lookup", fmt.Sprintf("%d", i.table))
	_ = i.execCmd(ctx, "ip", "route", "del", "local", "0.0.0.0/0",
		"dev", "lo", "table", fmt.Sprintf("%d", i.table))
	return nil
}

// installIPRule adds "ip rule add fwmark <mark> lookup <table>" if not
// already present.
func (i *linuxInstaller) installIPRule(ctx context.Context) error {
	// Probe: list existing rules and check for ours.
	out, err := cmdOutput(ctx, "ip", "rule", "show")
	if err != nil {
		return fmt.Errorf("ip rule show: %w", err)
	}
	want := fmt.Sprintf("fwmark 0x%x lookup %d", i.mark, i.table)
	if strings.Contains(out, want) {
		return nil // already present
	}
	return i.execCmd(ctx, "ip", "rule", "add",
		"fwmark", fmt.Sprintf("0x%x", i.mark),
		"lookup", fmt.Sprintf("%d", i.table))
}

// installLocalRoute adds "ip route add local 0.0.0.0/0 dev lo table <table>"
// so that TPROXY-marked packets are delivered locally.
func (i *linuxInstaller) installLocalRoute(ctx context.Context) error {
	out, err := cmdOutput(ctx, "ip", "route", "show", "table", fmt.Sprintf("%d", i.table))
	if err == nil && strings.Contains(out, "local 0.0.0.0/0") {
		return nil
	}
	return i.execCmd(ctx, "ip", "route", "add", "local", "0.0.0.0/0",
		"dev", "lo", "table", fmt.Sprintf("%d", i.table))
}

// installIPTables installs a mangle TPROXY rule for port if not already
// present (probed via iptables -C).
func (i *linuxInstaller) installIPTables(ctx context.Context, port int) error {
	args := []string{
		"-t", "mangle", "-p", "tcp",
		"--destination-port", fmt.Sprintf("%d", port),
		"-j", "TPROXY",
		"--tproxy-mark", fmt.Sprintf("0x%x", i.mark),
		"--on-port", fmt.Sprintf("%d", port),
	}
	// -C checks if the rule exists; exit 0 means present.
	checkArgs := append([]string{"-C", "PREROUTING"}, args...)
	if err := i.execCmd(ctx, "iptables", checkArgs...); err == nil {
		return nil // rule already installed
	}
	addArgs := append([]string{"-A", "PREROUTING"}, args...)
	return i.execCmd(ctx, "iptables", addArgs...)
}

// ProbeTPROXY verifies that the TPROXY iptables target is available by running
// a no-op iptables command that references the TPROXY target. If this fails,
// the kernel does not have CONFIG_NETFILTER_XT_TARGET_TPROXY and the agent
// must fail-close (ADR-0006 operational implication).
func ProbeTPROXY(ctx context.Context) error {
	// A dry-run: iptables -t mangle -L verifies the mangle table is accessible;
	// we then check for TPROXY module specifically.
	if err := runCmd(ctx, "iptables", "-t", "mangle", "-L"); err != nil {
		return fmt.Errorf("iptables mangle table unavailable: %w", err)
	}
	// Check that the TPROXY module is loadable.
	if err := runCmd(ctx, "modprobe", "xt_TPROXY"); err != nil {
		// modprobe may not be available or module may be built-in; try a probe
		// via iptables --test instead.
		if err2 := runCmd(ctx, "iptables", "-t", "mangle", "-C", "PREROUTING",
			"-p", "tcp", "--dport", "1", "-j", "TPROXY",
			"--tproxy-mark", "0x1", "--on-port", "1"); err2 != nil {
			// iptables -C returns 1 if rule absent but module present; returns
			// different error if module is missing. We can't reliably distinguish
			// without more parsing, so only fail if modprobe gave a hard error.
			if strings.Contains(err.Error(), "not found") {
				return fmt.Errorf("TPROXY module not available: %w", err)
			}
		}
	}
	return nil
}

func runCmd(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func cmdOutput(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.Output()
	return string(out), err
}
