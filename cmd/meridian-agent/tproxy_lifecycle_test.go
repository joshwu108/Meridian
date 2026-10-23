//go:build linux

package main

import (
	"context"
	"errors"
	"testing"
)

// recordingInstaller records the Installer calls startPhase4's TPROXY step makes.
type recordingInstaller struct {
	installs   int
	uninstalls int
	installErr error
}

func (r *recordingInstaller) Install(context.Context) error {
	r.installs++
	return r.installErr
}

func (r *recordingInstaller) Uninstall(context.Context) error {
	r.uninstalls++
	return nil
}

// TestInstallTPROXYLeavesRulesInPlace is the regression for the defer that sat
// inside the startPhase4 SETUP function: because startPhase4 returns handles to
// its caller rather than blocking, `defer tproxyInst.Uninstall(...)` fired the
// instant setup finished. The agent logged "TPROXY rules installed" and then
// immediately tore the rules down, so mangle/ip-rule/table-100 were empty for
// the entire lifetime of the process.
//
// The tproxy package contract (see package doc) is explicit that rules are left
// in place on shutdown so in-flight connections survive a restart, and Install
// is idempotent so boot reconciles rather than recreates. So the correct
// behaviour is: install, never uninstall from here.
func TestInstallTPROXYLeavesRulesInPlace(t *testing.T) {
	inst := &recordingInstaller{}

	if ok := installTPROXY(context.Background(), inst); !ok {
		t.Fatalf("installTPROXY reported failure on a healthy installer")
	}

	if inst.installs != 1 {
		t.Fatalf("Install called %d times, want 1", inst.installs)
	}
	if inst.uninstalls != 0 {
		t.Fatalf("Uninstall called %d times, want 0 — steering rules must outlive setup", inst.uninstalls)
	}
}

// TestInstallTPROXYReportsFailure keeps the proxy-redirect-disabled path honest:
// a failed install must be reported, not swallowed behind a success log.
func TestInstallTPROXYReportsFailure(t *testing.T) {
	inst := &recordingInstaller{installErr: errors.New("no CONFIG_NETFILTER_XT_TARGET_TPROXY")}

	if ok := installTPROXY(context.Background(), inst); ok {
		t.Fatalf("installTPROXY reported success despite install error")
	}
	if inst.uninstalls != 0 {
		t.Fatalf("Uninstall called %d times after a failed install, want 0", inst.uninstalls)
	}
}
