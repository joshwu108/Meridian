//go:build !linux

package tproxy

import (
	"context"
	"testing"
)

func TestUnsupportedInstallerError(t *testing.T) {
	inst := &unsupportedInstaller{}
	if err := inst.Install(context.Background()); err == nil {
		t.Fatal("expected error from unsupported installer, got nil")
	}
	if err := inst.Uninstall(context.Background()); err == nil {
		t.Fatal("expected error from unsupported uninstall, got nil")
	}
}
