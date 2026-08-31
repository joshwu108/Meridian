//go:build !linux

package tproxy

import (
	"context"
	"fmt"
)

// NewInstaller returns a no-op Installer on non-Linux platforms. TPROXY is a
// Linux kernel feature; attempting to install on macOS or Windows will return
// an unsupported error at Install time.
func NewInstaller() Installer {
	return &unsupportedInstaller{}
}

type unsupportedInstaller struct{}

func (*unsupportedInstaller) Install(_ context.Context) error {
	return fmt.Errorf("tproxy: TPROXY is a Linux kernel feature and is not available on this platform")
}

func (*unsupportedInstaller) Uninstall(_ context.Context) error {
	return fmt.Errorf("tproxy: TPROXY is a Linux kernel feature and is not available on this platform")
}
