//go:build !linux

package proxy

import "net"

// transparentListenConfig returns a plain ListenConfig on non-Linux.
// IP_TRANSPARENT is a Linux kernel feature; on macOS/Windows this falls back
// to a regular listen so unit tests can run without it.
func transparentListenConfig() net.ListenConfig {
	return net.ListenConfig{}
}
