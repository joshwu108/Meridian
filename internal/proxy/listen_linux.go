//go:build linux

package proxy

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// transparentListenConfig returns a net.ListenConfig that sets IP_TRANSPARENT
// on TCP sockets, enabling TPROXY-based original-destination recovery (ADR-0006
// D-C). The socket option must be set before bind; net.ListenConfig.Control
// runs before bind.
func transparentListenConfig() net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var setErr error
			if err := c.Control(func(fd uintptr) {
				// SO_REUSEADDR — allow immediate restart after a crash.
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					setErr = err
					return
				}
				// IP_TRANSPARENT — accept connections whose destination address
				// is not locally assigned (TPROXY-steered packets).
				if err := unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1); err != nil {
					setErr = err
				}
			}); err != nil {
				return err
			}
			return setErr
		},
	}
}
