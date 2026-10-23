//go:build linux

package main

import (
	"fmt"
	"net"
)

// ifaceFlagsFunc resolves an interface name to its link flags. Injectable so
// the guard is testable without touching host networking.
type ifaceFlagsFunc func(name string) (net.Flags, error)

// netIfaceFlags is the production resolver.
func netIfaceFlags(name string) (net.Flags, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Flags, nil
}

// validateEnforcementIface refuses to attach the ingress enforcement program
// to a loopback device.
//
// Why this is fatal rather than merely unwise: meridian_tc_ingress is
// fail-closed on unknown identity (ADR-0001), and identity_map is empty until
// the first ADS snapshot lands. Attached to a loopback device that posture
// drops every loopback packet on the host — including the agent's own admin
// server on 127.0.0.1, its ADS dial when the control plane is on 127.0.0.1,
// and DNS to 127.0.0.53. The agent therefore drops the traffic that would have
// delivered the identities that would have stopped the dropping: a bootstrap
// deadlock that presents as an indefinite `i/o timeout` and a host with no
// working loopback until the process is killed.
//
// The supported attach targets are pod veths (--veth-prefix) and real links.
// To run an agent and a control plane on one box, bind the control plane to a
// routable address rather than putting the control channel behind the data
// plane it is configuring.
//
// allowLoopback is the escape hatch for the one case where this is deliberate:
// a fail-open posture (MERIDIAN_CFG_FALLOPEN_UNKNOWN seeded into
// runtime_config_map before attach), which is how the integration gates drive
// loopback enforcement safely.
func validateEnforcementIface(iface string, allowLoopback bool, lookup ifaceFlagsFunc) error {
	if iface == "" {
		return nil
	}

	flags, err := lookup(iface)
	if err != nil {
		return fmt.Errorf("resolve --iface %q: %w", iface, err)
	}
	if flags&net.FlagLoopback == 0 {
		return nil
	}
	if allowLoopback {
		return nil
	}

	return fmt.Errorf(
		"refusing to attach ingress enforcement to loopback interface %q: "+
			"the fail-closed posture drops every loopback packet until the first ADS "+
			"snapshot lands, which black-holes the agent's own admin server and its "+
			"path to a loopback control plane (bootstrap deadlock). "+
			"Attach to a pod veth (--veth-prefix) or a real link, and bind the control "+
			"plane to a routable address. "+
			"Pass --allow-loopback-enforcement to override (only safe with the "+
			"fail-open-unknown posture seeded first)",
		iface)
}

// isLoopbackIface reports whether iface resolves to a loopback device. A
// resolution failure reports false: validateEnforcementIface runs first and
// has already turned that case into a startup error.
func isLoopbackIface(iface string, lookup ifaceFlagsFunc) bool {
	if iface == "" {
		return false
	}
	flags, err := lookup(iface)
	if err != nil {
		return false
	}
	return flags&net.FlagLoopback != 0
}
