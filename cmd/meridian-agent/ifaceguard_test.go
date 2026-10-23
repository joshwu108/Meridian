//go:build linux

package main

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func flagsFor(m map[string]net.Flags) ifaceFlagsFunc {
	return func(name string) (net.Flags, error) {
		f, ok := m[name]
		if !ok {
			return 0, errors.New("no such network interface")
		}
		return f, nil
	}
}

// TestValidateEnforcementIfaceRejectsLoopback is the regression for the
// self-DoS: attaching the fail-closed ingress enforcement program to a
// loopback device black-holes every loopback packet on the box while
// identity_map is still empty. That includes the agent's own admin server
// (127.0.0.1:9902), its ADS dial to a loopback control plane, and DNS to
// 127.0.0.53 — so the agent drops the very traffic that would deliver the
// identities needed to stop dropping it. Observed as: ADS never connects,
// `i/o timeout` forever, and all host loopback TCP dead until the agent exits.
func TestValidateEnforcementIfaceRejectsLoopback(t *testing.T) {
	lookup := flagsFor(map[string]net.Flags{
		"lo":   net.FlagUp | net.FlagLoopback,
		"eth0": net.FlagUp | net.FlagBroadcast,
	})

	err := validateEnforcementIface("lo", false, lookup)
	if err == nil {
		t.Fatalf("attaching enforcement to lo was accepted; want refusal")
	}
	// The operator must be told how to proceed, not just that it failed.
	for _, want := range []string{"loopback", "--allow-loopback-enforcement"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q missing actionable detail %q", err, want)
		}
	}
}

// TestValidateEnforcementIfaceAllowsRealLinks keeps the production path open:
// pod veths and physical links are the supported attach targets.
func TestValidateEnforcementIfaceAllowsRealLinks(t *testing.T) {
	lookup := flagsFor(map[string]net.Flags{
		"eth0":    net.FlagUp | net.FlagBroadcast,
		"mh-abcd": net.FlagUp | net.FlagBroadcast,
	})

	for _, iface := range []string{"eth0", "mh-abcd"} {
		if err := validateEnforcementIface(iface, false, lookup); err != nil {
			t.Fatalf("validateEnforcementIface(%q) = %v, want nil", iface, err)
		}
	}
}

// TestValidateEnforcementIfaceEmptyIsNoop — no --iface means no static attach
// (the veth watcher path), so there is nothing to guard.
func TestValidateEnforcementIfaceEmptyIsNoop(t *testing.T) {
	called := false
	lookup := func(string) (net.Flags, error) { called = true; return 0, nil }

	if err := validateEnforcementIface("", false, lookup); err != nil {
		t.Fatalf("empty iface returned %v, want nil", err)
	}
	if called {
		t.Fatalf("empty iface should not resolve any interface")
	}
}

// TestValidateEnforcementIfaceOverride keeps the escape hatch working for the
// fail-open posture the integration gates use, where loopback enforcement is
// intentional and MERIDIAN_CFG_FALLOPEN_UNKNOWN is seeded before attach.
func TestValidateEnforcementIfaceOverride(t *testing.T) {
	lookup := flagsFor(map[string]net.Flags{"lo": net.FlagUp | net.FlagLoopback})

	if err := validateEnforcementIface("lo", true, lookup); err != nil {
		t.Fatalf("override still refused loopback: %v", err)
	}
}

// TestValidateEnforcementIfaceUnknownInterface fails fast on a typo rather
// than letting startup proceed to a confusing attach error.
func TestValidateEnforcementIfaceUnknownInterface(t *testing.T) {
	lookup := flagsFor(map[string]net.Flags{"eth0": net.FlagUp})

	err := validateEnforcementIface("eth1", false, lookup)
	if err == nil {
		t.Fatalf("unknown interface accepted; want error")
	}
	if !strings.Contains(err.Error(), "eth1") {
		t.Fatalf("error %q does not name the offending interface", err)
	}
}

// TestIsLoopbackIface backs the startup warning. The warning used to fire for
// any non-empty --iface whenever the override flag was set, so an operator who
// passed --allow-loopback-enforcement defensively while attaching to a normal
// veth was told, falsely, that their loopback traffic would be dropped.
func TestIsLoopbackIface(t *testing.T) {
	lookup := flagsFor(map[string]net.Flags{
		"lo":   net.FlagUp | net.FlagLoopback,
		"eth0": net.FlagUp | net.FlagBroadcast,
	})

	tests := []struct {
		name  string
		iface string
		want  bool
	}{
		{name: "loopback device", iface: "lo", want: true},
		{name: "real link", iface: "eth0", want: false},
		{name: "no static attach", iface: "", want: false},
		{name: "unresolvable is not loopback", iface: "nope0", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isLoopbackIface(tc.iface, lookup); got != tc.want {
				t.Fatalf("isLoopbackIface(%q) = %v, want %v", tc.iface, got, tc.want)
			}
		})
	}
}
