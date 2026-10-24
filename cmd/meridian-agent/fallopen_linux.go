//go:build linux

package main

import (
	"fmt"

	"github.com/joshuawu/meridian/internal/agent/bpfobj"
)

// seedFallOpenPosture writes the --policy-fallopen posture into the pinned
// runtime_config_map.
//
// It MUST be called before the supervisor starts, not after: the supervisor's
// Startup() attaches the TC program to --iface as part of its own body (see
// internal/agent/supervisor/runner.go), so by the time it returns, packets are
// already being classified. Seeding afterwards would leave a window in which
// an empty identity_map drops every flow on the node — including CoreDNS.
//
// Pre-opening the pin set here and closing it again is safe and is the
// established idiom (test/integration's seedFailOpenUnknown does the same):
// LoadTcIngress pins by name, the pins outlive this handle, and the
// supervisor's later load re-opens the very same maps with the posture already
// in place. That is the restart-survival contract bpfobj documents.
func seedFallOpenPosture(pinDir string, fallOpen bool) error {
	objs, err := bpfobj.LoadTcIngress(pinDir)
	if err != nil {
		return fmt.Errorf("open pinned maps to seed policy posture: %w", err)
	}
	defer func() { _ = objs.Close() }()

	return seedRuntimeConfig(objs.RuntimeConfigMap, fallOpen)
}
