//go:build integration

package integration

import "testing"

// MER-29 (P1.2 gate) is opened here and reserved for the full product-path
// policy integration scenario (agent stub, live allow/deny flips, denied map,
// restart survival).
//
// Blockers:
//   - MER-26 datapath.Writer implementation
//   - MER-27 agent stub YAML->snapshot->CommitPlan runner
func TestLivePolicyIntegrationGate_MER29(t *testing.T) {
	t.Skip("MER-29 opened; waiting on MER-26/MER-27 agent datapath path")
}
