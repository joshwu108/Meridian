//go:build integration

package integration

import "testing"

// MER-21 (P1.3 gate) is opened here and reserved for the two-node
// Geneve-carried identity enforcement assertions.
//
// Blocker: MER-20 (tc_egress Geneve option push) is not yet present, so there
// is no carried src_identity for ingress to consume and assert.
func TestGeneveIngressIdentityPolicyGate_MER21(t *testing.T) {
	t.Skip("MER-21 opened; waiting on MER-20 Geneve identity option push")
}
