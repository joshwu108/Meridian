package wire

import "testing"

// TestPolicyFlagBitContract pins the cross-boundary POLICY_FLAG_* bit layout
// (ARCHITECTURE D4). These positions are part of the wire contract shared with
// policy_verdict.flags in bpf/include/meridian_types.h; a silent renumbering
// here would desynchronize the control plane from the kernel. This is the T-1
// pin test the Phase-0 review (F-1) required alongside the compile fix.
func TestPolicyFlagBitContract(t *testing.T) {
	cases := []struct {
		name string
		got  PolicyFlags
		want PolicyFlags
	}{
		{"SockmapEligible", PolicyFlagSockmapEligible, 1 << 0},
		{"L7Required", PolicyFlagL7Required, 1 << 1},
		{"MTLSRequired", PolicyFlagMTLSRequired, 1 << 2},
		{"Audit", PolicyFlagAudit, 1 << 3},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Errorf("%s = %#b, want %#b", tc.name, tc.got, tc.want)
		}
	}

	// Bits 4-7 are reserved and must be zero: the defined flags must not
	// collide and must all live in the low nibble.
	allDefined := PolicyFlagSockmapEligible | PolicyFlagL7Required |
		PolicyFlagMTLSRequired | PolicyFlagAudit
	if allDefined != 0b0000_1111 {
		t.Fatalf("defined flag union = %#b, want 0b00001111 (bits 4-7 reserved)", allDefined)
	}
}

// TestPolicyActionContract pins the primary L4 action enumeration so the
// iota ordering cannot drift away from policy_verdict.action.
func TestPolicyActionContract(t *testing.T) {
	if PolicyActionAllow != 0 || PolicyActionDeny != 1 || PolicyActionRedirectProxy != 2 {
		t.Fatalf("action values drifted: allow=%d deny=%d redirect=%d",
			PolicyActionAllow, PolicyActionDeny, PolicyActionRedirectProxy)
	}
}

// TestDirectionContract pins the direction byte that replaced v1's pad in the
// frozen v2 policy_key (ADR-0003): ingress=0, egress=1.
func TestDirectionContract(t *testing.T) {
	if DirectionIngress != 0 || DirectionEgress != 1 {
		t.Fatalf("direction values drifted: ingress=%d egress=%d",
			DirectionIngress, DirectionEgress)
	}
}
