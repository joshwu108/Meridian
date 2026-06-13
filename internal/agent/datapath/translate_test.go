//go:build linux

package datapath

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/pkg/wire"
)

// C-side constants from bpf/include/meridian_types.h. bpf2go exports the
// struct mirrors (CounterPolicyKey, CounterPolicyVerdict) but not the
// POLICY_FLAG_* macros or _Static_assert sizes — this file pins wire↔C
// equivalence at the datapath translation boundary (MER-15 / D17).
const (
	cPolicyKeySize     = 12 // sizeof(struct policy_key)
	cPolicyVerdictSize = 4  // sizeof(struct policy_verdict)

	cPolicyFlagSockmapEligible uint8 = 1 << 0
	cPolicyFlagL7Required      uint8 = 1 << 1
	cPolicyFlagMTLSRequired    uint8 = 1 << 2
	cPolicyFlagAudit           uint8 = 1 << 3
)

func TestWirePolicyFlagsMatchCPolicyVerdictFlagBits(t *testing.T) {
	cases := []struct {
		name string
		got  wire.PolicyFlags
		want uint8
	}{
		{"SockmapEligible", wire.PolicyFlagSockmapEligible, cPolicyFlagSockmapEligible},
		{"L7Required", wire.PolicyFlagL7Required, cPolicyFlagL7Required},
		{"MTLSRequired", wire.PolicyFlagMTLSRequired, cPolicyFlagMTLSRequired},
		{"Audit", wire.PolicyFlagAudit, cPolicyFlagAudit},
	}
	for _, tc := range cases {
		if uint8(tc.got) != tc.want {
			t.Errorf("%s = %#b, want C POLICY_FLAG %#b", tc.name, tc.got, tc.want)
		}
	}

	combined := wire.PolicyFlagSockmapEligible | wire.PolicyFlagL7Required |
		wire.PolicyFlagMTLSRequired | wire.PolicyFlagAudit
	if uint8(combined) != cPolicyFlagSockmapEligible|cPolicyFlagL7Required|
		cPolicyFlagMTLSRequired|cPolicyFlagAudit {
		t.Fatalf("combined wire flags %#b != combined C flags %#b",
			combined, cPolicyFlagSockmapEligible|cPolicyFlagL7Required|
				cPolicyFlagMTLSRequired|cPolicyFlagAudit)
	}
}

func TestWirePolicyActionMatchesCFlowVerdict(t *testing.T) {
	if uint8(wire.PolicyActionAllow) != 0 ||
		uint8(wire.PolicyActionDeny) != 1 ||
		uint8(wire.PolicyActionRedirectProxy) != 2 {
		t.Fatalf("wire action drifted from enum flow_verdict: allow=%d deny=%d redirect=%d",
			wire.PolicyActionAllow, wire.PolicyActionDeny, wire.PolicyActionRedirectProxy)
	}
}

func TestWireDirectionMatchesCPolicyDirection(t *testing.T) {
	if uint8(wire.DirectionIngress) != 0 || uint8(wire.DirectionEgress) != 1 {
		t.Fatalf("wire direction drifted from enum policy_direction: ingress=%d egress=%d",
			wire.DirectionIngress, wire.DirectionEgress)
	}
}

func TestPolicyStructSizesMatchCStaticAsserts(t *testing.T) {
	if got := unsafe.Sizeof(policyMapKey{}); got != cPolicyKeySize {
		t.Fatalf("policyMapKey size = %d, want %d (C policy_key)", got, cPolicyKeySize)
	}
	if got := unsafe.Sizeof(bpf.CounterPolicyKey{}); got != cPolicyKeySize {
		t.Fatalf("bpf.CounterPolicyKey size = %d, want %d (C policy_key)", got, cPolicyKeySize)
	}
	if got := unsafe.Sizeof(policyMapVerdict{}); got != cPolicyVerdictSize {
		t.Fatalf("policyMapVerdict size = %d, want %d (C policy_verdict)", got, cPolicyVerdictSize)
	}
	if got := unsafe.Sizeof(bpf.CounterPolicyVerdict{}); got != cPolicyVerdictSize {
		t.Fatalf("bpf.CounterPolicyVerdict size = %d, want %d (C policy_verdict)", got, cPolicyVerdictSize)
	}
}

func TestWirePolicyRuleKeyMapsOneToOneToCounterPolicyKey(t *testing.T) {
	for _, direction := range []wire.Direction{wire.DirectionIngress, wire.DirectionEgress} {
		in := wire.PolicyRuleKey{
			SrcIdentity: 7,
			DstIdentity: 9,
			DstPort:     5353,
			Protocol:    17,
			Direction:   direction,
		}
		got := translatePolicyRuleKey(in)
		want := bpf.CounterPolicyKey{
			SrcId:     uint32(in.SrcIdentity),
			DstId:     uint32(in.DstIdentity),
			DstPort:   in.DstPort,
			Proto:     in.Protocol,
			Direction: uint8(in.Direction),
		}
		if got.SrcID != want.SrcId ||
			got.DstID != want.DstId ||
			got.DstPort != want.DstPort ||
			got.Proto != want.Proto ||
			got.Direction != want.Direction {
			t.Fatalf("translatePolicyRuleKey(%+v) = %+v, want CounterPolicyKey %+v", in, got, want)
		}
	}
}

func TestWirePolicyVerdictMapsOneToOneToCounterPolicyVerdict(t *testing.T) {
	in := wire.PolicyVerdict{
		Action: wire.PolicyActionRedirectProxy,
		Flags:  wire.PolicyFlagSockmapEligible | wire.PolicyFlagAudit,
	}
	got := translatePolicyVerdict(in)
	want := bpf.CounterPolicyVerdict{
		Action: uint8(in.Action),
		Flags:  uint8(in.Flags),
		Pad:    0,
	}
	if got.Action != want.Action || got.Flags != want.Flags || got.Pad != want.Pad {
		t.Fatalf("translatePolicyVerdict(%+v) = %+v, want CounterPolicyVerdict %+v", in, got, want)
	}
}

func TestTranslateIdentityRequiresIPv4Field(t *testing.T) {
	_, err := translateIdentity(wire.Identity{ID: 99})
	if err == nil {
		t.Fatalf("expected error when wire.Identity has no IPv4 field")
	}
	if !strings.Contains(err.Error(), "id=99") {
		t.Fatalf("expected error naming identity id, got %q", err.Error())
	}
}

func TestTranslateIdentityUsesNetworkOrderIPv4Key(t *testing.T) {
	entry, err := translateIdentity(wire.Identity{
		ID:      88,
		PodIPv4: "10.0.0.42",
	})
	if err != nil {
		t.Fatalf("translateIdentity error = %v", err)
	}
	if entry.Key != 0x0a00002a {
		t.Fatalf("identity key = %#08x, want 0x0a00002a (network-order IPv4)", entry.Key)
	}
	if entry.Value != 88 {
		t.Fatalf("identity value = %d, want 88", entry.Value)
	}
}
