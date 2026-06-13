package wire

// PolicySnapshotVersion identifies one complete policy snapshot revision.
type PolicySnapshotVersion string

// PolicySnapshot is the control-plane to agent desired-state envelope.
type PolicySnapshot struct {
	Version    PolicySnapshotVersion
	Identities []Identity
	Policies   []PolicyRule
}

// ProxyPolicySnapshot is the subset of policy state consumed by the node proxy.
type ProxyPolicySnapshot struct {
	Version  PolicySnapshotVersion
	Policies []PolicyRule
}

// CommitPlan is the staged update the datapath writer applies to kernel maps.
type CommitPlan struct {
	IdentityUpserts []Identity
	IdentityDeletes []IdentityID
	PolicyUpserts   []PolicyRule
	PolicyDeletes   []PolicyRuleKey
}

// Direction is the traffic direction of a compiled policy entry. Values
// mirror enum policy_direction in bpf/include/meridian_types.h (ADR-0003).
type Direction uint8

const (
	DirectionIngress Direction = 0
	DirectionEgress  Direction = 1
)

// PolicyRuleKey uniquely identifies one compiled policy entry. It mirrors
// struct policy_key (frozen v2): the direction byte replaced v1's pad, so
// every rule is direction-explicit — there is no "both directions" key.
type PolicyRuleKey struct {
	SrcIdentity IdentityID
	DstIdentity IdentityID
	DstPort     uint16
	Protocol    uint8
	Direction   Direction
}

// PolicyRule is a key/value pair in the compiled L4 policy table.
type PolicyRule struct {
	Key     PolicyRuleKey
	Verdict PolicyVerdict
}

// PolicyVerdict represents the datapath action and flags for a flow.
type PolicyVerdict struct {
	Action PolicyAction
	Flags  PolicyFlags
}

// PolicyAction is the primary L4 enforcement action.
type PolicyAction uint8

const (
	PolicyActionAllow PolicyAction = iota
	PolicyActionDeny
	PolicyActionRedirectProxy
)

// PolicyFlags are secondary controls attached to a verdict.
//
// Bit positions are part of the cross-boundary contract (ARCHITECTURE D4) and
// mirror the POLICY_FLAG_* bits of policy_verdict.flags in
// bpf/include/meridian_types.h. Bits 4-7 are reserved and must be zero.
type PolicyFlags uint8

const (
	PolicyFlagSockmapEligible PolicyFlags = 1 << iota // bit 0
	PolicyFlagL7Required                              // bit 1
	PolicyFlagMTLSRequired                            // bit 2
	PolicyFlagAudit                                   // bit 3
)
