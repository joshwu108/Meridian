package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshuawu/meridian/pkg/wire"
)

func TestLoadPolicySnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	const body = `
version: v1
identities:
  - id: 1001
    pod_ipv4: 10.0.0.10
    spiffe_id: spiffe://cluster.local/ns/default/sa/frontend
    namespace: default
    name: frontend
policies:
  - src_identity: 1001
    dst_identity: 2001
    dst_port: 8080
    protocol: 6
    direction: 0
    action: allow
    flags: 8
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	got, err := LoadPolicySnapshot(path)
	if err != nil {
		t.Fatalf("LoadPolicySnapshot() error = %v", err)
	}
	if got.Version != "v1" {
		t.Fatalf("version = %q, want v1", got.Version)
	}
	if len(got.Identities) != 1 || got.Identities[0].PodIPv4 != "10.0.0.10" {
		t.Fatalf("identities = %+v", got.Identities)
	}
	if len(got.Policies) != 1 {
		t.Fatalf("policies len = %d, want 1", len(got.Policies))
	}
	if got.Policies[0].Verdict.Action != wire.PolicyActionAllow {
		t.Fatalf("action = %d, want allow", got.Policies[0].Verdict.Action)
	}
}

func TestLoadPolicySnapshotRejectsMissingIdentityIPv4(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.yaml")
	const body = `
version: v1
identities:
  - id: 1001
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	_, err := LoadPolicySnapshot(path)
	if err == nil || !strings.Contains(err.Error(), "missing pod_ipv4") {
		t.Fatalf("expected missing pod_ipv4 error, got %v", err)
	}
}

func TestBuildCommitPlanMinimalDiff(t *testing.T) {
	current := wire.PolicySnapshot{
		Identities: []wire.Identity{
			{ID: 1, PodIPv4: "10.0.0.1"},
			{ID: 2, PodIPv4: "10.0.0.2"},
		},
		Policies: []wire.PolicyRule{
			{
				Key: wire.PolicyRuleKey{
					SrcIdentity: 1,
					DstIdentity: 2,
					DstPort:     80,
					Protocol:    6,
					Direction:   wire.DirectionIngress,
				},
				Verdict: wire.PolicyVerdict{
					Action: wire.PolicyActionAllow,
					Flags:  0,
				},
			},
		},
	}
	desired := wire.PolicySnapshot{
		Identities: []wire.Identity{
			{ID: 2, PodIPv4: "10.0.0.20"},
			{ID: 3, PodIPv4: "10.0.0.3"},
		},
		Policies: []wire.PolicyRule{
			{
				Key: wire.PolicyRuleKey{
					SrcIdentity: 2,
					DstIdentity: 3,
					DstPort:     443,
					Protocol:    6,
					Direction:   wire.DirectionEgress,
				},
				Verdict: wire.PolicyVerdict{
					Action: wire.PolicyActionDeny,
					Flags:  1,
				},
			},
		},
	}

	plan := BuildCommitPlan(current, desired)
	if len(plan.IdentityUpserts) != 2 {
		t.Fatalf("identity upserts len = %d, want 2", len(plan.IdentityUpserts))
	}
	if len(plan.IdentityDeletes) != 1 || plan.IdentityDeletes[0] != 1 {
		t.Fatalf("identity deletes = %+v, want [1]", plan.IdentityDeletes)
	}
	if len(plan.PolicyUpserts) != 1 {
		t.Fatalf("policy upserts len = %d, want 1", len(plan.PolicyUpserts))
	}
	if len(plan.PolicyDeletes) != 1 {
		t.Fatalf("policy deletes len = %d, want 1", len(plan.PolicyDeletes))
	}
}
