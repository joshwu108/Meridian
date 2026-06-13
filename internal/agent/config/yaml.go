package config

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/joshuawu/meridian/pkg/wire"
)

type stubYAML struct {
	Version    string             `yaml:"version"`
	Identities []stubIdentityYAML `yaml:"identities"`
	Policies   []stubPolicyRule   `yaml:"policies"`
}

type stubIdentityYAML struct {
	ID        wire.IdentityID `yaml:"id"`
	PodIPv4   string          `yaml:"pod_ipv4"`
	SpiffeID  string          `yaml:"spiffe_id"`
	Namespace string          `yaml:"namespace"`
	Name      string          `yaml:"name"`
}

type stubPolicyRule struct {
	SrcIdentity wire.IdentityID `yaml:"src_identity"`
	DstIdentity wire.IdentityID `yaml:"dst_identity"`
	DstPort     uint16          `yaml:"dst_port"`
	Protocol    uint8           `yaml:"protocol"`
	Direction   wire.Direction  `yaml:"direction"`
	Action      string          `yaml:"action"`
	Flags       uint8           `yaml:"flags"`
}

// LoadPolicySnapshot loads and validates static agent-stub YAML policy state.
func LoadPolicySnapshot(path string) (wire.PolicySnapshot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return wire.PolicySnapshot{}, fmt.Errorf("load policy snapshot %s: %w", path, err)
	}

	var doc stubYAML
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return wire.PolicySnapshot{}, fmt.Errorf("load policy snapshot %s: %w", path, err)
	}

	idsByID := make(map[wire.IdentityID]struct{}, len(doc.Identities))
	identities := make([]wire.Identity, 0, len(doc.Identities))
	for i, in := range doc.Identities {
		id := wire.Identity{
			ID:        in.ID,
			PodIPv4:   in.PodIPv4,
			SpiffeID:  in.SpiffeID,
			Namespace: in.Namespace,
			Name:      in.Name,
		}
		if id.ID == wire.IdentityUnknown {
			return wire.PolicySnapshot{}, fmt.Errorf("load policy snapshot %s: identities[%d] uses reserved id=0", path, i)
		}
		if id.PodIPv4 == "" {
			return wire.PolicySnapshot{}, fmt.Errorf("load policy snapshot %s: identities[%d] missing pod_ipv4", path, i)
		}
		if _, exists := idsByID[id.ID]; exists {
			return wire.PolicySnapshot{}, fmt.Errorf("load policy snapshot %s: identities[%d] duplicates id=%d", path, i, id.ID)
		}
		idsByID[id.ID] = struct{}{}
		identities = append(identities, id)
	}

	policies := make([]wire.PolicyRule, 0, len(doc.Policies))
	for i, in := range doc.Policies {
		action, err := parsePolicyAction(in.Action)
		if err != nil {
			return wire.PolicySnapshot{}, fmt.Errorf("load policy snapshot %s: policies[%d] action: %w", path, i, err)
		}
		if in.Direction != wire.DirectionIngress && in.Direction != wire.DirectionEgress {
			return wire.PolicySnapshot{}, fmt.Errorf("load policy snapshot %s: policies[%d] invalid direction=%d", path, i, in.Direction)
		}

		policies = append(policies, wire.PolicyRule{
			Key: wire.PolicyRuleKey{
				SrcIdentity: in.SrcIdentity,
				DstIdentity: in.DstIdentity,
				DstPort:     in.DstPort,
				Protocol:    in.Protocol,
				Direction:   in.Direction,
			},
			Verdict: wire.PolicyVerdict{
				Action: action,
				Flags:  wire.PolicyFlags(in.Flags),
			},
		})
	}

	return wire.PolicySnapshot{
		Version:    wire.PolicySnapshotVersion(doc.Version),
		Identities: identities,
		Policies:   policies,
	}, nil
}

// BuildCommitPlan computes the minimal desired map mutations.
func BuildCommitPlan(current, desired wire.PolicySnapshot) wire.CommitPlan {
	currentIDs := make(map[wire.IdentityID]wire.Identity, len(current.Identities))
	for _, id := range current.Identities {
		currentIDs[id.ID] = id
	}
	desiredIDs := make(map[wire.IdentityID]wire.Identity, len(desired.Identities))
	for _, id := range desired.Identities {
		desiredIDs[id.ID] = id
	}

	currentPolicies := make(map[wire.PolicyRuleKey]wire.PolicyVerdict, len(current.Policies))
	for _, p := range current.Policies {
		currentPolicies[p.Key] = p.Verdict
	}
	desiredPolicies := make(map[wire.PolicyRuleKey]wire.PolicyVerdict, len(desired.Policies))
	for _, p := range desired.Policies {
		desiredPolicies[p.Key] = p.Verdict
	}

	var plan wire.CommitPlan

	desiredIDKeys := make([]wire.IdentityID, 0, len(desiredIDs))
	for id := range desiredIDs {
		desiredIDKeys = append(desiredIDKeys, id)
	}
	slices.Sort(desiredIDKeys)
	for _, id := range desiredIDKeys {
		want := desiredIDs[id]
		if have, ok := currentIDs[id]; !ok || have != want {
			plan.IdentityUpserts = append(plan.IdentityUpserts, want)
		}
	}

	currentIDKeys := make([]wire.IdentityID, 0, len(currentIDs))
	for id := range currentIDs {
		currentIDKeys = append(currentIDKeys, id)
	}
	slices.Sort(currentIDKeys)
	for _, id := range currentIDKeys {
		if _, ok := desiredIDs[id]; !ok {
			plan.IdentityDeletes = append(plan.IdentityDeletes, id)
		}
	}

	desiredPolicyKeys := make([]wire.PolicyRuleKey, 0, len(desiredPolicies))
	for key := range desiredPolicies {
		desiredPolicyKeys = append(desiredPolicyKeys, key)
	}
	slices.SortFunc(desiredPolicyKeys, comparePolicyRuleKey)
	for _, key := range desiredPolicyKeys {
		want := desiredPolicies[key]
		if have, ok := currentPolicies[key]; !ok || have != want {
			plan.PolicyUpserts = append(plan.PolicyUpserts, wire.PolicyRule{
				Key:     key,
				Verdict: want,
			})
		}
	}

	currentPolicyKeys := make([]wire.PolicyRuleKey, 0, len(currentPolicies))
	for key := range currentPolicies {
		currentPolicyKeys = append(currentPolicyKeys, key)
	}
	slices.SortFunc(currentPolicyKeys, comparePolicyRuleKey)
	for _, key := range currentPolicyKeys {
		if _, ok := desiredPolicies[key]; !ok {
			plan.PolicyDeletes = append(plan.PolicyDeletes, key)
		}
	}

	return plan
}

func parsePolicyAction(raw string) (wire.PolicyAction, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "allow":
		return wire.PolicyActionAllow, nil
	case "deny":
		return wire.PolicyActionDeny, nil
	case "redirect", "redirect_proxy":
		return wire.PolicyActionRedirectProxy, nil
	default:
		return 0, fmt.Errorf("unsupported value %q", raw)
	}
}

func comparePolicyRuleKey(a, b wire.PolicyRuleKey) int {
	if a.SrcIdentity != b.SrcIdentity {
		if a.SrcIdentity < b.SrcIdentity {
			return -1
		}
		return 1
	}
	if a.DstIdentity != b.DstIdentity {
		if a.DstIdentity < b.DstIdentity {
			return -1
		}
		return 1
	}
	if a.DstPort != b.DstPort {
		if a.DstPort < b.DstPort {
			return -1
		}
		return 1
	}
	if a.Protocol != b.Protocol {
		if a.Protocol < b.Protocol {
			return -1
		}
		return 1
	}
	if a.Direction != b.Direction {
		if a.Direction < b.Direction {
			return -1
		}
		return 1
	}
	return 0
}
