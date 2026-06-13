package control

import (
	"fmt"
	"slices"
	"strings"

	"github.com/joshuawu/meridian/pkg/wire"
)

// Compile resolves a declarative policy spec into deterministic compiled rules.
func Compile(spec wire.PolicySpec, identities []wire.Identity) ([]wire.PolicyRule, error) {
	identitiesBySpiffe := make(map[string]wire.IdentityID, len(identities))
	for i, identity := range identities {
		if identity.ID == wire.IdentityUnknown {
			return nil, fmt.Errorf("identities[%d] uses unknown identity (0): spiffe=%q", i, identity.SpiffeID)
		}
		if identity.SpiffeID == "" {
			return nil, fmt.Errorf("identities[%d] missing SPIFFE name for identity id=%d", i, identity.ID)
		}
		if prior, exists := identitiesBySpiffe[identity.SpiffeID]; exists && prior != identity.ID {
			return nil, fmt.Errorf("identities[%d] duplicates SPIFFE name %q with conflicting IDs (%d vs %d)", i, identity.SpiffeID, prior, identity.ID)
		}
		identitiesBySpiffe[identity.SpiffeID] = identity.ID
	}

	rulesByKey := make(map[wire.PolicyRuleKey]wire.PolicyVerdict)
	for policyIdx, policy := range spec.Policies {
		policyName := policy.Name
		if strings.TrimSpace(policyName) == "" {
			policyName = fmt.Sprintf("policy[%d]", policyIdx)
		}

		for ruleIdx, rule := range policy.Rules {
			ruleName := rule.Name
			if strings.TrimSpace(ruleName) == "" {
				ruleName = fmt.Sprintf("rule[%d]", ruleIdx)
			}
			rulePath := fmt.Sprintf("%s/%s", policyName, ruleName)

			srcIDs, err := resolveIdentityNames(rulePath, "sources", rule.Sources, identitiesBySpiffe)
			if err != nil {
				return nil, err
			}
			dstIDs, err := resolveIdentityNames(rulePath, "destinations", rule.Destinations, identitiesBySpiffe)
			if err != nil {
				return nil, err
			}

			if len(rule.Ports) == 0 {
				return nil, fmt.Errorf("%s: ports selector is empty", rulePath)
			}
			if len(rule.Protocols) == 0 {
				return nil, fmt.Errorf("%s: protocols selector is empty", rulePath)
			}
			if len(rule.Directions) == 0 {
				return nil, fmt.Errorf("%s: directions selector is empty", rulePath)
			}

			if err := validateVerdict(rule.Verdict); err != nil {
				return nil, fmt.Errorf("%s: %w", rulePath, err)
			}

			for _, srcID := range srcIDs {
				for _, dstID := range dstIDs {
					for _, port := range rule.Ports {
						for _, proto := range rule.Protocols {
							for _, direction := range rule.Directions {
								key := wire.PolicyRuleKey{
									SrcIdentity: srcID,
									DstIdentity: dstID,
									DstPort:     port,
									Protocol:    proto,
									Direction:   direction,
								}

								ruleForValidation := wire.PolicyRule{Key: key, Verdict: rule.Verdict}
								if err := validateRule(ruleForValidation); err != nil {
									return nil, fmt.Errorf("%s: %w", rulePath, err)
								}

								if existing, exists := rulesByKey[key]; exists {
									if existing != rule.Verdict {
										return nil, fmt.Errorf("%s: duplicate key with conflicting verdicts key=%+v existing=%+v new=%+v", rulePath, key, existing, rule.Verdict)
									}
									continue
								}
								rulesByKey[key] = rule.Verdict
							}
						}
					}
				}
			}
		}
	}

	keys := make([]wire.PolicyRuleKey, 0, len(rulesByKey))
	for key := range rulesByKey {
		keys = append(keys, key)
	}

	slices.SortFunc(keys, func(a, b wire.PolicyRuleKey) int {
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
	})

	compiled := make([]wire.PolicyRule, 0, len(keys))
	for _, key := range keys {
		compiled = append(compiled, wire.PolicyRule{
			Key:     key,
			Verdict: rulesByKey[key],
		})
	}
	return compiled, nil
}

func resolveIdentityNames(rulePath, selectorName string, names []string, identitiesBySpiffe map[string]wire.IdentityID) ([]wire.IdentityID, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("%s: %s selector is empty", rulePath, selectorName)
	}

	resolved := make([]wire.IdentityID, 0, len(names))
	seen := make(map[wire.IdentityID]struct{}, len(names))
	for i, name := range names {
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("%s: %s[%d] is empty", rulePath, selectorName, i)
		}

		identityID, ok := identitiesBySpiffe[name]
		if !ok {
			return nil, fmt.Errorf("%s: unresolved SPIFFE name %q in %s", rulePath, name, selectorName)
		}
		if identityID == wire.IdentityUnknown {
			return nil, fmt.Errorf("%s: %s references unknown identity (0): %q", rulePath, selectorName, name)
		}
		if _, exists := seen[identityID]; exists {
			continue
		}
		seen[identityID] = struct{}{}
		resolved = append(resolved, identityID)
	}

	return resolved, nil
}

func validateRule(rule wire.PolicyRule) error {
	if rule.Key.SrcIdentity == wire.IdentityUnknown || rule.Key.DstIdentity == wire.IdentityUnknown {
		return fmt.Errorf("rules must not reference unknown identity (0)")
	}
	if rule.Key.Direction != wire.DirectionIngress && rule.Key.Direction != wire.DirectionEgress {
		return fmt.Errorf("unsupported direction: %d", rule.Key.Direction)
	}
	if err := validateVerdict(rule.Verdict); err != nil {
		return err
	}
	return nil
}

func validateVerdict(verdict wire.PolicyVerdict) error {
	switch verdict.Action {
	case wire.PolicyActionAllow, wire.PolicyActionDeny, wire.PolicyActionRedirectProxy:
	default:
		return fmt.Errorf("unsupported action: %d", verdict.Action)
	}

	knownMask := flagMask(wire.PolicyFlagSockmapEligible) |
		flagMask(wire.PolicyFlagL7Required) |
		flagMask(wire.PolicyFlagMTLSRequired) |
		flagMask(wire.PolicyFlagAudit)
	if verdict.Flags&^knownMask != 0 {
		return fmt.Errorf("unknown flag bits set: 0x%x", uint8(verdict.Flags&^knownMask))
	}

	sockmap := hasFlag(verdict.Flags, wire.PolicyFlagSockmapEligible)
	l7 := hasFlag(verdict.Flags, wire.PolicyFlagL7Required)
	mtls := hasFlag(verdict.Flags, wire.PolicyFlagMTLSRequired)
	if sockmap {
		if verdict.Action != wire.PolicyActionAllow {
			return fmt.Errorf("SOCKMAP_ELIGIBLE requires ALLOW action")
		}
		if l7 {
			return fmt.Errorf("SOCKMAP_ELIGIBLE is incompatible with L7_REQUIRED")
		}
		if mtls {
			return fmt.Errorf("SOCKMAP_ELIGIBLE is incompatible with MTLS_REQUIRED")
		}
	}

	return nil
}

func hasFlag(flags wire.PolicyFlags, flag wire.PolicyFlags) bool {
	return flags&flagMask(flag) != 0
}

func flagMask(pos wire.PolicyFlags) wire.PolicyFlags {
	return wire.PolicyFlags(1) << pos
}
