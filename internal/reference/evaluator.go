package reference

import (
	"context"
	"errors"
	"fmt"

	"github.com/joshuawu/meridian/pkg/wire"
)

// Direction constants for policy matching.
const (
	DirectionIngress uint8 = 0
	DirectionEgress  uint8 = 1
)

// UnknownIdentityMode controls evaluator behavior when either flow identity is
// wire.IdentityUnknown.
type UnknownIdentityMode uint8

const (
	UnknownIdentityFailOpen UnknownIdentityMode = iota
	UnknownIdentityFailClosed
)

// Rule is one deterministic policy entry consumed by the reference evaluator.
type Rule struct {
	SrcIdentity wire.IdentityID
	DstIdentity wire.IdentityID
	DstPort     uint16
	Protocol    uint8
	Direction   uint8
	Verdict     wire.PolicyVerdict
}

// MapEvaluator is a pure-Go source-of-truth policy evaluator. It is immutable
// after construction and safe for concurrent Evaluate calls.
type MapEvaluator struct {
	unknownMode UnknownIdentityMode
	rules       map[ruleKey]wire.PolicyVerdict
}

type ruleKey struct {
	srcID     wire.IdentityID
	dstID     wire.IdentityID
	dstPort   uint16
	protocol  uint8
	direction uint8
}

// NewEvaluator validates the provided rules and returns an immutable evaluator.
func NewEvaluator(mode UnknownIdentityMode, rules []Rule) (*MapEvaluator, error) {
	if mode != UnknownIdentityFailOpen && mode != UnknownIdentityFailClosed {
		return nil, fmt.Errorf("invalid unknown identity mode: %d", mode)
	}

	compiled := make(map[ruleKey]wire.PolicyVerdict, len(rules))
	for i, rule := range rules {
		if err := validateRule(rule); err != nil {
			return nil, fmt.Errorf("rule[%d] invalid: %w", i, err)
		}
		key := keyFromRule(rule)
		if _, exists := compiled[key]; exists {
			return nil, fmt.Errorf("rule[%d] duplicates existing key %+v", i, key)
		}
		compiled[key] = rule.Verdict
	}

	return &MapEvaluator{
		unknownMode: mode,
		rules:       compiled,
	}, nil
}

// Evaluate returns the deterministic verdict for one flow tuple.
//
// Resolution order:
//   1. canceled context -> error
//   2. unknown identity posture (fail-open or fail-closed)
//   3. exact 5-tuple match (src,dst,port,proto,direction)
//   4. default deny on miss
func (e *MapEvaluator) Evaluate(ctx context.Context, in Input) (wire.PolicyVerdict, error) {
	if err := ctx.Err(); err != nil {
		return wire.PolicyVerdict{}, err
	}

	if in.SrcIdentity == wire.IdentityUnknown || in.DstIdentity == wire.IdentityUnknown {
		if e.unknownMode == UnknownIdentityFailOpen {
			return wire.PolicyVerdict{Action: wire.PolicyActionAllow}, nil
		}
		return wire.PolicyVerdict{Action: wire.PolicyActionDeny}, nil
	}

	key := ruleKey{
		srcID:     in.SrcIdentity,
		dstID:     in.DstIdentity,
		dstPort:   in.DstPort,
		protocol:  in.Protocol,
		direction: in.Direction,
	}

	if verdict, ok := e.rules[key]; ok {
		return verdict, nil
	}

	return wire.PolicyVerdict{Action: wire.PolicyActionDeny}, nil
}

func validateRule(rule Rule) error {
	if rule.SrcIdentity == wire.IdentityUnknown || rule.DstIdentity == wire.IdentityUnknown {
		return errors.New("rules must not reference unknown identity (0)")
	}
	if rule.Direction != DirectionIngress && rule.Direction != DirectionEgress {
		return fmt.Errorf("unsupported direction: %d", rule.Direction)
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
			return errors.New("SOCKMAP_ELIGIBLE requires ALLOW action")
		}
		if l7 {
			return errors.New("SOCKMAP_ELIGIBLE is incompatible with L7_REQUIRED")
		}
		if mtls {
			return errors.New("SOCKMAP_ELIGIBLE is incompatible with MTLS_REQUIRED")
		}
	}
	return nil
}

func keyFromRule(rule Rule) ruleKey {
	return ruleKey{
		srcID:     rule.SrcIdentity,
		dstID:     rule.DstIdentity,
		dstPort:   rule.DstPort,
		protocol:  rule.Protocol,
		direction: rule.Direction,
	}
}

func hasFlag(flags wire.PolicyFlags, pos wire.PolicyFlags) bool {
	return flags&flagMask(pos) != 0
}

func flagMask(pos wire.PolicyFlags) wire.PolicyFlags {
	return wire.PolicyFlags(1) << pos
}
