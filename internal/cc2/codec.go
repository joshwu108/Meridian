// Package cc2 implements the frozen CC-2 xDS resource codec (ADR-0008 §2): the
// versioned-JSON encoding the control plane (ADS server) and the agent (ADS
// client) use to carry compiled policy and identity state over the xDS stream.
//
// Each resource is a google.protobuf.Any wrapping a BytesValue whose .value is a
// versioned JSON envelope {schema_version, kind, spec}. JSON (stdlib) is used
// rather than protoc-generated messages — see ADR-0008 §2 (no protoc toolchain;
// the contract is made rigorous by freezing + versioning the schema and
// validating field widths). The package is the single neutral owner of the
// encoding so control and agent never diverge; it mirrors pkg/wire field-for-field.
package cc2

import (
	"bytes"
	"encoding/json"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/joshuawu/meridian/pkg/wire"
)

// SchemaVersion is the current CC-2 envelope major version (ADR-0008 §2). A
// decoder MUST reject an unknown version (→ NACK).
const SchemaVersion uint32 = 1

// Resource kinds; each MUST match its xDS channel (CDS→PolicyRule, EDS→Identity).
const (
	KindPolicyRule = "PolicyRule"
	KindIdentity   = "Identity"
)

type envelope struct {
	SchemaVersion uint32          `json:"schema_version"`
	Kind          string          `json:"kind"`
	Spec          json.RawMessage `json:"spec"`
}

// policySpec mirrors wire.PolicyRule (flattened) — ADR-0008 §2.
type policySpec struct {
	SrcIdentity uint32 `json:"src_identity"`
	DstIdentity uint32 `json:"dst_identity"`
	DstPort     uint16 `json:"dst_port"`
	Protocol    uint8  `json:"protocol"`
	Direction   uint8  `json:"direction"`
	Action      uint8  `json:"action"`
	Flags       uint8  `json:"flags"`
}

// identitySpec mirrors wire.Identity — ADR-0008 §2.
type identitySpec struct {
	ID        uint32 `json:"id"`
	SpiffeID  string `json:"spiffe_id"`
	PodIPv4   string `json:"pod_ipv4"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// EncodePolicyRule encodes one compiled policy rule as a CC-2 CDS resource.
func EncodePolicyRule(r wire.PolicyRule) (*anypb.Any, error) {
	return encode(KindPolicyRule, policySpec{
		SrcIdentity: uint32(r.Key.SrcIdentity),
		DstIdentity: uint32(r.Key.DstIdentity),
		DstPort:     r.Key.DstPort,
		Protocol:    r.Key.Protocol,
		Direction:   uint8(r.Key.Direction),
		Action:      uint8(r.Verdict.Action),
		Flags:       uint8(r.Verdict.Flags),
	})
}

// EncodeIdentity encodes one identity as a CC-2 EDS resource.
func EncodeIdentity(i wire.Identity) (*anypb.Any, error) {
	return encode(KindIdentity, identitySpec{
		ID:        uint32(i.ID),
		SpiffeID:  i.SpiffeID,
		PodIPv4:   i.PodIPv4,
		Namespace: i.Namespace,
		Name:      i.Name,
	})
}

func encode(kind string, spec any) (*anypb.Any, error) {
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("cc2: marshal %s spec: %w", kind, err)
	}
	doc, err := json.Marshal(envelope{SchemaVersion: SchemaVersion, Kind: kind, Spec: specJSON})
	if err != nil {
		return nil, fmt.Errorf("cc2: marshal %s envelope: %w", kind, err)
	}
	packed, err := anypb.New(wrapperspb.Bytes(doc))
	if err != nil {
		return nil, fmt.Errorf("cc2: pack %s resource: %w", kind, err)
	}
	return packed, nil
}

// DecodePolicyRule decodes a CC-2 CDS resource into a wire.PolicyRule, applying
// the ADR-0008 §2 fail-closed rules (unknown version/kind/field and out-of-range
// values are contract violations).
func DecodePolicyRule(a *anypb.Any) (wire.PolicyRule, error) {
	raw, err := openEnvelope(a, KindPolicyRule)
	if err != nil {
		return wire.PolicyRule{}, err
	}
	var s policySpec
	if err := strictDecode(raw, &s); err != nil {
		return wire.PolicyRule{}, fmt.Errorf("cc2: decode PolicyRule spec: %w", err)
	}
	if s.Direction > 1 {
		return wire.PolicyRule{}, fmt.Errorf("cc2: direction %d out of range {0,1}", s.Direction)
	}
	if s.Action > uint8(wire.PolicyActionRedirectProxy) {
		return wire.PolicyRule{}, fmt.Errorf("cc2: action %d out of range {0,1,2}", s.Action)
	}
	return wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: wire.IdentityID(s.SrcIdentity),
			DstIdentity: wire.IdentityID(s.DstIdentity),
			DstPort:     s.DstPort,
			Protocol:    s.Protocol,
			Direction:   wire.Direction(s.Direction),
		},
		Verdict: wire.PolicyVerdict{
			Action: wire.PolicyAction(s.Action),
			Flags:  wire.PolicyFlags(s.Flags),
		},
	}, nil
}

// DecodeIdentity decodes a CC-2 EDS resource into a wire.Identity.
func DecodeIdentity(a *anypb.Any) (wire.Identity, error) {
	raw, err := openEnvelope(a, KindIdentity)
	if err != nil {
		return wire.Identity{}, err
	}
	var s identitySpec
	if err := strictDecode(raw, &s); err != nil {
		return wire.Identity{}, fmt.Errorf("cc2: decode Identity spec: %w", err)
	}
	return wire.Identity{
		ID:        wire.IdentityID(s.ID),
		SpiffeID:  s.SpiffeID,
		PodIPv4:   s.PodIPv4,
		Namespace: s.Namespace,
		Name:      s.Name,
	}, nil
}

// openEnvelope unwraps Any→BytesValue→envelope and verifies version + kind.
func openEnvelope(a *anypb.Any, wantKind string) (json.RawMessage, error) {
	var bv wrapperspb.BytesValue
	if err := a.UnmarshalTo(&bv); err != nil {
		return nil, fmt.Errorf("cc2: resource is not a BytesValue: %w", err)
	}
	var env envelope
	if err := strictDecode(bv.GetValue(), &env); err != nil {
		return nil, fmt.Errorf("cc2: decode envelope: %w", err)
	}
	if env.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("cc2: unsupported schema_version %d (want %d)", env.SchemaVersion, SchemaVersion)
	}
	if env.Kind != wantKind {
		return nil, fmt.Errorf("cc2: kind %q on a %s channel", env.Kind, wantKind)
	}
	if len(env.Spec) == 0 {
		return nil, fmt.Errorf("cc2: %s envelope has empty spec", wantKind)
	}
	return env.Spec, nil
}

// strictDecode decodes exactly one JSON value, rejecting unknown fields and
// trailing data (ADR-0008 §2 fail-closed rule 1).
func strictDecode(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return fmt.Errorf("unexpected trailing data")
	}
	return nil
}
