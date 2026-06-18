package ads

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/joshuawu/meridian/pkg/wire"
)

// CC-2 wire contract (ADR-0008 §2, revised by MER-77 to a no-protoc encoding).
//
// Each xDS resource is a google.protobuf.Any wrapping a google.protobuf.BytesValue
// whose .value is a versioned JSON envelope: {schema_version, kind, spec}. This is
// the frozen, stdlib-only codec that the ADS server (CDS=PolicyRule, EDS=Identity),
// the agent ADS client, and tests all share. Decoding is fail-closed:
// DisallowUnknownFields + trailing-data rejection + integer-width validation
// mirroring the ADR-0004 kernel struct widths; any deviation is a contract
// violation the caller turns into a NACK.
const (
	// SchemaVersion is the current CC-2 envelope major version. A decoder rejects
	// any other version (evolution is additive + version-gated, ADR-0008 §2).
	SchemaVersion uint32 = 1

	KindPolicyRule = "PolicyRule" // CDS channel
	KindIdentity   = "Identity"   // EDS channel
)

// envelope is the versioned wrapper carried in the BytesValue. Spec stays raw so
// it can be decoded strictly against the kind-specific spec type.
type envelope struct {
	SchemaVersion uint32          `json:"schema_version"`
	Kind          string          `json:"kind"`
	Spec          json.RawMessage `json:"spec"`
}

// policySpec mirrors wire.PolicyRule (ADR-0008 §2 PolicyRule). Integer fields are
// uint32 on the wire and range-validated on decode against their kernel widths.
type policySpec struct {
	SrcIdentity uint32 `json:"src_identity"`
	DstIdentity uint32 `json:"dst_identity"`
	DstPort     uint32 `json:"dst_port"` // uint16 range
	Protocol    uint32 `json:"protocol"` // uint8 range
	Direction   uint32 `json:"direction"`
	Action      uint32 `json:"action"`
	Flags       uint32 `json:"flags"` // uint8 range
}

// identitySpec mirrors wire.Identity (ADR-0008 §2 Identity).
type identitySpec struct {
	ID        uint32 `json:"id"`
	SpiffeID  string `json:"spiffe_id"`
	PodIPv4   string `json:"pod_ipv4"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// DecodedResource is the result of DecodeResource: Kind selects which field is
// populated.
type DecodedResource struct {
	Kind     string
	Policy   wire.PolicyRule
	Identity wire.Identity
}

// EncodePolicyRule packs a compiled policy rule as a CDS resource.
func EncodePolicyRule(p wire.PolicyRule) (*anypb.Any, error) {
	return encodeEnvelope(KindPolicyRule, policySpec{
		SrcIdentity: uint32(p.Key.SrcIdentity),
		DstIdentity: uint32(p.Key.DstIdentity),
		DstPort:     uint32(p.Key.DstPort),
		Protocol:    uint32(p.Key.Protocol),
		Direction:   uint32(p.Key.Direction),
		Action:      uint32(p.Verdict.Action),
		Flags:       uint32(p.Verdict.Flags),
	})
}

// EncodeIdentity packs an identity as an EDS resource.
func EncodeIdentity(id wire.Identity) (*anypb.Any, error) {
	return encodeEnvelope(KindIdentity, identitySpec{
		ID:        uint32(id.ID),
		SpiffeID:  id.SpiffeID,
		PodIPv4:   id.PodIPv4,
		Namespace: id.Namespace,
		Name:      id.Name,
	})
}

func encodeEnvelope(kind string, spec any) (*anypb.Any, error) {
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return nil, fmt.Errorf("ads: marshal %s spec: %w", kind, err)
	}
	raw, err := json.Marshal(envelope{SchemaVersion: SchemaVersion, Kind: kind, Spec: specJSON})
	if err != nil {
		return nil, fmt.Errorf("ads: marshal %s envelope: %w", kind, err)
	}
	packed, err := anypb.New(wrapperspb.Bytes(raw))
	if err != nil {
		return nil, fmt.Errorf("ads: pack %s Any: %w", kind, err)
	}
	return packed, nil
}

// DecodeResource decodes one CC-2 resource. It is fail-closed: a non-BytesValue
// Any, an unknown field at any level, trailing data, an unsupported schema_version,
// an unknown kind, or an out-of-range integer all yield an error (→ NACK).
func DecodeResource(res *anypb.Any) (DecodedResource, error) {
	var bv wrapperspb.BytesValue
	if err := res.UnmarshalTo(&bv); err != nil {
		return DecodedResource{}, fmt.Errorf("resource is not a BytesValue: %w", err)
	}

	var env envelope
	if err := strictUnmarshal(bv.GetValue(), &env); err != nil {
		return DecodedResource{}, fmt.Errorf("decode envelope: %w", err)
	}
	if env.SchemaVersion != SchemaVersion {
		return DecodedResource{}, fmt.Errorf("unsupported schema_version %d (want %d)", env.SchemaVersion, SchemaVersion)
	}

	switch env.Kind {
	case KindPolicyRule:
		var spec policySpec
		if err := strictUnmarshal(env.Spec, &spec); err != nil {
			return DecodedResource{}, fmt.Errorf("decode PolicyRule spec: %w", err)
		}
		rule, err := spec.toWire()
		if err != nil {
			return DecodedResource{}, err
		}
		return DecodedResource{Kind: KindPolicyRule, Policy: rule}, nil
	case KindIdentity:
		var spec identitySpec
		if err := strictUnmarshal(env.Spec, &spec); err != nil {
			return DecodedResource{}, fmt.Errorf("decode Identity spec: %w", err)
		}
		return DecodedResource{Kind: KindIdentity, Identity: spec.toWire()}, nil
	default:
		return DecodedResource{}, fmt.Errorf("unknown resource kind %q", env.Kind)
	}
}

// strictUnmarshal decodes exactly one JSON value into dst, rejecting unknown
// fields and trailing data so malformed/forward-incompatible input fails closed.
func strictUnmarshal(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("unexpected trailing data")
	}
	return nil
}

func (p policySpec) toWire() (wire.PolicyRule, error) {
	if p.DstPort > 0xFFFF {
		return wire.PolicyRule{}, fmt.Errorf("dst_port %d out of uint16 range", p.DstPort)
	}
	if p.Protocol > 0xFF {
		return wire.PolicyRule{}, fmt.Errorf("protocol %d out of uint8 range", p.Protocol)
	}
	if p.Flags > 0xFF {
		return wire.PolicyRule{}, fmt.Errorf("flags %d out of uint8 range", p.Flags)
	}
	if p.Direction != uint32(wire.DirectionIngress) && p.Direction != uint32(wire.DirectionEgress) {
		return wire.PolicyRule{}, fmt.Errorf("direction %d invalid (want 0=ingress or 1=egress)", p.Direction)
	}
	switch wire.PolicyAction(p.Action) {
	case wire.PolicyActionAllow, wire.PolicyActionDeny, wire.PolicyActionRedirectProxy:
	default:
		return wire.PolicyRule{}, fmt.Errorf("action %d invalid (want 0=allow, 1=deny, 2=redirect)", p.Action)
	}
	return wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: wire.IdentityID(p.SrcIdentity),
			DstIdentity: wire.IdentityID(p.DstIdentity),
			DstPort:     uint16(p.DstPort),
			Protocol:    uint8(p.Protocol),
			Direction:   wire.Direction(p.Direction),
		},
		Verdict: wire.PolicyVerdict{
			Action: wire.PolicyAction(p.Action),
			Flags:  wire.PolicyFlags(p.Flags),
		},
	}, nil
}

func (i identitySpec) toWire() wire.Identity {
	return wire.Identity{
		ID:        wire.IdentityID(i.ID),
		SpiffeID:  i.SpiffeID,
		PodIPv4:   i.PodIPv4,
		Namespace: i.Namespace,
		Name:      i.Name,
	}
}
