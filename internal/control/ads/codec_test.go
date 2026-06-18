package ads

import (
	"bytes"
	"encoding/json"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/joshuawu/meridian/pkg/wire"
)

func TestEncodeDecodePolicyRuleRoundTrip(t *testing.T) {
	want := wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: 7, DstIdentity: 9, DstPort: 8443,
			Protocol: 6, Direction: wire.DirectionEgress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionRedirectProxy, Flags: 0x05},
	}
	any, err := EncodePolicyRule(want)
	if err != nil {
		t.Fatalf("EncodePolicyRule: %v", err)
	}
	got, err := DecodeResource(any)
	if err != nil {
		t.Fatalf("DecodeResource: %v", err)
	}
	if got.Kind != KindPolicyRule || got.Policy != want {
		t.Fatalf("round-trip mismatch: kind=%q policy=%+v, want PolicyRule %+v", got.Kind, got.Policy, want)
	}
}

func TestEncodeDecodeIdentityRoundTrip(t *testing.T) {
	want := wire.Identity{ID: 42, SpiffeID: "spiffe://cluster.local/ns/a/sa/b", PodIPv4: "10.0.0.5", Namespace: "a", Name: "b"}
	any, err := EncodeIdentity(want)
	if err != nil {
		t.Fatalf("EncodeIdentity: %v", err)
	}
	got, err := DecodeResource(any)
	if err != nil {
		t.Fatalf("DecodeResource: %v", err)
	}
	if got.Kind != KindIdentity || got.Identity != want {
		t.Fatalf("round-trip mismatch: kind=%q identity=%+v, want Identity %+v", got.Kind, got.Identity, want)
	}
}

// anyFromEnvelopeJSON packs an arbitrary JSON envelope body as a resource Any so
// tests can drive malformed inputs through DecodeResource.
func anyFromEnvelopeJSON(t *testing.T, body string) *anypb.Any {
	t.Helper()
	packed, err := anypb.New(wrapperspb.Bytes([]byte(body)))
	if err != nil {
		t.Fatalf("pack Any: %v", err)
	}
	return packed
}

func TestDecodeResourceFailsClosed(t *testing.T) {
	validPolicySpec := `{"src_identity":1,"dst_identity":2,"dst_port":443,"protocol":6,"direction":0,"action":0,"flags":0}`

	tests := []struct {
		name string
		body string
	}{
		{"unsupported schema_version", `{"schema_version":2,"kind":"PolicyRule","spec":` + validPolicySpec + `}`},
		{"unknown kind", `{"schema_version":1,"kind":"Cluster","spec":{}}`},
		{"unknown field in envelope", `{"schema_version":1,"kind":"PolicyRule","spec":` + validPolicySpec + `,"extra":1}`},
		{"unknown field in spec", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":443,"protocol":6,"direction":0,"action":0,"flags":0,"bogus":1}}`},
		{"dst_port over uint16", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":70000,"protocol":6,"direction":0,"action":0,"flags":0}}`},
		{"protocol over uint8", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":443,"protocol":300,"direction":0,"action":0,"flags":0}}`},
		{"flags over uint8", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":443,"protocol":6,"direction":0,"action":0,"flags":256}}`},
		{"invalid direction", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":443,"protocol":6,"direction":2,"action":0,"flags":0}}`},
		{"invalid action", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":443,"protocol":6,"direction":0,"action":3,"flags":0}}`},
		{"trailing data", `{"schema_version":1,"kind":"Identity","spec":{"id":1,"spiffe_id":"","pod_ipv4":"","namespace":"","name":""}}{}`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeResource(anyFromEnvelopeJSON(t, tc.body)); err == nil {
				t.Fatalf("expected DecodeResource to fail closed for %q, got nil error", tc.name)
			}
		})
	}
}

func TestDecodeResourceRejectsNonBytesValue(t *testing.T) {
	// A bare wrapperspb.StringValue is not the BytesValue the contract requires.
	packed, err := anypb.New(wrapperspb.String("not bytes"))
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	if _, err := DecodeResource(packed); err == nil {
		t.Fatalf("expected failure decoding a non-BytesValue resource")
	}
}

// TestEnvelopeWireShape pins the on-wire envelope shape (ADR-0008 §2): a
// schema_version + kind + spec object, so an accidental shape change is caught.
func TestEnvelopeWireShape(t *testing.T) {
	any, err := EncodePolicyRule(wire.PolicyRule{Key: wire.PolicyRuleKey{SrcIdentity: 1, DstIdentity: 2, DstPort: 1, Protocol: 6}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	var bv wrapperspb.BytesValue
	if err := any.UnmarshalTo(&bv); err != nil {
		t.Fatalf("unmarshal BytesValue: %v", err)
	}
	var top map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(bv.GetValue()))
	if err := dec.Decode(&top); err != nil {
		t.Fatalf("decode envelope shape: %v", err)
	}
	for _, k := range []string{"schema_version", "kind", "spec"} {
		if _, ok := top[k]; !ok {
			t.Fatalf("envelope missing required field %q; got keys %v", k, top)
		}
	}
}
