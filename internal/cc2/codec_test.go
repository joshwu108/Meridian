package cc2

import (
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/joshuawu/meridian/pkg/wire"
)

func TestPolicyRuleRoundTrip(t *testing.T) {
	want := wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: 1001, DstIdentity: 2002, DstPort: 8443,
			Protocol: 6, Direction: wire.DirectionEgress,
		},
		Verdict: wire.PolicyVerdict{
			Action: wire.PolicyActionAllow,
			Flags:  wire.PolicyFlagSockmapEligible,
		},
	}
	a, err := EncodePolicyRule(want)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodePolicyRule(a)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestIdentityRoundTrip(t *testing.T) {
	want := wire.Identity{
		ID: 4242, SpiffeID: "spiffe://cluster.local/ns/test/sa/svc",
		PodIPv4: "10.0.0.7", Namespace: "test", Name: "svc",
	}
	a, err := EncodeIdentity(want)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodeIdentity(a)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got != want {
		t.Fatalf("round-trip mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

// anyOf wraps an arbitrary JSON document as a CC-2 resource Any (test helper for
// building malformed payloads the encoder would never emit).
func anyOf(t *testing.T, doc string) *anypb.Any {
	t.Helper()
	a, err := anypb.New(wrapperspb.Bytes([]byte(doc)))
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}
	return a
}

func TestDecodeFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		doc  string
	}{
		{"unknown schema_version", `{"schema_version":2,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":80,"protocol":6,"direction":0,"action":0,"flags":0}}`},
		{"kind mismatch", `{"schema_version":1,"kind":"Identity","spec":{"src_identity":1,"dst_identity":2,"dst_port":80,"protocol":6,"direction":0,"action":0,"flags":0}}`},
		{"unknown field in spec", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":80,"protocol":6,"direction":0,"action":0,"flags":0,"bogus":1}}`},
		{"unknown field in envelope", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":80,"protocol":6,"direction":0,"action":0,"flags":0},"extra":true}`},
		{"dst_port overflow (u16)", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":70000,"protocol":6,"direction":0,"action":0,"flags":0}}`},
		{"protocol overflow (u8)", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":80,"protocol":300,"direction":0,"action":0,"flags":0}}`},
		{"direction out of range", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":80,"protocol":6,"direction":2,"action":0,"flags":0}}`},
		{"action out of range", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":80,"protocol":6,"direction":0,"action":9,"flags":0}}`},
		{"trailing data", `{"schema_version":1,"kind":"PolicyRule","spec":{"src_identity":1,"dst_identity":2,"dst_port":80,"protocol":6,"direction":0,"action":0,"flags":0}}{}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodePolicyRule(anyOf(t, tc.doc)); err == nil {
				t.Fatalf("expected decode error for %q, got nil", tc.name)
			}
		})
	}
}

func TestDecodeRejectsNonBytesValue(t *testing.T) {
	bad, err := anypb.New(wrapperspb.String("not a bytesvalue"))
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}
	if _, err := DecodePolicyRule(bad); err == nil {
		t.Fatalf("expected error for non-BytesValue resource")
	}
}
