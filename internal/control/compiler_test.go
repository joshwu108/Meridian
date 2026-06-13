package control

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/joshuawu/meridian/internal/reference"
	"github.com/joshuawu/meridian/pkg/wire"
)

var updateCompilerSnapshots = flag.Bool("update", false, "update compiler golden snapshots")

func TestCompileTable(t *testing.T) {
	t.Parallel()

	identities := []wire.Identity{
		{ID: 1001, SpiffeID: "spiffe://meridian/ns/default/sa/client-a"},
		{ID: 1002, SpiffeID: "spiffe://meridian/ns/default/sa/client-b"},
		{ID: 2001, SpiffeID: "spiffe://meridian/ns/default/sa/server-a"},
		{ID: 2002, SpiffeID: "spiffe://meridian/ns/default/sa/server-b"},
	}

	tests := []struct {
		name       string
		spec       wire.PolicySpec
		identities []wire.Identity
		wantCount  int
		wantErr    string
	}{
		{
			name: "valid single rule",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{{
					Name: "allow-client-a-server-a",
					Rules: []wire.PolicyRuleSelector{{
						Name:         "rule-1",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow},
					}},
				}},
			},
			identities: identities,
			wantCount:  1,
		},
		{
			name: "valid multi selector expansion",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{{
					Name: "expanded",
					Rules: []wire.PolicyRuleSelector{{
						Name:         "matrix",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client-a", "spiffe://meridian/ns/default/sa/client-b"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
						Ports:        []uint16{80, 443},
						Protocols:    []uint8{6, 17},
						Directions:   []wire.Direction{wire.DirectionIngress, wire.DirectionEgress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionDeny},
					}},
				}},
			},
			identities: identities,
			wantCount:  16,
		},
		{
			name: "unresolved spiffe name",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{{
					Name: "bad",
					Rules: []wire.PolicyRuleSelector{{
						Name:         "missing-src",
						Sources:      []string{"spiffe://meridian/ns/default/sa/missing"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow},
					}},
				}},
			},
			identities: identities,
			wantErr:    `bad/missing-src: unresolved SPIFFE name "spiffe://meridian/ns/default/sa/missing" in sources`,
		},
		{
			name: "identity zero in identity set",
			spec: wire.PolicySpec{
				Policies: nil,
			},
			identities: []wire.Identity{
				{ID: wire.IdentityUnknown, SpiffeID: "spiffe://meridian/ns/default/sa/zero"},
			},
			wantErr: "uses unknown identity (0)",
		},
		{
			name: "conflicting duplicate key",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{{
					Name: "dupe-conflict",
					Rules: []wire.PolicyRuleSelector{
						{
							Name:         "allow",
							Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
							Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
							Ports:        []uint16{80},
							Protocols:    []uint8{6},
							Directions:   []wire.Direction{wire.DirectionIngress},
							Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow},
						},
						{
							Name:         "deny",
							Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
							Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
							Ports:        []uint16{80},
							Protocols:    []uint8{6},
							Directions:   []wire.Direction{wire.DirectionIngress},
							Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionDeny},
						},
					},
				}},
			},
			identities: identities,
			wantErr:    "duplicate key with conflicting verdicts",
		},
		{
			name: "unsupported action",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{{
					Name: "invalid-action",
					Rules: []wire.PolicyRuleSelector{{
						Name:         "bad-action",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyAction(88)},
					}},
				}},
			},
			identities: identities,
			wantErr:    "unsupported action: 88",
		},
		{
			name: "unknown flag bits",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{{
					Name: "invalid-flags",
					Rules: []wire.PolicyRuleSelector{{
						Name:         "bad-flags",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict: wire.PolicyVerdict{
							Action: wire.PolicyActionAllow,
							Flags:  wire.PolicyFlags(1 << 7),
						},
					}},
				}},
			},
			identities: identities,
			wantErr:    "unknown flag bits set: 0x80",
		},
		{
			name: "sockmap invariant",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{{
					Name: "bad-sockmap",
					Rules: []wire.PolicyRuleSelector{{
						Name:         "sockmap-with-l7",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict: wire.PolicyVerdict{
							Action: wire.PolicyActionAllow,
							Flags:  refFlagMask(wire.PolicyFlagSockmapEligible) | refFlagMask(wire.PolicyFlagL7Required),
						},
					}},
				}},
			},
			identities: identities,
			wantErr:    "SOCKMAP_ELIGIBLE is incompatible with L7_REQUIRED",
		},
		{
			name: "unsupported direction",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{{
					Name: "bad-direction",
					Rules: []wire.PolicyRuleSelector{{
						Name:         "dir",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.Direction(9)},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow},
					}},
				}},
			},
			identities: identities,
			wantErr:    "unsupported direction: 9",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Compile(tt.spec, tt.identities)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("Compile() error = %v", err)
			}
			if len(got) != tt.wantCount {
				t.Fatalf("compiled rule count=%d want=%d", len(got), tt.wantCount)
			}
		})
	}
}

func TestCompileDeterministicAcrossRunsAndShuffledInput(t *testing.T) {
	t.Parallel()

	identities := []wire.Identity{
		{ID: 2002, SpiffeID: "spiffe://meridian/ns/default/sa/server-b"},
		{ID: 1001, SpiffeID: "spiffe://meridian/ns/default/sa/client-a"},
		{ID: 2001, SpiffeID: "spiffe://meridian/ns/default/sa/server-a"},
		{ID: 1002, SpiffeID: "spiffe://meridian/ns/default/sa/client-b"},
	}

	spec := wire.PolicySpec{
		Policies: []wire.Policy{
			{
				Name: "policy-b",
				Rules: []wire.PolicyRuleSelector{
					{
						Name:         "rule-b1",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client-b"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-b"},
						Ports:        []uint16{8443, 443},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionEgress, wire.DirectionIngress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionRedirectProxy, Flags: refFlagMask(wire.PolicyFlagL7Required)},
					},
				},
			},
			{
				Name: "policy-a",
				Rules: []wire.PolicyRuleSelector{
					{
						Name:         "rule-a1",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6, 17},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow},
					},
				},
			},
		},
	}

	first, err := Compile(spec, identities)
	if err != nil {
		t.Fatalf("first compile failed: %v", err)
	}
	second, err := Compile(spec, identities)
	if err != nil {
		t.Fatalf("second compile failed: %v", err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("same input produced different rule sets")
	}
	firstBytes := mustMarshalRules(t, first)
	secondBytes := mustMarshalRules(t, second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("same input produced non-byte-identical output")
	}

	shuffledSpec := spec
	shuffledSpec.Policies = append([]wire.Policy(nil), spec.Policies...)
	slices.Reverse(shuffledSpec.Policies)
	shuffledSpec.Policies[0].Rules = append([]wire.PolicyRuleSelector(nil), shuffledSpec.Policies[0].Rules...)
	slices.Reverse(shuffledSpec.Policies[0].Rules)

	shuffledIdentities := append([]wire.Identity(nil), identities...)
	slices.Reverse(shuffledIdentities)

	third, err := Compile(shuffledSpec, shuffledIdentities)
	if err != nil {
		t.Fatalf("shuffled compile failed: %v", err)
	}
	thirdBytes := mustMarshalRules(t, third)
	if !bytes.Equal(firstBytes, thirdBytes) {
		t.Fatalf("shuffled input changed compiled bytes")
	}
}

func TestCompileSnapshotGolden(t *testing.T) {
	t.Parallel()

	identities := []wire.Identity{
		{ID: 1001, SpiffeID: "spiffe://meridian/ns/default/sa/client-a"},
		{ID: 1002, SpiffeID: "spiffe://meridian/ns/default/sa/client-b"},
		{ID: 2001, SpiffeID: "spiffe://meridian/ns/default/sa/server-a"},
		{ID: 2002, SpiffeID: "spiffe://meridian/ns/default/sa/server-b"},
		{ID: 3001, SpiffeID: "spiffe://meridian/ns/default/sa/proxy"},
	}

	cases := []struct {
		name string
		spec wire.PolicySpec
	}{
		{
			name: "allow_deny_matrix",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{
					{
						Name: "matrix",
						Rules: []wire.PolicyRuleSelector{
							{
								Name:         "allow-ingress",
								Sources:      []string{"spiffe://meridian/ns/default/sa/client-a", "spiffe://meridian/ns/default/sa/client-b"},
								Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
								Ports:        []uint16{80},
								Protocols:    []uint8{6, 17},
								Directions:   []wire.Direction{wire.DirectionIngress},
								Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow},
							},
							{
								Name:         "deny-egress",
								Sources:      []string{"spiffe://meridian/ns/default/sa/server-a"},
								Destinations: []string{"spiffe://meridian/ns/default/sa/client-a", "spiffe://meridian/ns/default/sa/client-b"},
								Ports:        []uint16{25},
								Protocols:    []uint8{6},
								Directions:   []wire.Direction{wire.DirectionEgress},
								Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionDeny},
							},
						},
					},
				},
			},
		},
		{
			name: "proxy_redirect",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{
					{
						Name: "proxy-path",
						Rules: []wire.PolicyRuleSelector{
							{
								Name:         "redirect-to-proxy",
								Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
								Destinations: []string{"spiffe://meridian/ns/default/sa/server-b"},
								Ports:        []uint16{443, 8443},
								Protocols:    []uint8{6},
								Directions:   []wire.Direction{wire.DirectionIngress, wire.DirectionEgress},
								Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionRedirectProxy, Flags: refFlagMask(wire.PolicyFlagL7Required)},
							},
						},
					},
				},
			},
		},
		{
			name: "sockmap_safe_allow",
			spec: wire.PolicySpec{
				Policies: []wire.Policy{
					{
						Name: "sockmap",
						Rules: []wire.PolicyRuleSelector{
							{
								Name:         "eligible-fast-path",
								Sources:      []string{"spiffe://meridian/ns/default/sa/client-a", "spiffe://meridian/ns/default/sa/client-b"},
								Destinations: []string{"spiffe://meridian/ns/default/sa/proxy"},
								Ports:        []uint16{15001},
								Protocols:    []uint8{6},
								Directions:   []wire.Direction{wire.DirectionIngress},
								Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow, Flags: refFlagMask(wire.PolicyFlagSockmapEligible)},
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			compiled, err := Compile(tc.spec, identities)
			if err != nil {
				t.Fatalf("compile failed: %v", err)
			}

			got := mustMarshalRulesPretty(t, compiled)
			goldenPath := filepath.Join("testdata", "compiler", tc.name+".golden.json")
			if *updateCompilerSnapshots {
				if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
					t.Fatalf("mkdir golden dir failed: %v", err)
				}
				if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
					t.Fatalf("write golden failed: %v", err)
				}
			}

			want, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %q failed: %v (run `go test ./internal/control -run TestCompileSnapshotGolden -update` to regenerate)", goldenPath, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("golden mismatch for %s (run `go test ./internal/control -run TestCompileSnapshotGolden -update` to regenerate)", tc.name)
			}
		})
	}
}

func TestCompileReferenceEvaluatorSmoke(t *testing.T) {
	t.Parallel()

	identities := []wire.Identity{
		{ID: 101, SpiffeID: "spiffe://meridian/ns/default/sa/client"},
		{ID: 202, SpiffeID: "spiffe://meridian/ns/default/sa/server"},
		{ID: 303, SpiffeID: "spiffe://meridian/ns/default/sa/proxy"},
	}
	spec := wire.PolicySpec{
		Policies: []wire.Policy{
			{
				Name: "intent",
				Rules: []wire.PolicyRuleSelector{
					{
						Name:         "allow-http",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow},
					},
					{
						Name:         "redirect-proxy",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/proxy"},
						Ports:        []uint16{15001},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionRedirectProxy, Flags: refFlagMask(wire.PolicyFlagL7Required)},
					},
				},
			},
		},
	}

	compiled, err := Compile(spec, identities)
	if err != nil {
		t.Fatalf("compile failed: %v", err)
	}

	refRules := make([]reference.Rule, 0, len(compiled))
	for _, rule := range compiled {
		refRules = append(refRules, reference.Rule{
			SrcIdentity: rule.Key.SrcIdentity,
			DstIdentity: rule.Key.DstIdentity,
			DstPort:     rule.Key.DstPort,
			Protocol:    rule.Key.Protocol,
			Direction:   uint8(rule.Key.Direction),
			Verdict:     rule.Verdict,
		})
	}

	eval, err := reference.NewEvaluator(reference.UnknownIdentityFailClosed, refRules)
	if err != nil {
		t.Fatalf("NewEvaluator failed: %v", err)
	}

	tests := []struct {
		name string
		in   reference.Input
		want wire.PolicyVerdict
	}{
		{
			name: "allow tuple hits allow rule",
			in: reference.Input{
				SrcIdentity: 101, DstIdentity: 202, DstPort: 80, Protocol: 6, Direction: reference.DirectionIngress,
			},
			want: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
		},
		{
			name: "proxy tuple hits redirect rule",
			in: reference.Input{
				SrcIdentity: 101, DstIdentity: 303, DstPort: 15001, Protocol: 6, Direction: reference.DirectionIngress,
			},
			want: wire.PolicyVerdict{Action: wire.PolicyActionRedirectProxy, Flags: refFlagMask(wire.PolicyFlagL7Required)},
		},
		{
			name: "miss defaults deny",
			in: reference.Input{
				SrcIdentity: 101, DstIdentity: 202, DstPort: 443, Protocol: 6, Direction: reference.DirectionIngress,
			},
			want: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := eval.Evaluate(context.Background(), tt.in)
			if err != nil {
				t.Fatalf("Evaluate failed: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected verdict: got=%+v want=%+v", got, tt.want)
			}
		})
	}
}

func TestCompileDuplicateKeySameVerdictDedupes(t *testing.T) {
	t.Parallel()

	identities := []wire.Identity{
		{ID: 1001, SpiffeID: "spiffe://meridian/ns/default/sa/client-a"},
		{ID: 2001, SpiffeID: "spiffe://meridian/ns/default/sa/server-a"},
	}
	spec := wire.PolicySpec{
		Policies: []wire.Policy{
			{
				Name: "policy-a",
				Rules: []wire.PolicyRuleSelector{
					{
						Name:         "allow-a",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow},
					},
				},
			},
			{
				Name: "policy-b",
				Rules: []wire.PolicyRuleSelector{
					{
						Name:         "allow-b",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client-a"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server-a"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow},
					},
				},
			},
		},
	}

	got, err := Compile(spec, identities)
	if err != nil {
		t.Fatalf("Compile failed: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one deduplicated rule, got %d", len(got))
	}
}

func TestCompileDoesNotMutateInputs(t *testing.T) {
	t.Parallel()

	spec := wire.PolicySpec{
		Policies: []wire.Policy{
			{
				Name: "immutability",
				Rules: []wire.PolicyRuleSelector{
					{
						Name:         "rule",
						Sources:      []string{"spiffe://meridian/ns/default/sa/client"},
						Destinations: []string{"spiffe://meridian/ns/default/sa/server"},
						Ports:        []uint16{80},
						Protocols:    []uint8{6},
						Directions:   []wire.Direction{wire.DirectionIngress},
						Verdict:      wire.PolicyVerdict{Action: wire.PolicyActionAllow},
					},
				},
			},
		},
	}
	identities := []wire.Identity{
		{ID: 101, SpiffeID: "spiffe://meridian/ns/default/sa/client"},
		{ID: 202, SpiffeID: "spiffe://meridian/ns/default/sa/server"},
	}

	specBefore := deepClonePolicySpec(t, spec)
	identitiesBefore := append([]wire.Identity(nil), identities...)

	if _, err := Compile(spec, identities); err != nil {
		t.Fatalf("Compile failed: %v", err)
	}

	if !reflect.DeepEqual(spec, specBefore) {
		t.Fatalf("spec mutated by Compile")
	}
	if !reflect.DeepEqual(identities, identitiesBefore) {
		t.Fatalf("identities mutated by Compile")
	}
}

func mustMarshalRules(t *testing.T, rules []wire.PolicyRule) []byte {
	t.Helper()
	data, err := json.Marshal(rules)
	if err != nil {
		t.Fatalf("marshal rules failed: %v", err)
	}
	return data
}

func mustMarshalRulesPretty(t *testing.T, rules []wire.PolicyRule) []byte {
	t.Helper()
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		t.Fatalf("marshal indent rules failed: %v", err)
	}
	data = append(data, '\n')
	return data
}

func refFlagMask(pos wire.PolicyFlags) wire.PolicyFlags {
	return wire.PolicyFlags(1) << pos
}

func deepClonePolicySpec(t *testing.T, spec wire.PolicySpec) wire.PolicySpec {
	t.Helper()
	data, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal spec failed: %v", err)
	}
	var clone wire.PolicySpec
	if err := json.Unmarshal(data, &clone); err != nil {
		t.Fatalf("unmarshal spec failed: %v", err)
	}
	return clone
}
