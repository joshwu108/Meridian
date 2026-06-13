package control

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/joshuawu/meridian/internal/reference"
	"github.com/joshuawu/meridian/pkg/wire"
)

const (
	defaultConformanceIterations = 10_000
	shortConformanceIterations   = 1_000
	nightlyConformanceIterations = 1_000_000
	flowsPerSpec                 = 16
)

func conformanceIterations() int {
	if v := os.Getenv("MERIDIAN_CONFORMANCE_ITERATIONS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			panic(fmt.Sprintf("invalid MERIDIAN_CONFORMANCE_ITERATIONS=%q", v))
		}
		return n
	}
	return defaultConformanceIterations
}

// TestCompilerMatchesReferenceProperty is the CP-2 gate (MER-24): for random
// compilable policy specs and random flow tuples, verdicts from the reference
// evaluator built from Compile() output must match an independent declarative
// spec oracle. PR CI runs 1e4 iterations (default); nightly runs 1e6 via
// MERIDIAN_CONFORMANCE_ITERATIONS.
func TestCompilerMatchesReferenceProperty(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping MER-24 property harness in -short mode")
	}

	iterations := conformanceIterations()
	ctx := context.Background()

	for i := 0; i < iterations; i++ {
		seed := conformanceSeed(i)
		r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))

		spec, identities := randomPolicySpec(r)
		compiled, err := Compile(spec, identities)
		if err != nil {
			continue
		}

		eval, err := newReferenceEvaluatorFromCompiled(compiled, reference.UnknownIdentityFailClosed)
		if err != nil {
			t.Fatalf("seed=%d build compiled evaluator: %v", seed, err)
		}

		for j := 0; j < flowsPerSpec; j++ {
			input := randomFlowInput(r, identities)
			got, err := eval.Evaluate(ctx, input)
			if err != nil {
				t.Fatalf("seed=%d flow=%d compiled evaluate: %v", seed, j, err)
			}
			want, err := naiveEvaluateSpec(spec, identities, reference.UnknownIdentityFailClosed, input)
			if err != nil {
				t.Fatalf("seed=%d flow=%d naive evaluate: %v", seed, j, err)
			}
			if got != want {
				logConformanceFailure(t, seed, j, spec, identities, input, got, want)
				t.Fatalf("compiler ≡ reference divergence at seed=%d flow=%d (see logged repro above)", seed, j)
			}
		}
	}
}

// TestConformanceRegressionCorpus replays committed failing seeds so fixed
// divergences cannot regress silently.
func TestConformanceRegressionCorpus(t *testing.T) {
	cases, err := loadConformanceRegressionCases()
	if err != nil {
		t.Fatalf("load regression corpus: %v", err)
	}
	if len(cases) == 0 {
		t.Skip("no conformance regression cases committed yet")
	}

	ctx := context.Background()
	for _, tc := range cases {
		tc := tc
		t.Run(fmt.Sprintf("seed=%d", tc.Seed), func(t *testing.T) {
			compiled, err := Compile(tc.Spec, tc.Identities)
			if err != nil {
				t.Fatalf("Compile: %v", err)
			}
			eval, err := newReferenceEvaluatorFromCompiled(compiled, tc.UnknownMode)
			if err != nil {
				t.Fatalf("evaluator: %v", err)
			}
			for i, input := range tc.Flows {
				got, err := eval.Evaluate(ctx, input)
				if err != nil {
					t.Fatalf("flow[%d] evaluate: %v", i, err)
				}
				want, err := naiveEvaluateSpec(tc.Spec, tc.Identities, tc.UnknownMode, input)
				if err != nil {
					t.Fatalf("flow[%d] naive: %v", i, err)
				}
				if got != want {
					t.Fatalf("flow[%d] divergence: got=%+v want=%+v input=%+v", i, got, want, input)
				}
			}
		})
	}
}

type conformanceRegressionCase struct {
	Seed        uint64                        `json:"seed"`
	UnknownMode reference.UnknownIdentityMode `json:"unknown_mode"`
	Spec        wire.PolicySpec               `json:"spec"`
	Identities  []wire.Identity               `json:"identities"`
	Flows       []reference.Input             `json:"flows"`
}

func loadConformanceRegressionCases() ([]conformanceRegressionCase, error) {
	path := filepath.Join("testdata", "conformance", "regression.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var cases []conformanceRegressionCase
	if err := json.Unmarshal(data, &cases); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return cases, nil
}

func conformanceSeed(iteration int) uint64 {
	return 0x4d45523000000000 | uint64(iteration)
}

func newReferenceEvaluatorFromCompiled(rules []wire.PolicyRule, mode reference.UnknownIdentityMode) (*reference.MapEvaluator, error) {
	refRules := make([]reference.Rule, 0, len(rules))
	for _, rule := range rules {
		refRules = append(refRules, reference.Rule{
			SrcIdentity: rule.Key.SrcIdentity,
			DstIdentity: rule.Key.DstIdentity,
			DstPort:     rule.Key.DstPort,
			Protocol:    rule.Key.Protocol,
			Direction:   uint8(rule.Key.Direction),
			Verdict:     rule.Verdict,
		})
	}
	return reference.NewEvaluator(mode, refRules)
}

// naiveEvaluateSpec is an independent declarative oracle: it expands selectors
// at evaluation time without calling Compile(), mirroring the compiler's
// semantics for matchable flows.
func naiveEvaluateSpec(spec wire.PolicySpec, identities []wire.Identity, mode reference.UnknownIdentityMode, in reference.Input) (wire.PolicyVerdict, error) {
	if in.SrcIdentity == wire.IdentityUnknown || in.DstIdentity == wire.IdentityUnknown {
		if mode == reference.UnknownIdentityFailOpen {
			return wire.PolicyVerdict{Action: wire.PolicyActionAllow}, nil
		}
		return wire.PolicyVerdict{Action: wire.PolicyActionDeny}, nil
	}

	bySpiffe := make(map[string]wire.IdentityID, len(identities))
	for _, id := range identities {
		bySpiffe[id.SpiffeID] = id.ID
	}

	for _, policy := range spec.Policies {
		for _, rule := range policy.Rules {
			srcIDs, err := resolveNamesForOracle(rule.Sources, bySpiffe)
			if err != nil {
				return wire.PolicyVerdict{}, err
			}
			dstIDs, err := resolveNamesForOracle(rule.Destinations, bySpiffe)
			if err != nil {
				return wire.PolicyVerdict{}, err
			}
			for _, srcID := range srcIDs {
				for _, dstID := range dstIDs {
					for _, port := range rule.Ports {
						for _, proto := range rule.Protocols {
							for _, direction := range rule.Directions {
								if in.SrcIdentity == srcID &&
									in.DstIdentity == dstID &&
									in.DstPort == port &&
									in.Protocol == proto &&
									in.Direction == uint8(direction) {
									return rule.Verdict, nil
								}
							}
						}
					}
				}
			}
		}
	}

	return wire.PolicyVerdict{Action: wire.PolicyActionDeny}, nil
}

func resolveNamesForOracle(names []string, bySpiffe map[string]wire.IdentityID) ([]wire.IdentityID, error) {
	out := make([]wire.IdentityID, 0, len(names))
	seen := make(map[wire.IdentityID]struct{}, len(names))
	for _, name := range names {
		id, ok := bySpiffe[name]
		if !ok {
			return nil, fmt.Errorf("unresolved SPIFFE name %q", name)
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out, nil
}

func randomPolicySpec(r *rand.Rand) (wire.PolicySpec, []wire.Identity) {
	nIdent := 2 + r.IntN(3)
	identities := make([]wire.Identity, 0, nIdent)
	for i := 0; i < nIdent; i++ {
		id := wire.IdentityID(1000 + r.Uint32N(9000))
		identities = append(identities, wire.Identity{
			ID:       id,
			SpiffeID: fmt.Sprintf("spiffe://meridian/ns/default/sa/workload-%d", id),
		})
	}

	nRules := 1 + r.IntN(2)
	rules := make([]wire.PolicyRuleSelector, 0, nRules)
	for i := 0; i < nRules; i++ {
		srcCount := 1 + r.IntN(2)
		dstCount := 1 + r.IntN(2)
		sources := pickSpiffeNames(r, identities, srcCount)
		destinations := pickSpiffeNames(r, identities, dstCount)

		ports := []uint16{80, 443, 8080, 8443}
		portPick := ports[r.IntN(len(ports))]
		protoPick := []uint8{6, 17}[r.IntN(2)]
		dirPick := []wire.Direction{wire.DirectionIngress, wire.DirectionEgress}[r.IntN(2)]
		actionPick := []wire.PolicyAction{
			wire.PolicyActionAllow,
			wire.PolicyActionDeny,
			wire.PolicyActionRedirectProxy,
		}[r.IntN(3)]

		var flags wire.PolicyFlags
		if actionPick == wire.PolicyActionAllow && r.IntN(4) == 0 {
			flags = wire.PolicyFlagAudit
		}

		rules = append(rules, wire.PolicyRuleSelector{
			Name:         fmt.Sprintf("rule-%d", i),
			Sources:      sources,
			Destinations: destinations,
			Ports:        []uint16{portPick},
			Protocols:    []uint8{protoPick},
			Directions:   []wire.Direction{dirPick},
			Verdict: wire.PolicyVerdict{
				Action: actionPick,
				Flags:  flags,
			},
		})
	}

	return wire.PolicySpec{
		Policies: []wire.Policy{{
			Name:  "random-policy",
			Rules: rules,
		}},
	}, identities
}

func pickSpiffeNames(r *rand.Rand, identities []wire.Identity, count int) []string {
	if count > len(identities) {
		count = len(identities)
	}
	perm := r.Perm(len(identities))
	out := make([]string, 0, count)
	for i := 0; i < count; i++ {
		out = append(out, identities[perm[i]].SpiffeID)
	}
	return out
}

func randomFlowInput(r *rand.Rand, identities []wire.Identity) reference.Input {
	var src, dst wire.IdentityID
	if r.IntN(5) == 0 {
		src = wire.IdentityUnknown
	} else {
		src = identities[r.IntN(len(identities))].ID
	}
	if r.IntN(5) == 0 {
		dst = wire.IdentityUnknown
	} else {
		dst = identities[r.IntN(len(identities))].ID
	}

	ports := []uint16{80, 443, 8080, 8443, 9000}
	return reference.Input{
		SrcIdentity: src,
		DstIdentity: dst,
		DstPort:     ports[r.IntN(len(ports))],
		Protocol:    []uint8{6, 17}[r.IntN(2)],
		Direction:   []uint8{reference.DirectionIngress, reference.DirectionEgress}[r.IntN(2)],
	}
}

func logConformanceFailure(t *testing.T, seed uint64, flow int, spec wire.PolicySpec, identities []wire.Identity, input reference.Input, got, want wire.PolicyVerdict) {
	t.Helper()
	repro := conformanceRegressionCase{
		Seed:        seed,
		UnknownMode: reference.UnknownIdentityFailClosed,
		Spec:        spec,
		Identities:  identities,
		Flows:       []reference.Input{input},
	}
	data, err := json.MarshalIndent(repro, "", "  ")
	if err != nil {
		t.Logf("seed=%d flow=%d marshal repro failed: %v", seed, flow, err)
		return
	}
	t.Logf("conformance divergence repro (add to testdata/conformance/regression.json):\n%s", string(data))
	t.Logf("got=%+v want=%+v input=%+v", got, want, input)
}
