// Package bench contains Phase 8 performance benchmarks.
// Run with: go test -bench=. -benchmem ./test/bench/...
//
// These benchmarks exercise pure-Go logic (compiler, evaluator, L7 matcher,
// circuit breaker). eBPF throughput benchmarks (bpf_prog_test_run at 1M pps)
// require a Linux host and are in test/bpf/ with the bpf build tag.
package bench

import (
	"context"
	"net/http"
	"testing"

	"github.com/joshuawu/meridian/internal/proxy"
	"github.com/joshuawu/meridian/internal/reference"
	"github.com/joshuawu/meridian/pkg/wire"
)

// BenchmarkReferenceEvaluatorLookup measures policy lookup hot-path at 10k rules.
// PRD NFR: lookup must complete in < 50 µs at 10k identities.
func BenchmarkReferenceEvaluatorLookup(b *testing.B) {
	const nRules = 10_000
	rules := make([]reference.Rule, nRules)
	for i := 0; i < nRules; i++ {
		rules[i] = reference.Rule{
			SrcIdentity: wire.IdentityID(i + 1),
			DstIdentity: wire.IdentityID(i + 2),
			DstPort:     8080,
			Protocol:    6,
			Direction:   0,
			Verdict:     wire.PolicyVerdict{Action: wire.PolicyActionAllow},
		}
	}
	eval, err := reference.NewEvaluator(reference.UnknownIdentityFailClosed, rules)
	if err != nil {
		b.Fatalf("NewEvaluator: %v", err)
	}
	// Look up the middle rule (worst case: linear scan on hash miss).
	flow := reference.Input{
		SrcIdentity: 5000,
		DstIdentity: 5001,
		DstPort:     8080,
		Protocol:    6,
		Direction:   0,
	}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = eval.Evaluate(ctx, flow)
	}
}

// BenchmarkReferenceEvaluatorMiss measures the cost of a miss (default deny).
func BenchmarkReferenceEvaluatorMiss(b *testing.B) {
	rules := []reference.Rule{
		{SrcIdentity: 1, DstIdentity: 2, DstPort: 80, Protocol: 6, Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow}},
	}
	eval, _ := reference.NewEvaluator(reference.UnknownIdentityFailClosed, rules)
	flow := reference.Input{SrcIdentity: 999, DstIdentity: 1000, DstPort: 8080, Protocol: 6}
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = eval.Evaluate(ctx, flow)
	}
}

// BenchmarkL7MatcherSimple measures L7 rule matching on a 3-rule set.
func BenchmarkL7MatcherSimple(b *testing.B) {
	rules := []wire.CompiledL7Rule{
		{Method: "GET", PathPrefix: "/api/", Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow}},
		{Method: "POST", PathPrefix: "/api/", Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow}},
		{PathPrefix: "/admin/", Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny}},
	}
	req, _ := http.NewRequest("GET", "http://svc/api/users", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = proxy.MatchL7(rules, req)
	}
}

// BenchmarkL7MatcherLargeRuleset measures matching against 100 rules (worst-case last match).
func BenchmarkL7MatcherLargeRuleset(b *testing.B) {
	rules := make([]wire.CompiledL7Rule, 101)
	for i := 0; i < 100; i++ {
		rules[i] = wire.CompiledL7Rule{
			Method:     "POST",
			PathPrefix: "/api/v" + string(rune('0'+i%10)) + "/",
			Verdict:    wire.PolicyVerdict{Action: wire.PolicyActionAllow},
		}
	}
	rules[100] = wire.CompiledL7Rule{
		PathPrefix: "/api/",
		Verdict:    wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	}
	req, _ := http.NewRequest("GET", "http://svc/api/users", nil)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = proxy.MatchL7(rules, req)
	}
}

// BenchmarkCircuitBreakerAllow measures the hot-path Allow() call under no contention.
func BenchmarkCircuitBreakerAllow(b *testing.B) {
	cb := proxy.NewCircuitBreaker(5, 30e9)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = cb.Allow()
	}
}

// BenchmarkCircuitBreakerParallel measures Allow() under goroutine contention.
func BenchmarkCircuitBreakerParallel(b *testing.B) {
	cb := proxy.NewCircuitBreaker(5, 30e9)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cb.Allow()
			cb.RecordSuccess()
		}
	})
}
