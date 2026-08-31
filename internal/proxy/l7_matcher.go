package proxy

import (
	"net/http"
	"strings"

	"github.com/joshuawu/meridian/pkg/wire"
)

// MatchL7 evaluates rules against an HTTP request and returns the verdict of
// the first matching rule. If no rule matches it returns a default-deny verdict
// (fail-closed, matching CC-5 and ADR-0001).
//
// Matching semantics (all conditions within a rule are AND'd):
//   - Method: empty → any; non-empty → exact case-insensitive match.
//   - PathExact: empty → skip; non-empty → exact path match.
//   - PathPrefix: empty → skip; non-empty → path starts with prefix.
//   - Headers: all HeaderMatchers must match (see matchHeader).
//
// Rules are evaluated in order; the first matching rule wins. This mirrors the
// kernel's policy_map first-match evaluation and the order enforced by the
// control plane compiler.
func MatchL7(rules []wire.CompiledL7Rule, r *http.Request) wire.PolicyVerdict {
	for _, rule := range rules {
		if matchRule(rule, r) {
			return rule.Verdict
		}
	}
	// No match → deny (fail-closed).
	return wire.PolicyVerdict{Action: wire.PolicyActionDeny}
}

func matchRule(rule wire.CompiledL7Rule, r *http.Request) bool {
	if rule.Method != "" && !strings.EqualFold(r.Method, rule.Method) {
		return false
	}
	if rule.PathExact != "" && r.URL.Path != rule.PathExact {
		return false
	}
	if rule.PathPrefix != "" && !strings.HasPrefix(r.URL.Path, rule.PathPrefix) {
		return false
	}
	for _, hm := range rule.Headers {
		if !matchHeader(hm, r.Header) {
			return false
		}
	}
	return true
}

// matchHeader checks a single HeaderMatcher against the request headers.
// Name lookup is case-insensitive (http.Header.Get canonicalises).
// If Exact is true the value must match exactly; if false the value must be a
// substring of the actual header value, or empty (presence-only check).
func matchHeader(hm wire.HeaderMatcher, headers http.Header) bool {
	actual := headers.Get(hm.Name)
	if actual == "" {
		// Header absent.
		if hm.Value == "" {
			return false // presence check failed
		}
		return false
	}
	if hm.Value == "" {
		return true // presence check passed
	}
	if hm.Exact {
		return actual == hm.Value
	}
	return strings.Contains(actual, hm.Value)
}
