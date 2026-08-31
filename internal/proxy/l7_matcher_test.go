package proxy

import (
	"net/http"
	"testing"

	"github.com/joshuawu/meridian/pkg/wire"
)

func allowRule(method, pathExact, pathPrefix string, headers ...wire.HeaderMatcher) wire.CompiledL7Rule {
	return wire.CompiledL7Rule{
		Method:     method,
		PathExact:  pathExact,
		PathPrefix: pathPrefix,
		Headers:    headers,
		Verdict:    wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	}
}

func denyRule(method, pathExact, pathPrefix string) wire.CompiledL7Rule {
	return wire.CompiledL7Rule{
		Method:     method,
		PathExact:  pathExact,
		PathPrefix: pathPrefix,
		Verdict:    wire.PolicyVerdict{Action: wire.PolicyActionDeny},
	}
}

func req(method, path string, headers ...string) *http.Request {
	r, _ := http.NewRequest(method, "http://svc"+path, nil)
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r
}

func TestMatchL7_NoRules_Deny(t *testing.T) {
	v := MatchL7(nil, req("GET", "/api/v1/foo"))
	if v.Action != wire.PolicyActionDeny {
		t.Fatalf("no rules: want deny, got %v", v.Action)
	}
}

func TestMatchL7_MethodMatch(t *testing.T) {
	rules := []wire.CompiledL7Rule{
		allowRule("GET", "", ""),
		denyRule("POST", "", ""),
	}
	if v := MatchL7(rules, req("GET", "/x")); v.Action != wire.PolicyActionAllow {
		t.Fatalf("GET should allow, got %v", v.Action)
	}
	if v := MatchL7(rules, req("POST", "/x")); v.Action != wire.PolicyActionDeny {
		t.Fatalf("POST should deny, got %v", v.Action)
	}
}

func TestMatchL7_MethodCaseInsensitive(t *testing.T) {
	rules := []wire.CompiledL7Rule{allowRule("get", "", "")}
	if v := MatchL7(rules, req("GET", "/x")); v.Action != wire.PolicyActionAllow {
		t.Fatalf("case-insensitive method: want allow, got %v", v.Action)
	}
}

func TestMatchL7_PathExact(t *testing.T) {
	rules := []wire.CompiledL7Rule{allowRule("", "/api/health", "")}
	if v := MatchL7(rules, req("GET", "/api/health")); v.Action != wire.PolicyActionAllow {
		t.Fatalf("exact path: want allow, got %v", v.Action)
	}
	if v := MatchL7(rules, req("GET", "/api/health/extra")); v.Action != wire.PolicyActionDeny {
		t.Fatalf("path with suffix should not match exact: want deny, got %v", v.Action)
	}
}

func TestMatchL7_PathPrefix(t *testing.T) {
	rules := []wire.CompiledL7Rule{allowRule("", "", "/api/")}
	if v := MatchL7(rules, req("GET", "/api/v1/users")); v.Action != wire.PolicyActionAllow {
		t.Fatalf("prefix match: want allow, got %v", v.Action)
	}
	if v := MatchL7(rules, req("GET", "/admin/")); v.Action != wire.PolicyActionDeny {
		t.Fatalf("non-prefix: want deny, got %v", v.Action)
	}
}

func TestMatchL7_PRDExample(t *testing.T) {
	// PRD §4.8 example: /api/ GET allowed; /admin/ denied.
	rules := []wire.CompiledL7Rule{
		allowRule("GET", "", "/api/"),
		denyRule("", "", "/admin/"),
	}

	tests := []struct {
		method, path string
		want         wire.PolicyAction
	}{
		{"GET", "/api/users", wire.PolicyActionAllow},
		{"GET", "/api/orders", wire.PolicyActionAllow},
		{"POST", "/api/orders", wire.PolicyActionDeny}, // POST not matched by GET rule
		{"GET", "/admin/config", wire.PolicyActionDeny},
		{"POST", "/admin/reset", wire.PolicyActionDeny},
		{"GET", "/health", wire.PolicyActionDeny}, // no rule matches
	}
	for _, tc := range tests {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			v := MatchL7(rules, req(tc.method, tc.path))
			if v.Action != tc.want {
				t.Fatalf("MatchL7(%s %s) = %v, want %v", tc.method, tc.path, v.Action, tc.want)
			}
		})
	}
}

func TestMatchL7_HeaderPresence(t *testing.T) {
	rules := []wire.CompiledL7Rule{
		allowRule("GET", "", "", wire.HeaderMatcher{Name: "X-Auth-Token", Value: ""}),
	}
	if v := MatchL7(rules, req("GET", "/x", "X-Auth-Token", "abc")); v.Action != wire.PolicyActionAllow {
		t.Fatalf("header present: want allow, got %v", v.Action)
	}
	if v := MatchL7(rules, req("GET", "/x")); v.Action != wire.PolicyActionDeny {
		t.Fatalf("header absent: want deny, got %v", v.Action)
	}
}

func TestMatchL7_HeaderExactMatch(t *testing.T) {
	rules := []wire.CompiledL7Rule{
		allowRule("GET", "", "", wire.HeaderMatcher{Name: "X-Version", Value: "v2", Exact: true}),
	}
	if v := MatchL7(rules, req("GET", "/x", "X-Version", "v2")); v.Action != wire.PolicyActionAllow {
		t.Fatalf("exact header match: want allow, got %v", v.Action)
	}
	if v := MatchL7(rules, req("GET", "/x", "X-Version", "v2-beta")); v.Action != wire.PolicyActionDeny {
		t.Fatalf("non-exact header: want deny, got %v", v.Action)
	}
}

func TestMatchL7_HeaderSubstringMatch(t *testing.T) {
	rules := []wire.CompiledL7Rule{
		allowRule("GET", "", "", wire.HeaderMatcher{Name: "Accept", Value: "json", Exact: false}),
	}
	if v := MatchL7(rules, req("GET", "/x", "Accept", "application/json")); v.Action != wire.PolicyActionAllow {
		t.Fatalf("substring header: want allow, got %v", v.Action)
	}
	if v := MatchL7(rules, req("GET", "/x", "Accept", "text/html")); v.Action != wire.PolicyActionDeny {
		t.Fatalf("no substring: want deny, got %v", v.Action)
	}
}

func TestMatchL7_FirstMatchWins(t *testing.T) {
	// First rule: deny /admin/; second rule: allow all.
	// /admin/ should be denied even though a catch-all allow follows.
	rules := []wire.CompiledL7Rule{
		denyRule("", "", "/admin/"),
		allowRule("", "", ""),
	}
	if v := MatchL7(rules, req("GET", "/admin/config")); v.Action != wire.PolicyActionDeny {
		t.Fatalf("/admin/ should be denied by first rule, got %v", v.Action)
	}
	if v := MatchL7(rules, req("GET", "/api/x")); v.Action != wire.PolicyActionAllow {
		t.Fatalf("/api/x should be allowed by catch-all, got %v", v.Action)
	}
}

func TestMatchL7_MultipleHeaderConditionsAND(t *testing.T) {
	rules := []wire.CompiledL7Rule{
		allowRule("GET", "", "",
			wire.HeaderMatcher{Name: "X-Service", Value: "frontend", Exact: true},
			wire.HeaderMatcher{Name: "X-Version", Value: "v1", Exact: true},
		),
	}
	// Both headers present and matching → allow.
	if v := MatchL7(rules, req("GET", "/x", "X-Service", "frontend", "X-Version", "v1")); v.Action != wire.PolicyActionAllow {
		t.Fatalf("both headers: want allow, got %v", v.Action)
	}
	// Only one header → deny.
	if v := MatchL7(rules, req("GET", "/x", "X-Service", "frontend")); v.Action != wire.PolicyActionDeny {
		t.Fatalf("one header missing: want deny, got %v", v.Action)
	}
}

func TestMatchL7_WildcardRuleMatchesAll(t *testing.T) {
	rules := []wire.CompiledL7Rule{
		{Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow}},
	}
	for _, r := range []*http.Request{
		req("GET", "/x"),
		req("POST", "/y"),
		req("DELETE", "/z"),
	} {
		if v := MatchL7(rules, r); v.Action != wire.PolicyActionAllow {
			t.Fatalf("wildcard rule: want allow for %s, got %v", r.URL.Path, v.Action)
		}
	}
}
