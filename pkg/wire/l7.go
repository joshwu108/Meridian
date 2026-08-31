package wire

// CompiledL7Rule is one HTTP policy rule carried from the control plane to the
// node proxy via LDS/RDS (Phase 5). Rules are evaluated in order; first match
// wins. A rule with all zero/empty fields matches every request.
type CompiledL7Rule struct {
	// Method is the exact HTTP method to match ("GET", "POST", …).
	// Empty string matches any method.
	Method string

	// PathExact matches only if the request path equals this string exactly.
	// Empty string disables exact matching.
	PathExact string

	// PathPrefix matches if the request path starts with this prefix.
	// Empty string disables prefix matching.
	PathPrefix string

	// Headers is a list of header conditions that must ALL match (AND semantics).
	Headers []HeaderMatcher

	// Verdict is the action to take when this rule matches.
	Verdict PolicyVerdict
}

// HeaderMatcher is one HTTP header condition.
type HeaderMatcher struct {
	// Name is the header name (case-insensitive per HTTP spec).
	Name string
	// Value is the expected value.
	Value string
	// Exact: true → exact match; false → substring/presence check (Value "" = present).
	Exact bool
}

// L7PolicySnapshot is the proxy-scoped L7 policy pushed via LDS/RDS.
// It is kept separate from ProxyPolicySnapshot so L7 and L4 can evolve
// independently and the proxy can hold both atomically.
type L7PolicySnapshot struct {
	Version PolicySnapshotVersion
	Rules   []CompiledL7Rule
}
