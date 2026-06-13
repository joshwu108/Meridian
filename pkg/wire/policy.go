package wire

// PolicySpec is the declarative policy document compiled by the control plane
// into concrete PolicyRule entries.
type PolicySpec struct {
	Policies []Policy
}

// Policy groups declarative rules under one stable name.
type Policy struct {
	Name  string
	Rules []PolicyRuleSelector
}

// PolicyRuleSelector expands to one or more compiled PolicyRule entries. Source
// and destination identities are referenced by SPIFFE name.
type PolicyRuleSelector struct {
	Name string

	Sources      []string
	Destinations []string
	Ports        []uint16
	Protocols    []uint8
	Directions   []Direction

	Verdict PolicyVerdict
}
