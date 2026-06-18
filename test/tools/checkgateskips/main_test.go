package main

import (
	"strings"
	"testing"
)

// TestClassifyGroupFailsClosed verifies the per-gate classifier is fail-closed:
// a genuine skip is counted, a genuine failure is flagged, a gate that never ran
// is reported as not-ran, and unrelated tests do not bleed across. Grouping
// gates into one process must not weaken any of this (MER-44 / MER-68).
func TestClassifyGroupFailsClosed(t *testing.T) {
	const a = "TestSockmapIntegrityGate_MER51"
	const b = "TestGeneveIngressIdentityPolicyGate_MER21"
	names := []string{a, b}

	ev := func(action, test string) string {
		return `{"Action":"` + action + `","Test":"` + test + `"}`
	}

	tests := []struct {
		name  string
		lines []string
		want  map[string]gateResult
	}{
		{
			name:  "both pass",
			lines: []string{ev("run", a), ev("pass", a), ev("run", b), ev("pass", b)},
			want: map[string]gateResult{
				a: {ran: true}, b: {ran: true},
			},
		},
		{
			name:  "one skips, one passes",
			lines: []string{ev("run", a), ev("skip", a), ev("run", b), ev("pass", b)},
			want: map[string]gateResult{
				a: {ran: true, skips: 1}, b: {ran: true},
			},
		},
		{
			name:  "one fails, one passes",
			lines: []string{ev("run", a), ev("fail", a), ev("run", b), ev("pass", b)},
			want: map[string]gateResult{
				a: {ran: true, failed: true}, b: {ran: true},
			},
		},
		{
			name:  "a gate that never ran is not-ran (fail closed)",
			lines: []string{ev("run", b), ev("pass", b)},
			want: map[string]gateResult{
				a: {ran: false}, b: {ran: true},
			},
		},
		{
			name:  "subtest failure under a gate flags the gate",
			lines: []string{ev("run", a), ev("fail", a+"/sub_case"), ev("fail", a), ev("run", b), ev("pass", b)},
			want: map[string]gateResult{
				a: {ran: true, failed: true}, b: {ran: true},
			},
		},
		{
			name:  "unrelated test does not bleed across",
			lines: []string{ev("run", a), ev("pass", a), ev("run", b), ev("pass", b), ev("fail", "TestUnrelated")},
			want: map[string]gateResult{
				a: {ran: true}, b: {ran: true},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyGroup(strings.NewReader(strings.Join(tc.lines, "\n")), names)
			for _, n := range names {
				if got[n] != tc.want[n] {
					t.Errorf("gate %s: got %+v, want %+v", n, got[n], tc.want[n])
				}
			}
		})
	}
}

func TestGroupGatesBucketsByTagsAndPkg(t *testing.T) {
	entries := []gateEntry{
		{armed: true, tags: "integration", pkg: "./test/integration/...", testName: "T1"},
		{armed: true, tags: "bpf", pkg: "./test/bpf/...", testName: "T2"},
		{armed: true, tags: "integration", pkg: "./test/integration/...", testName: "T3"},
		{armed: false, tags: "integration", pkg: "./test/integration/...", testName: "Tdisarmed"},
		{armed: true, tags: "", pkg: "./internal/control/...", testName: "T4"},
	}
	groups := groupGates(entries)
	if len(groups) != 3 {
		t.Fatalf("want 3 groups, got %d", len(groups))
	}
	// First group is the integration package with its two armed gates (disarmed excluded).
	if groups[0].key.pkg != "./test/integration/..." || len(groups[0].gates) != 2 {
		t.Fatalf("group[0] = %+v, want integration pkg with 2 gates", groups[0])
	}
	for _, g := range groups[0].gates {
		if g.testName == "Tdisarmed" {
			t.Fatalf("disarmed gate must not be grouped")
		}
	}
}

func TestIsPrivileged(t *testing.T) {
	for tags, want := range map[string]bool{
		"bpf":         true,
		"integration": true,
		"":            false,
		"e2e":         false,
	} {
		if got := isPrivileged(tags); got != want {
			t.Errorf("isPrivileged(%q) = %v, want %v", tags, got, want)
		}
	}
}
