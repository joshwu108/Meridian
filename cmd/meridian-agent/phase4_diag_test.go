package main

import (
	"strings"
	"testing"
)

// TestCredentialGapReason covers the states that actually reach the message.
// The regression it guards is the second case: --control-addr WAS given, and
// the old wording claimed it was not.
func TestCredentialGapReason(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		standalone    bool
		controlAddr   string
		bootstrapCert string
		tokenPath     string
		wantContains  []string
		wantAbsent    []string
	}{
		{
			name:         "nothing configured",
			wantContains: []string{"neither --standalone nor --control-addr given"},
		},
		{
			name:         "control-addr without any credential",
			controlAddr:  "https://control:8080",
			wantContains: []string{"https://control:8080", "--token-path", "--bootstrap-cert"},
			// The whole point: do not claim --control-addr is missing.
			wantAbsent: []string{"neither --standalone nor --control-addr given"},
		},
		{
			name:        "control-addr with a cert but no key still names the addr",
			controlAddr: "https://control:8080",
			// bootstrapCert set means the caller took the other branch; this
			// is the defensive default arm.
			bootstrapCert: "/run/meridian/node.crt",
			wantContains:  []string{"https://control:8080"},
			wantAbsent:    []string{"neither --standalone nor --control-addr given"},
		},
		{
			name:         "standalone never blames the missing flags",
			standalone:   true,
			wantContains: []string{"--standalone"},
			wantAbsent:   []string{"neither --standalone nor --control-addr given"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := credentialGapReason(tc.standalone, tc.controlAddr, tc.bootstrapCert, tc.tokenPath)
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("reason %q does not contain %q", got, want)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("reason %q must not contain %q", got, absent)
				}
			}
		})
	}
}
