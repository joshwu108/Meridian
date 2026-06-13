package reference

import (
	"context"
	"strings"
	"testing"

	"github.com/joshuawu/meridian/pkg/wire"
)

func TestEvaluatorExhaustiveTable(t *testing.T) {
	t.Parallel()

	allowSockmap := wire.PolicyVerdict{
		Action: wire.PolicyActionAllow,
		Flags:  flagMask(wire.PolicyFlagSockmapEligible) | flagMask(wire.PolicyFlagAudit),
	}
	deny := wire.PolicyVerdict{Action: wire.PolicyActionDeny}
	redirect := wire.PolicyVerdict{
		Action: wire.PolicyActionRedirectProxy,
		Flags:  flagMask(wire.PolicyFlagL7Required) | flagMask(wire.PolicyFlagMTLSRequired),
	}

	rules := []Rule{
		{
			SrcIdentity: 1001,
			DstIdentity: 2001,
			DstPort:     80,
			Protocol:    6,
			Direction:   DirectionIngress,
			Verdict:     allowSockmap,
		},
		{
			SrcIdentity: 1002,
			DstIdentity: 2002,
			DstPort:     443,
			Protocol:    6,
			Direction:   DirectionIngress,
			Verdict:     deny,
		},
		{
			SrcIdentity: 1003,
			DstIdentity: 2003,
			DstPort:     15008,
			Protocol:    6,
			Direction:   DirectionEgress,
			Verdict:     redirect,
		},
	}

	failOpenEval := mustEval(t, UnknownIdentityFailOpen, rules)
	failClosedEval := mustEval(t, UnknownIdentityFailClosed, rules)

	tests := []struct {
		name    string
		eval    *MapEvaluator
		input   Input
		want    wire.PolicyVerdict
		wantErr string
	}{
		{
			name: "exact match allow with sockmap",
			eval: failOpenEval,
			input: Input{
				SrcIdentity: 1001,
				DstIdentity: 2001,
				DstPort:     80,
				Protocol:    6,
				Direction:   DirectionIngress,
			},
			want: allowSockmap,
		},
		{
			name: "exact match deny",
			eval: failOpenEval,
			input: Input{
				SrcIdentity: 1002,
				DstIdentity: 2002,
				DstPort:     443,
				Protocol:    6,
				Direction:   DirectionIngress,
			},
			want: deny,
		},
		{
			name: "exact match redirect",
			eval: failOpenEval,
			input: Input{
				SrcIdentity: 1003,
				DstIdentity: 2003,
				DstPort:     15008,
				Protocol:    6,
				Direction:   DirectionEgress,
			},
			want: redirect,
		},
		{
			name: "direction change misses and defaults deny",
			eval: failOpenEval,
			input: Input{
				SrcIdentity: 1001,
				DstIdentity: 2001,
				DstPort:     80,
				Protocol:    6,
				Direction:   DirectionEgress,
			},
			want: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
		},
		{
			name: "proto change misses and defaults deny",
			eval: failOpenEval,
			input: Input{
				SrcIdentity: 1001,
				DstIdentity: 2001,
				DstPort:     80,
				Protocol:    17,
				Direction:   DirectionIngress,
			},
			want: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
		},
		{
			name: "missing identities default deny",
			eval: failOpenEval,
			input: Input{
				SrcIdentity: 5555,
				DstIdentity: 6666,
				DstPort:     80,
				Protocol:    6,
				Direction:   DirectionIngress,
			},
			want: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
		},
		{
			name: "unknown src fail-open",
			eval: failOpenEval,
			input: Input{
				SrcIdentity: wire.IdentityUnknown,
				DstIdentity: 2001,
				DstPort:     80,
				Protocol:    6,
				Direction:   DirectionIngress,
			},
			want: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
		},
		{
			name: "unknown dst fail-open",
			eval: failOpenEval,
			input: Input{
				SrcIdentity: 1001,
				DstIdentity: wire.IdentityUnknown,
				DstPort:     80,
				Protocol:    6,
				Direction:   DirectionIngress,
			},
			want: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
		},
		{
			name: "unknown src fail-closed",
			eval: failClosedEval,
			input: Input{
				SrcIdentity: wire.IdentityUnknown,
				DstIdentity: 2001,
				DstPort:     80,
				Protocol:    6,
				Direction:   DirectionIngress,
			},
			want: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
		},
		{
			name: "unknown dst fail-closed",
			eval: failClosedEval,
			input: Input{
				SrcIdentity: 1001,
				DstIdentity: wire.IdentityUnknown,
				DstPort:     80,
				Protocol:    6,
				Direction:   DirectionIngress,
			},
			want: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.eval.Evaluate(context.Background(), tt.input)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("want error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected verdict: got=%+v want=%+v", got, tt.want)
			}
		})
	}
}

func TestEvaluatorValidationFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		mode        UnknownIdentityMode
		rules       []Rule
		wantErrPart string
	}{
		{
			name:        "invalid unknown posture mode",
			mode:        UnknownIdentityMode(99),
			rules:       nil,
			wantErrPart: "invalid unknown identity mode",
		},
		{
			name: "invalid action",
			mode: UnknownIdentityFailOpen,
			rules: []Rule{{
				SrcIdentity: 1, DstIdentity: 2, DstPort: 80, Protocol: 6, Direction: DirectionIngress,
				Verdict: wire.PolicyVerdict{Action: wire.PolicyAction(77)},
			}},
			wantErrPart: "unsupported action",
		},
		{
			name: "invalid direction",
			mode: UnknownIdentityFailOpen,
			rules: []Rule{{
				SrcIdentity: 1, DstIdentity: 2, DstPort: 80, Protocol: 6, Direction: 3,
				Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
			}},
			wantErrPart: "unsupported direction",
		},
		{
			name: "unknown identity in rule source",
			mode: UnknownIdentityFailOpen,
			rules: []Rule{{
				SrcIdentity: wire.IdentityUnknown, DstIdentity: 2, DstPort: 80, Protocol: 6, Direction: DirectionIngress,
				Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
			}},
			wantErrPart: "must not reference unknown identity",
		},
		{
			name: "unknown identity in rule destination",
			mode: UnknownIdentityFailOpen,
			rules: []Rule{{
				SrcIdentity: 1, DstIdentity: wire.IdentityUnknown, DstPort: 80, Protocol: 6, Direction: DirectionIngress,
				Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
			}},
			wantErrPart: "must not reference unknown identity",
		},
		{
			name: "unknown flag bit set",
			mode: UnknownIdentityFailOpen,
			rules: []Rule{{
				SrcIdentity: 1, DstIdentity: 2, DstPort: 80, Protocol: 6, Direction: DirectionIngress,
				Verdict: wire.PolicyVerdict{
					Action: wire.PolicyActionAllow,
					Flags:  wire.PolicyFlags(1 << 7),
				},
			}},
			wantErrPart: "unknown flag bits set",
		},
		{
			name: "sockmap requires allow",
			mode: UnknownIdentityFailOpen,
			rules: []Rule{{
				SrcIdentity: 1, DstIdentity: 2, DstPort: 80, Protocol: 6, Direction: DirectionIngress,
				Verdict: wire.PolicyVerdict{
					Action: wire.PolicyActionDeny,
					Flags:  flagMask(wire.PolicyFlagSockmapEligible),
				},
			}},
			wantErrPart: "SOCKMAP_ELIGIBLE requires ALLOW action",
		},
		{
			name: "sockmap incompatible with l7",
			mode: UnknownIdentityFailOpen,
			rules: []Rule{{
				SrcIdentity: 1, DstIdentity: 2, DstPort: 80, Protocol: 6, Direction: DirectionIngress,
				Verdict: wire.PolicyVerdict{
					Action: wire.PolicyActionAllow,
					Flags:  flagMask(wire.PolicyFlagSockmapEligible) | flagMask(wire.PolicyFlagL7Required),
				},
			}},
			wantErrPart: "SOCKMAP_ELIGIBLE is incompatible with L7_REQUIRED",
		},
		{
			name: "sockmap incompatible with mtls",
			mode: UnknownIdentityFailOpen,
			rules: []Rule{{
				SrcIdentity: 1, DstIdentity: 2, DstPort: 80, Protocol: 6, Direction: DirectionIngress,
				Verdict: wire.PolicyVerdict{
					Action: wire.PolicyActionAllow,
					Flags:  flagMask(wire.PolicyFlagSockmapEligible) | flagMask(wire.PolicyFlagMTLSRequired),
				},
			}},
			wantErrPart: "SOCKMAP_ELIGIBLE is incompatible with MTLS_REQUIRED",
		},
		{
			name: "duplicate keys rejected",
			mode: UnknownIdentityFailOpen,
			rules: []Rule{
				{
					SrcIdentity: 1, DstIdentity: 2, DstPort: 80, Protocol: 6, Direction: DirectionIngress,
					Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
				},
				{
					SrcIdentity: 1, DstIdentity: 2, DstPort: 80, Protocol: 6, Direction: DirectionIngress,
					Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
				},
			},
			wantErrPart: "duplicates existing key",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewEvaluator(tt.mode, tt.rules)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErrPart)
			}
			if !strings.Contains(err.Error(), tt.wantErrPart) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErrPart, err.Error())
			}
		})
	}
}

func TestEvaluatorDeterministicOutput(t *testing.T) {
	t.Parallel()

	rules := []Rule{{
		SrcIdentity: 10,
		DstIdentity: 20,
		DstPort:     8080,
		Protocol:    6,
		Direction:   DirectionIngress,
		Verdict: wire.PolicyVerdict{
			Action: wire.PolicyActionRedirectProxy,
			Flags:  flagMask(wire.PolicyFlagL7Required),
		},
	}}
	eval := mustEval(t, UnknownIdentityFailClosed, rules)

	in := Input{
		SrcIdentity: 10,
		DstIdentity: 20,
		DstPort:     8080,
		Protocol:    6,
		Direction:   DirectionIngress,
	}

	first, err := eval.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("first evaluate failed: %v", err)
	}

	for i := 0; i < 128; i++ {
		got, err := eval.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatalf("evaluate[%d] failed: %v", i, err)
		}
		if got != first {
			t.Fatalf("non-deterministic output at iter %d: first=%+v got=%+v", i, first, got)
		}
	}
}

func TestEvaluateContextCanceled(t *testing.T) {
	t.Parallel()
	eval := mustEval(t, UnknownIdentityFailClosed, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := eval.Evaluate(ctx, Input{
		SrcIdentity: 1,
		DstIdentity: 2,
		DstPort:     80,
		Protocol:    6,
		Direction:   DirectionIngress,
	})
	if err == nil {
		t.Fatal("expected canceled context error")
	}
}

func TestEvaluateNilContext(t *testing.T) {
	t.Parallel()
	eval := mustEval(t, UnknownIdentityFailClosed, nil)
	_, err := eval.Evaluate(nil, Input{
		SrcIdentity: 1,
		DstIdentity: 2,
		DstPort:     80,
		Protocol:    6,
		Direction:   DirectionIngress,
	})
	if err == nil {
		t.Fatal("expected nil context error")
	}
	if !strings.Contains(err.Error(), "nil context") {
		t.Fatalf("expected nil context error, got: %v", err)
	}
}

func TestEvaluateUnknownIdentityPrecedenceOverRule(t *testing.T) {
	t.Parallel()

	rule := Rule{
		SrcIdentity: 101,
		DstIdentity: 202,
		DstPort:     8443,
		Protocol:    6,
		Direction:   DirectionIngress,
		Verdict: wire.PolicyVerdict{
			Action: wire.PolicyActionRedirectProxy,
			Flags:  flagMask(wire.PolicyFlagL7Required),
		},
	}

	failOpenEval := mustEval(t, UnknownIdentityFailOpen, []Rule{rule})
	failClosedEval := mustEval(t, UnknownIdentityFailClosed, []Rule{rule})

	openVerdict, err := failOpenEval.Evaluate(context.Background(), Input{
		SrcIdentity: wire.IdentityUnknown,
		DstIdentity: 202,
		DstPort:     8443,
		Protocol:    6,
		Direction:   DirectionIngress,
	})
	if err != nil {
		t.Fatalf("fail-open evaluate failed: %v", err)
	}
	if openVerdict.Action != wire.PolicyActionAllow {
		t.Fatalf("fail-open unknown identity should force allow, got %+v", openVerdict)
	}

	closedVerdict, err := failClosedEval.Evaluate(context.Background(), Input{
		SrcIdentity: wire.IdentityUnknown,
		DstIdentity: 202,
		DstPort:     8443,
		Protocol:    6,
		Direction:   DirectionIngress,
	})
	if err != nil {
		t.Fatalf("fail-closed evaluate failed: %v", err)
	}
	if closedVerdict.Action != wire.PolicyActionDeny {
		t.Fatalf("fail-closed unknown identity should force deny, got %+v", closedVerdict)
	}
}

func mustEval(t *testing.T, mode UnknownIdentityMode, rules []Rule) *MapEvaluator {
	t.Helper()
	eval, err := NewEvaluator(mode, rules)
	if err != nil {
		t.Fatalf("NewEvaluator failed: %v", err)
	}
	return eval
}
