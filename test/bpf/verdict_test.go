//go:build bpf

package bpftest

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/joshuawu/meridian/internal/reference"
	"github.com/joshuawu/meridian/pkg/wire"
)

// MER-18: verdict matrix against the reference evaluator.
//
// NOTE: redirect and policy-map-driven deny/redirect require MER-17's policy
// lookup path in tc_ingress; those matrix rows are intentionally opened as
// subtests and marked skipped until that dependency lands.
func TestVerdictMatrixMatchesReferenceEvaluator(t *testing.T) {
	tuples := []struct {
		name             string
		packet           []byte
		input            reference.Input
		unknownMode      reference.UnknownIdentityMode
		seedSrcIdentity  *uint32
		seedDstIdentity  *uint32
		rules            []reference.Rule
		blockedByMissing string
	}{
		{
			name:        "allow identity hit",
			packet:      synthIPv4Packet(6, []byte{10, 42, 0, 2}, []byte{10, 42, 0, 3}),
			unknownMode: reference.UnknownIdentityFailClosed,
			input: reference.Input{
				SrcIdentity: 1001,
				DstIdentity: 2001,
				DstPort:     8080,
				Protocol:    6,
				Direction:   reference.DirectionIngress,
			},
			seedSrcIdentity: ptrUint32(1001),
			seedDstIdentity: ptrUint32(2001),
			rules: []reference.Rule{
				{
					SrcIdentity: 1001,
					DstIdentity: 2001,
					DstPort:     8080,
					Protocol:    6,
					Direction:   reference.DirectionIngress,
					Verdict: wire.PolicyVerdict{
						Action: wire.PolicyActionAllow,
					},
				},
			},
		},
		{
			name:        "deny unknown identity fail-closed",
			packet:      synthIPv4Packet(6, []byte{10, 42, 1, 2}, []byte{10, 42, 1, 3}),
			unknownMode: reference.UnknownIdentityFailClosed,
			input: reference.Input{
				SrcIdentity: wire.IdentityUnknown,
				DstIdentity: 2001,
				DstPort:     8080,
				Protocol:    6,
				Direction:   reference.DirectionIngress,
			},
			seedDstIdentity: ptrUint32(2001),
		},
		{
			name:        "allow unknown identity fail-open",
			packet:      synthIPv4Packet(17, []byte{10, 42, 2, 2}, []byte{10, 42, 2, 3}),
			unknownMode: reference.UnknownIdentityFailOpen,
			input: reference.Input{
				SrcIdentity: wire.IdentityUnknown,
				DstIdentity: 2001,
				DstPort:     8080,
				Protocol:    17,
				Direction:   reference.DirectionIngress,
			},
			seedDstIdentity: ptrUint32(2001),
		},
		{
			name:        "malformed packet follows unknown posture",
			packet:      synthMalformedIPv4IHLPacket(4),
			unknownMode: reference.UnknownIdentityFailClosed,
			input: reference.Input{
				SrcIdentity: wire.IdentityUnknown,
				DstIdentity: wire.IdentityUnknown,
				DstPort:     0,
				Protocol:    6,
				Direction:   reference.DirectionIngress,
			},
		},
		{
			name:        "ipv6 passthrough",
			packet:      synthNonIPv4Packet(0x86dd),
			unknownMode: reference.UnknownIdentityFailOpen,
			input: reference.Input{
				SrcIdentity: wire.IdentityUnknown,
				DstIdentity: wire.IdentityUnknown,
				DstPort:     0,
				Protocol:    0,
				Direction:   reference.DirectionIngress,
			},
		},
		{
			name:        "redirect verdict (pending MER-17 policy path)",
			packet:      synthIPv4Packet(6, []byte{10, 42, 3, 2}, []byte{10, 42, 3, 3}),
			unknownMode: reference.UnknownIdentityFailClosed,
			input: reference.Input{
				SrcIdentity: 1003,
				DstIdentity: 2003,
				DstPort:     8080,
				Protocol:    6,
				Direction:   reference.DirectionIngress,
			},
			seedSrcIdentity: ptrUint32(1003),
			seedDstIdentity: ptrUint32(2003),
			rules: []reference.Rule{
				{
					SrcIdentity: 1003,
					DstIdentity: 2003,
					DstPort:     8080,
					Protocol:    6,
					Direction:   reference.DirectionIngress,
					Verdict: wire.PolicyVerdict{
						Action: wire.PolicyActionRedirectProxy,
					},
				},
			},
			blockedByMissing: "MER-17 policy lookup / redirect action in tc_ingress",
		},
	}

	for _, tc := range tuples {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.blockedByMissing != "" {
				t.Skipf("ticket opened; blocked by dependency: %s", tc.blockedByMissing)
			}

			eval, err := reference.NewEvaluator(tc.unknownMode, tc.rules)
			if err != nil {
				t.Fatalf("new evaluator: %v", err)
			}
			want, err := eval.Evaluate(context.Background(), tc.input)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}

			objs := loadTcIngress(t)
			if tc.seedSrcIdentity != nil {
				seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(tc.packet[26:30]), *tc.seedSrcIdentity)
			}
			if tc.seedDstIdentity != nil {
				seedIdentity(t, objs.IdentityMap, keyFromIPv4Wire(tc.packet[30:34]), *tc.seedDstIdentity)
			}
			setUnknownMode(t, objs.RuntimeConfigMap, tc.unknownMode)

			got, err := objs.MeridianTcIngress.Run(&ebpf.RunOptions{Data: tc.packet})
			if err != nil {
				t.Fatalf("prog run: %v", err)
			}

			wantTCAct, ok := actionToTCAct(want.Action)
			if !ok {
				t.Fatalf("unsupported expected action in current matrix: %d", want.Action)
			}
			if got != wantTCAct {
				t.Fatalf("verdict mismatch: kernel=%d expected(tc)=%d expected(action)=%d", got, wantTCAct, want.Action)
			}
		})
	}
}

func setUnknownMode(t *testing.T, cfgMap *ebpf.Map, mode reference.UnknownIdentityMode) {
	t.Helper()
	var cfg uint32
	if mode == reference.UnknownIdentityFailOpen {
		cfg = cfgFailopenUnknownBit
	}
	if err := cfgMap.Put(cfgSlotUnknownIdentity, cfg); err != nil {
		t.Fatalf("set runtime_config_map mode=%d: %v", mode, err)
	}
}

func actionToTCAct(action wire.PolicyAction) (int, bool) {
	switch action {
	case wire.PolicyActionAllow:
		return tcActOK, true
	case wire.PolicyActionDeny:
		return tcActShot, true
	default:
		return 0, false
	}
}

func ptrUint32(v uint32) *uint32 { return &v }
