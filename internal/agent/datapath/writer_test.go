//go:build linux

package datapath

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/joshuawu/meridian/pkg/wire"
)

type mapOp struct {
	Index int
	Map   string
	Kind  string
	Key   string
	Value string
}

type opRecorder struct {
	ops []mapOp
}

func (r *opRecorder) append(op mapOp) {
	op.Index = len(r.ops)
	r.ops = append(r.ops, op)
}

type fakeMap struct {
	name      string
	recorder  *opRecorder
	state     map[string]string
	failMatch func(op mapOp) bool
}

func newFakeMap(name string, recorder *opRecorder) *fakeMap {
	return &fakeMap{
		name:     name,
		recorder: recorder,
		state:    make(map[string]string),
	}
}

func (m *fakeMap) Update(key, value any, _ ebpf.MapUpdateFlags) error {
	op := mapOp{
		Map:   m.name,
		Kind:  "update",
		Key:   keySignature(key),
		Value: valueSignature(value),
	}
	if m.failMatch != nil && m.failMatch(op) {
		return errors.New("injected map update failure")
	}
	m.recorder.append(op)
	m.state[op.Key] = op.Value
	return nil
}

func (m *fakeMap) Delete(key any) error {
	op := mapOp{
		Map:  m.name,
		Kind: "delete",
		Key:  keySignature(key),
	}
	if m.failMatch != nil && m.failMatch(op) {
		return errors.New("injected map delete failure")
	}
	m.recorder.append(op)
	delete(m.state, op.Key)
	return nil
}

func keySignature(key any) string {
	return fmt.Sprintf("%T:%#v", key, key)
}

func valueSignature(value any) string {
	return fmt.Sprintf("%T:%#v", value, value)
}

func cloneState(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func TestWriterApplyOrdersUpsertsBeforeDeletes(t *testing.T) {
	recorder := &opRecorder{}
	identityMap := newFakeMap("identity_map", recorder)
	policyMap := newFakeMap("policy_map", recorder)
	w := newWriter(identityMap, policyMap)

	plan := wire.CommitPlan{
		PolicyUpserts: []wire.PolicyRule{
			{
				Key: wire.PolicyRuleKey{
					SrcIdentity: 10,
					DstIdentity: 20,
					DstPort:     8080,
					Protocol:    6,
					Direction:   wire.DirectionIngress,
				},
				Verdict: wire.PolicyVerdict{
					Action: wire.PolicyActionAllow,
					Flags:  wire.PolicyFlagAudit,
				},
			},
		},
		IdentityDeletes: []wire.IdentityID{31},
		PolicyDeletes: []wire.PolicyRuleKey{
			{
				SrcIdentity: 11,
				DstIdentity: 21,
				DstPort:     9090,
				Protocol:    17,
				Direction:   wire.DirectionEgress,
			},
		},
	}

	if err := w.Apply(context.Background(), plan); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}

	var latestUpsertIdx = -1
	var earliestDeleteIdx = -1
	for _, op := range recorder.ops {
		if op.Kind == "update" && op.Index > latestUpsertIdx {
			latestUpsertIdx = op.Index
		}
		if op.Kind == "delete" && (earliestDeleteIdx == -1 || op.Index < earliestDeleteIdx) {
			earliestDeleteIdx = op.Index
		}
	}
	if latestUpsertIdx == -1 || earliestDeleteIdx == -1 {
		t.Fatalf("expected both update and delete operations, got %+v", recorder.ops)
	}
	if latestUpsertIdx >= earliestDeleteIdx {
		t.Fatalf("upserts must precede deletes; latest upsert=%d earliest delete=%d ops=%+v", latestUpsertIdx, earliestDeleteIdx, recorder.ops)
	}
}

func TestWriterApplyIdempotentReapply(t *testing.T) {
	recorder := &opRecorder{}
	identityMap := newFakeMap("identity_map", recorder)
	policyMap := newFakeMap("policy_map", recorder)
	w := newWriter(identityMap, policyMap)

	plan := wire.CommitPlan{
		PolicyUpserts: []wire.PolicyRule{
			{
				Key: wire.PolicyRuleKey{
					SrcIdentity: 1,
					DstIdentity: 2,
					DstPort:     80,
					Protocol:    6,
					Direction:   wire.DirectionIngress,
				},
				Verdict: wire.PolicyVerdict{
					Action: wire.PolicyActionRedirectProxy,
					Flags:  wire.PolicyFlagL7Required,
				},
			},
		},
	}

	if err := w.Apply(context.Background(), plan); err != nil {
		t.Fatalf("first Apply() error = %v", err)
	}
	firstIdentityState := cloneState(identityMap.state)
	firstPolicyState := cloneState(policyMap.state)

	if err := w.Apply(context.Background(), plan); err != nil {
		t.Fatalf("second Apply() error = %v", err)
	}
	if !reflect.DeepEqual(firstIdentityState, identityMap.state) {
		t.Fatalf("identity state changed after idempotent reapply: first=%v second=%v", firstIdentityState, identityMap.state)
	}
	if !reflect.DeepEqual(firstPolicyState, policyMap.state) {
		t.Fatalf("policy state changed after idempotent reapply: first=%v second=%v", firstPolicyState, policyMap.state)
	}
}

func TestWriterApplyPartialFailureNamesFailedKey(t *testing.T) {
	recorder := &opRecorder{}
	identityMap := newFakeMap("identity_map", recorder)
	policyMap := newFakeMap("policy_map", recorder)
	w := newWriter(identityMap, policyMap)

	failingKey := wire.PolicyRuleKey{
		SrcIdentity: 101,
		DstIdentity: 202,
		DstPort:     8443,
		Protocol:    6,
		Direction:   wire.DirectionEgress,
	}
	expectedKeyText := formatPolicyRuleKey(failingKey)
	policyMap.failMatch = func(op mapOp) bool {
		return op.Kind == "update" && strings.Contains(op.Key, "101") && strings.Contains(op.Key, "202")
	}

	err := w.Apply(context.Background(), wire.CommitPlan{
		PolicyUpserts: []wire.PolicyRule{
			{
				Key:     failingKey,
				Verdict: wire.PolicyVerdict{Action: wire.PolicyActionDeny},
			},
		},
	})
	if err == nil {
		t.Fatalf("expected Apply() error for injected failure")
	}
	if !strings.Contains(err.Error(), expectedKeyText) {
		t.Fatalf("error must include failed key %q, got %q", expectedKeyText, err.Error())
	}
}

func TestTranslatePolicyKeyDirectionRoundTrip(t *testing.T) {
	for _, direction := range []wire.Direction{wire.DirectionIngress, wire.DirectionEgress} {
		in := wire.PolicyRuleKey{
			SrcIdentity: 7,
			DstIdentity: 9,
			DstPort:     5353,
			Protocol:    17,
			Direction:   direction,
		}
		got := translatePolicyRuleKey(in)
		if got.SrcID != uint32(in.SrcIdentity) ||
			got.DstID != uint32(in.DstIdentity) ||
			got.DstPort != in.DstPort ||
			got.Proto != in.Protocol {
			t.Fatalf("translated key mismatch: got=%+v in=%+v", got, in)
		}
		if got.Direction != uint8(direction) {
			t.Fatalf("direction mismatch: got=%d want=%d", got.Direction, direction)
		}
	}
}

func TestTranslatePolicyVerdictFlagsAndZeroPad(t *testing.T) {
	in := wire.PolicyVerdict{
		Action: wire.PolicyActionRedirectProxy,
		Flags:  wire.PolicyFlagSockmapEligible | wire.PolicyFlagAudit,
	}
	got := translatePolicyVerdict(in)
	if got.Action != uint8(in.Action) {
		t.Fatalf("action mismatch: got=%d want=%d", got.Action, in.Action)
	}
	if got.Flags != uint8(in.Flags) {
		t.Fatalf("flags mismatch: got=%d want=%d", got.Flags, in.Flags)
	}
	if got.Pad != 0 {
		t.Fatalf("policy_verdict pad must be zero, got=%d", got.Pad)
	}
}

func TestTranslateIdentityRequiresIPv4Field(t *testing.T) {
	_, err := translateIdentity(wire.Identity{ID: 99})
	if err == nil {
		t.Fatalf("expected error when wire.Identity has no IPv4 field")
	}
	if !strings.Contains(err.Error(), "id=99") {
		t.Fatalf("expected error naming identity id, got %q", err.Error())
	}
}
