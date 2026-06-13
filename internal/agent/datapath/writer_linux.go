//go:build linux

package datapath

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/joshuawu/meridian/pkg/wire"
)

type bpfMap interface {
	Update(key, value any, flags ebpf.MapUpdateFlags) error
	Delete(key any) error
}

type writer struct {
	identityMap     bpfMap
	policyMap       bpfMap
	identityKeyByID map[wire.IdentityID]uint32
}

func NewWriter(identityMap, policyMap *ebpf.Map) Writer {
	return &writer{
		identityMap:     identityMap,
		policyMap:       policyMap,
		identityKeyByID: make(map[wire.IdentityID]uint32),
	}
}

func newWriter(identityMap, policyMap bpfMap) *writer {
	return &writer{
		identityMap:     identityMap,
		policyMap:       policyMap,
		identityKeyByID: make(map[wire.IdentityID]uint32),
	}
}

func (w *writer) Apply(_ context.Context, plan wire.CommitPlan) error {
	if err := w.applyIdentityUpserts(plan.IdentityUpserts); err != nil {
		return err
	}
	if err := w.applyPolicyUpserts(plan.PolicyUpserts); err != nil {
		return err
	}
	if err := w.applyPolicyDeletes(plan.PolicyDeletes); err != nil {
		return err
	}
	if err := w.applyIdentityDeletes(plan.IdentityDeletes); err != nil {
		return err
	}
	return nil
}

func (w *writer) applyIdentityUpserts(upserts []wire.Identity) error {
	for _, identity := range upserts {
		entry, err := translateIdentity(identity)
		if err != nil {
			return err
		}
		if err := w.identityMap.Update(entry.Key, entry.Value, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("datapath apply identity upsert id=%d ip_key=%#08x: %w", identity.ID, entry.Key, err)
		}
		w.identityKeyByID[identity.ID] = entry.Key
	}
	return nil
}

func (w *writer) applyPolicyUpserts(upserts []wire.PolicyRule) error {
	for _, rule := range upserts {
		key := translatePolicyRuleKey(rule.Key)
		verdict := translatePolicyVerdict(rule.Verdict)
		if err := w.policyMap.Update(key, verdict, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("datapath apply policy upsert key=%s: %w", formatPolicyRuleKey(rule.Key), err)
		}
	}
	return nil
}

func (w *writer) applyIdentityDeletes(deletes []wire.IdentityID) error {
	for _, identityID := range deletes {
		ipKey, ok := w.identityKeyByID[identityID]
		if !ok {
			// We only track keys observed by this writer instance.
			continue
		}
		if err := w.identityMap.Delete(ipKey); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("datapath apply identity delete id=%d ip_key=%#08x: %w", identityID, ipKey, err)
		}
		delete(w.identityKeyByID, identityID)
	}
	return nil
}

func (w *writer) applyPolicyDeletes(deletes []wire.PolicyRuleKey) error {
	for _, ruleKey := range deletes {
		key := translatePolicyRuleKey(ruleKey)
		if err := w.policyMap.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("datapath apply policy delete key=%s: %w", formatPolicyRuleKey(ruleKey), err)
		}
	}
	return nil
}

func formatPolicyRuleKey(key wire.PolicyRuleKey) string {
	return fmt.Sprintf(
		"src=%d dst=%d port=%d proto=%d dir=%d",
		key.SrcIdentity,
		key.DstIdentity,
		key.DstPort,
		key.Protocol,
		key.Direction,
	)
}
