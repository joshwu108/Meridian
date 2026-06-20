package xds

import "github.com/joshuawu/meridian/pkg/wire"

// diff computes the wire.CommitPlan that turns the old applied snapshot into the
// new desired snapshot. The datapath.Writer applies the plan in the fixed
// ADR-0008 §3 / D5 kernel order (identity upserts → policy upserts → policy
// deletes → identity deletes), so diff only has to classify each element as an
// upsert (new or changed) or a delete (present in old, absent in new).
func diff(old, next snapshot) wire.CommitPlan {
	var plan wire.CommitPlan

	oldIdent := make(map[wire.IdentityID]wire.Identity, len(old.identities))
	for _, id := range old.identities {
		oldIdent[id.ID] = id
	}
	nextIdent := make(map[wire.IdentityID]struct{}, len(next.identities))
	for _, id := range next.identities {
		nextIdent[id.ID] = struct{}{}
		if prev, ok := oldIdent[id.ID]; !ok || prev != id {
			plan.IdentityUpserts = append(plan.IdentityUpserts, id)
		}
	}
	for _, id := range old.identities {
		if _, ok := nextIdent[id.ID]; !ok {
			plan.IdentityDeletes = append(plan.IdentityDeletes, id.ID)
		}
	}

	oldPol := make(map[wire.PolicyRuleKey]wire.PolicyRule, len(old.policies))
	for _, p := range old.policies {
		oldPol[p.Key] = p
	}
	nextPol := make(map[wire.PolicyRuleKey]struct{}, len(next.policies))
	for _, p := range next.policies {
		nextPol[p.Key] = struct{}{}
		if prev, ok := oldPol[p.Key]; !ok || prev != p {
			plan.PolicyUpserts = append(plan.PolicyUpserts, p)
		}
	}
	for _, p := range old.policies {
		if _, ok := nextPol[p.Key]; !ok {
			plan.PolicyDeletes = append(plan.PolicyDeletes, p.Key)
		}
	}

	return plan
}
