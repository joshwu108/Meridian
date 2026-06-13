package harness

import (
	"context"
	"strings"
	"testing"

	"github.com/joshuawu/meridian/pkg/wire"
)

type recordingWriter struct {
	plans []wire.CommitPlan
	err   error
}

func (w *recordingWriter) Apply(_ context.Context, plan wire.CommitPlan) error {
	w.plans = append(w.plans, plan)
	return w.err
}

func TestSeedIdentityUsesDatapathWriter(t *testing.T) {
	w := &recordingWriter{}
	id := wire.Identity{
		ID:        42,
		SpiffeID:  "spiffe://cluster.local/ns/default/sa/frontend",
		Namespace: "default",
		Name:      "frontend",
	}
	if err := SeedIdentity(context.Background(), w, id); err != nil {
		t.Fatalf("SeedIdentity failed: %v", err)
	}
	if len(w.plans) != 1 {
		t.Fatalf("expected exactly one Apply call, got %d", len(w.plans))
	}
	plan := w.plans[0]
	if len(plan.IdentityUpserts) != 1 || plan.IdentityUpserts[0] != id {
		t.Fatalf("unexpected identity plan payload: %+v", plan)
	}
	if len(plan.PolicyUpserts) != 0 || len(plan.IdentityDeletes) != 0 || len(plan.PolicyDeletes) != 0 {
		t.Fatalf("SeedIdentity touched unexpected plan sections: %+v", plan)
	}
}

func TestSeedPolicyUsesDatapathWriter(t *testing.T) {
	w := &recordingWriter{}
	rule := wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: 11,
			DstIdentity: 22,
			DstPort:     8080,
			Protocol:    6,
		},
		Verdict: wire.PolicyVerdict{
			Action: wire.PolicyActionAllow,
			Flags:  0,
		},
	}
	if err := SeedPolicy(context.Background(), w, rule); err != nil {
		t.Fatalf("SeedPolicy failed: %v", err)
	}
	if len(w.plans) != 1 {
		t.Fatalf("expected exactly one Apply call, got %d", len(w.plans))
	}
	plan := w.plans[0]
	if len(plan.PolicyUpserts) != 1 || plan.PolicyUpserts[0] != rule {
		t.Fatalf("unexpected policy plan payload: %+v", plan)
	}
	if len(plan.IdentityUpserts) != 0 || len(plan.IdentityDeletes) != 0 || len(plan.PolicyDeletes) != 0 {
		t.Fatalf("SeedPolicy touched unexpected plan sections: %+v", plan)
	}
}

func TestSeedHelpersRejectNilWriter(t *testing.T) {
	if err := SeedIdentity(context.Background(), nil, wire.Identity{}); err == nil || !strings.Contains(err.Error(), "nil datapath writer") {
		t.Fatalf("expected nil writer error from SeedIdentity, got: %v", err)
	}
	if err := SeedPolicy(context.Background(), nil, wire.PolicyRule{}); err == nil || !strings.Contains(err.Error(), "nil datapath writer") {
		t.Fatalf("expected nil writer error from SeedPolicy, got: %v", err)
	}
}
