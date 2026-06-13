package harness

import (
	"context"
	"fmt"

	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/pkg/wire"
)

// SeedIdentity writes one identity upsert through datapath.Writer.
// It never mutates maps directly.
func SeedIdentity(ctx context.Context, w datapath.Writer, identity wire.Identity) error {
	if w == nil {
		return fmt.Errorf("seed identity: nil datapath writer")
	}
	return w.Apply(ctx, wire.CommitPlan{
		IdentityUpserts: []wire.Identity{identity},
	})
}

// SeedPolicy writes one policy upsert through datapath.Writer.
// It never mutates maps directly.
func SeedPolicy(ctx context.Context, w datapath.Writer, rule wire.PolicyRule) error {
	if w == nil {
		return fmt.Errorf("seed policy: nil datapath writer")
	}
	return w.Apply(ctx, wire.CommitPlan{
		PolicyUpserts: []wire.PolicyRule{rule},
	})
}
