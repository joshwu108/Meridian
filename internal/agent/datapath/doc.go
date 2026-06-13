// Package datapath defines the sole-writer contract for kernel policy state.
package datapath

import (
	"context"

	"github.com/joshuawu/meridian/pkg/wire"
)

// Writer is the only component allowed to mutate identity/policy map state.
type Writer interface {
	Apply(context.Context, wire.CommitPlan) error
}
