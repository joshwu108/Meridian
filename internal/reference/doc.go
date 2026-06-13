// Package reference defines the policy oracle contracts used to verify
// compiler correctness.
package reference

import (
	"context"

	"github.com/joshuawu/meridian/pkg/wire"
)

// Input represents one flow tuple evaluated by the oracle.
type Input struct {
	SrcIdentity wire.IdentityID
	DstIdentity wire.IdentityID
	DstPort     uint16
	Protocol    uint8
	Direction   uint8
}

// Evaluator returns the expected verdict for one flow tuple.
type Evaluator interface {
	Evaluate(context.Context, Input) (wire.PolicyVerdict, error)
}
