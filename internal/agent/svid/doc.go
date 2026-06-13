// Package svid defines lifecycle contracts for node/workload SVIDs.
package svid

import "context"

// Manager manages SVID issuance/rotation for identities served by this node.
type Manager interface {
	Start(context.Context) error
	Stop(context.Context) error
}
