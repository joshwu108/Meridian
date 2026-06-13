// Package supervisor coordinates agent components and their lifecycle.
//
// Phase 0 ticket P0-002 only introduces contracts. Runtime orchestration is
// implemented in later phases.
package supervisor

import "context"

// Component is a long-lived agent actor managed by the supervisor.
type Component interface {
	// Name returns a stable component identifier for logs and metrics.
	Name() string
	// Run blocks until shutdown or fatal error.
	Run(context.Context) error
}

// Runner starts and stops a component set as a unit.
type Runner interface {
	Run(context.Context) error
}
