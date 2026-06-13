// Package admin defines the local admin API server contract for the agent.
package admin

import "context"

// Server serves local admin endpoints (status, diagnostics, health).
type Server interface {
	Serve(context.Context) error
}
