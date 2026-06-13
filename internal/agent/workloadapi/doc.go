// Package workloadapi defines SPIFFE Workload API server contracts.
package workloadapi

import "context"

// Server serves the SPIFFE Workload API on a Unix domain socket.
type Server interface {
	Serve(context.Context) error
}
