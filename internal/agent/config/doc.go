// Package config defines agent configuration contracts.
//
// P0-002 scaffold only: concrete loading/validation logic arrives later.
package config

// Config is the validated runtime configuration consumed by agent components.
type Config struct {
	NodeID         string
	PinDir         string
	WorkloadSocket string
}

// Provider returns the current configuration snapshot.
type Provider interface {
	Current() Config
}
