// Package tproxy defines transparent-proxy rule installation contracts.
package tproxy

import "context"

// Installer owns install/teardown of transparent-proxy interception rules.
type Installer interface {
	Install(context.Context) error
	Uninstall(context.Context) error
}
