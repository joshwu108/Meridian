// Package proxy defines node-proxy contracts.
package proxy

import (
	"context"
	"net"
	"net/netip"

	"github.com/joshuawu/meridian/pkg/wire"
)

// OriginalDestinationResolver resolves the pre-intercept destination/identities
// for a redirected inbound connection.
type OriginalDestinationResolver interface {
	Resolve(net.Conn) (netip.AddrPort, wire.IdentityID, wire.IdentityID, error)
}

// PolicySource provides the latest proxy-relevant policy snapshot.
type PolicySource interface {
	Current(context.Context) (wire.ProxyPolicySnapshot, error)
}

// Server runs the node proxy listeners.
type Server interface {
	Serve(context.Context) error
}
