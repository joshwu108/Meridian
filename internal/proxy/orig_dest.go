package proxy

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/joshuawu/meridian/pkg/wire"
)

// IdentityLookup translates a pod IP to a numeric identity ID. It is the
// agent's identity table; the proxy re-resolves dst_identity from the recovered
// original destination IP (ADR-0006 D-D).
type IdentityLookup interface {
	LookupByIP(ip netip.Addr) (wire.IdentityID, bool)
}

// TPROXYResolver implements OriginalDestinationResolver using the local address
// of an IP_TRANSPARENT connection to recover the original destination
// (ADR-0006 D-C / D-E swappable seam). When TPROXY is in effect, LocalAddr()
// on the accepted *net.TCPConn returns the original dst_ip:dst_port the client
// dialed because TPROXY preserves packet addresses (unlike DNAT).
//
// Source identity (second return value) is always wire.IdentityUnknown on the
// outbound :15001 path — src identity is obtained from the mTLS peer cert on
// the inbound :15008 path (ADR-0006 D-D).
type TPROXYResolver struct {
	identityLookup IdentityLookup
}

// NewTPROXYResolver returns a resolver backed by an identity table lookup.
func NewTPROXYResolver(lookup IdentityLookup) *TPROXYResolver {
	return &TPROXYResolver{identityLookup: lookup}
}

// Resolve recovers the original destination from the connection's local address
// and resolves dst_identity from the identity table.
func (r *TPROXYResolver) Resolve(conn net.Conn) (netip.AddrPort, wire.IdentityID, wire.IdentityID, error) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return netip.AddrPort{}, 0, 0,
			fmt.Errorf("tproxy resolver: conn is %T, want *net.TCPConn", conn)
	}
	ap, err := addrPortFrom(tc.LocalAddr())
	if err != nil {
		return netip.AddrPort{}, 0, 0,
			fmt.Errorf("tproxy resolver: recover orig dst: %w", err)
	}

	var dstID wire.IdentityID
	if r.identityLookup != nil {
		if id, ok := r.identityLookup.LookupByIP(ap.Addr()); ok {
			dstID = id
		}
	}
	// srcID is always IdentityUnknown at this layer (ADR-0006 D-D).
	return ap, wire.IdentityUnknown, dstID, nil
}

// OrigDstFromConn returns the original destination of a connection accepted on
// an IP_TRANSPARENT listener. On TPROXY connections, LocalAddr() returns the
// original dst_ip:dst_port the client dialed (not the proxy's bound address),
// because TPROXY preserves packet addresses. This is the primitive the T3 gate
// asserts on directly, and what TPROXYResolver.Resolve wraps for higher layers.
func OrigDstFromConn(conn net.Conn) (netip.AddrPort, error) {
	return addrPortFrom(conn.LocalAddr())
}

func addrPortFrom(addr net.Addr) (netip.AddrPort, error) {
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			return netip.AddrPort{}, fmt.Errorf("cannot parse IP %v", a.IP)
		}
		return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port)), nil
	default:
		ap, err := netip.ParseAddrPort(addr.String())
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("parse addr %q: %w", addr, err)
		}
		return ap, nil
	}
}
