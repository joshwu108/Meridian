package proxy

import (
	"crypto/x509"
	"fmt"
	"net/netip"

	"github.com/joshuawu/meridian/pkg/wire"
)

// AuthzResult is the decision from evaluating a flow against the proxy policy.
type AuthzResult uint8

const (
	AuthzAllow         AuthzResult = iota
	AuthzDeny                      // explicit deny or no matching rule (fail-closed)
	AuthzRedirectProxy             // policy says L7/mTLS — proxy handles it
)

// EvalPolicy evaluates whether the flow (srcID, dstID, dst port, proto) is
// permitted by snap. It mirrors the kernel's policy_map lookup: first-match
// wins; no match → AuthzDeny (fail-closed, matching ADR-0001 unknown-identity
// posture and CC-5).
func EvalPolicy(snap wire.ProxyPolicySnapshot, srcID, dstID wire.IdentityID, dst netip.AddrPort, proto uint8) AuthzResult {
	port := dst.Port()
	for _, rule := range snap.Policies {
		if rule.Key.SrcIdentity != srcID {
			continue
		}
		if rule.Key.DstIdentity != dstID {
			continue
		}
		if rule.Key.DstPort != 0 && rule.Key.DstPort != port {
			continue
		}
		if rule.Key.Protocol != 0 && rule.Key.Protocol != proto {
			continue
		}
		switch rule.Verdict.Action {
		case wire.PolicyActionAllow:
			return AuthzAllow
		case wire.PolicyActionDeny:
			return AuthzDeny
		case wire.PolicyActionRedirectProxy:
			return AuthzRedirectProxy
		}
	}
	return AuthzDeny
}

// SPIFFEIDFromCert extracts the validated SPIFFE URI from a peer certificate
// obtained from a completed TLS handshake. The cert must carry exactly one URI
// SAN with scheme "spiffe"; any other shape is a protocol violation (→ reject).
// Callers pass tls.ConnectionState().PeerCertificates[0] from the accepted conn.
func SPIFFEIDFromCert(cert *x509.Certificate) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("authz: nil peer certificate")
	}
	if len(cert.URIs) != 1 {
		return "", fmt.Errorf("authz: peer cert has %d URI SANs, want exactly 1", len(cert.URIs))
	}
	u := cert.URIs[0]
	if u.Scheme != "spiffe" {
		return "", fmt.Errorf("authz: peer cert URI SAN scheme %q, want spiffe", u.Scheme)
	}
	return u.String(), nil
}
