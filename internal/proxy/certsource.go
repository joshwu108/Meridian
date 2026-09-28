package proxy

import (
	"crypto/tls"
	"crypto/x509"
)

// CertSource is the proxy's read interface for obtaining a live *tls.Config
// that follows SVID rotation. It is defined here (where it is consumed) so
// the proxy stays decoupled from agent internals (depguard:
// proxy-no-dataplane); the agent's workloadapi CertSource satisfies it
// structurally.
type CertSource interface {
	// TLSConfig returns a *tls.Config whose GetCertificate/GetClientCertificate
	// callbacks always return the latest SVID. Each call returns a new config;
	// the callbacks share the underlying store reference so they stay live.
	TLSConfig(trustPool *x509.CertPool) *tls.Config
}
