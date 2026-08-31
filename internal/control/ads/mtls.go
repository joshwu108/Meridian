package ads

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/joshuawu/meridian/internal/control/ca"
)

// ServerTLSOption returns a grpc.ServerOption that enforces mTLS on the ADS
// stream using auth as the trust anchor (CP-4). The node-cert mTLS requirement:
//   - Clients must present a certificate signed by auth's trust pool.
//   - The peer certificate must carry a valid node SPIFFE ID
//     (spiffe://<td>/node/<id>) — enforced by ServerPeerVerifier.
//
// Unauthenticated or non-node-cert connections are rejected by the TLS
// handshake before any gRPC stream is established.
func ServerTLSOption(auth *ca.Authority, serverCerts []tls.Certificate) grpc.ServerOption {
	cfg := &tls.Config{
		Certificates: serverCerts,
		ClientCAs:    auth.TrustPool(),
		ClientAuth:   tls.RequireAndVerifyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return fmt.Errorf("ads mtls: no verified peer chain")
			}
			leaf := verifiedChains[0][0]
			if err := validateNodeCert(leaf); err != nil {
				return fmt.Errorf("ads mtls: peer cert rejected: %w", err)
			}
			return nil
		},
		MinVersion: tls.VersionTLS13,
	}
	return grpc.Creds(credentials.NewTLS(cfg))
}

// ClientTLSOption returns a grpc.DialOption that dials the ADS server with the
// node bootstrap certificate and verifies the server against auth's trust pool.
func ClientTLSOption(auth *ca.Authority, boot *ca.Bootstrap) (grpc.DialOption, error) {
	tlsCert, err := boot.TLSCertificate()
	if err != nil {
		return nil, fmt.Errorf("ads mtls: client TLS cert: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		RootCAs:      auth.TrustPool(),
		MinVersion:   tls.VersionTLS13,
	}
	return grpc.WithTransportCredentials(credentials.NewTLS(cfg)), nil
}

// NodeSpiffeIDFromContext extracts the authenticated node SPIFFE ID from the
// TLS peer certificate on an established gRPC stream. Returns an error if the
// peer has no verified node cert (stream should be rejected). Callers use this
// to scope per-agent policy views.
func NodeSpiffeIDFromContext(verifiedChains [][]*x509.Certificate) (string, error) {
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return "", fmt.Errorf("ads mtls: no verified chain in context")
	}
	leaf := verifiedChains[0][0]
	if err := validateNodeCert(leaf); err != nil {
		return "", err
	}
	return leaf.URIs[0].String(), nil
}

// validateNodeCert checks that cert carries exactly one URI SAN with the node
// SPIFFE path pattern spiffe://<domain>/node/<id>. A workload SVID or a cert
// without the /node/ prefix is rejected.
func validateNodeCert(cert *x509.Certificate) error {
	if len(cert.URIs) != 1 {
		return fmt.Errorf("expected 1 URI SAN, got %d", len(cert.URIs))
	}
	u := cert.URIs[0]
	if u.Scheme != "spiffe" {
		return fmt.Errorf("URI SAN scheme %q, want spiffe", u.Scheme)
	}
	if !strings.HasPrefix(u.Path, "/node/") || len(u.Path) <= len("/node/") {
		return fmt.Errorf("URI SAN path %q not a node identity (/node/<id> required)", u.Path)
	}
	return nil
}

// ExtractNodeID extracts the node ID string from a validated node SPIFFE URI.
// E.g. spiffe://cluster.local/node/worker-1 → "worker-1".
func ExtractNodeID(spiffeURI string) (string, error) {
	u, err := url.Parse(spiffeURI)
	if err != nil {
		return "", fmt.Errorf("parse SPIFFE ID: %w", err)
	}
	parts := strings.SplitN(u.Path, "/node/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", fmt.Errorf("cannot extract node ID from %q", spiffeURI)
	}
	return parts[1], nil
}
