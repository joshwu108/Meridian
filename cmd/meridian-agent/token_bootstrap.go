// Token-authenticated node bootstrap client (PKI-2b / Phase 7).
//
// bootstrapFromToken is the agent side of the meridian.ca.NodeBootstrap RPC:
// on a fresh node the agent has no bootstrap certificate yet, only a
// Kubernetes projected SA token. It generates the node key locally (the key
// never crosses the wire), sends token + CSR to the control plane, and turns
// the signed chain into a ca.Bootstrap the RemoteSigner path can use.
//
// No build tag: this file is pure Go so its tests run on any OS (T1).
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/joshuawu/meridian/internal/control/ca"
)

// tokenBootstrapTimeout bounds one bootstrap attempt client-side. The parent
// ctx is the process-lifetime signal context (no deadline), and gRPC would
// otherwise retry an unreachable control plane forever, wedging agent startup.
const tokenBootstrapTimeout = 30 * time.Second

// bootstrapNodeID returns the node ID for the token-bootstrap SPIFFE identity:
// the NODE_NAME env var when set (downward-API spec.nodeName, matching the
// kubelet node name the TokenReview claim is bound to), else the OS hostname.
// The two can diverge (--hostname-override, cloud provider names); the server
// only ever signs for the token's bound node name, so a wrong guess here fails
// closed at issuance rather than minting a mismatched credential.
func bootstrapNodeID() (string, error) {
	if name := os.Getenv("NODE_NAME"); name != "" {
		return name, nil
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("token bootstrap: node id: NODE_NAME unset and hostname unavailable: %w", err)
	}
	return hostname, nil
}

// obtainNodeBootstrap returns the node bootstrap credential for the token
// path. A still-valid credential already persisted at certPath/keyPath is
// reused — restarts must not re-spend the SA token or re-hit TokenReview —
// otherwise (first boot, expired or unusable files) a fresh credential is
// obtained via bootstrapFromToken and persisted for the next restart.
func obtainNodeBootstrap(ctx context.Context, controlAddr, tokenPath, trustDomain, nodeID, certPath, keyPath string) (*ca.Bootstrap, error) {
	if boot, err := ca.LoadBootstrapFiles(certPath, keyPath); err == nil {
		if time.Now().Before(boot.Cert.NotAfter) {
			log.Printf("token bootstrap: reusing persisted credential %s (%s, expires %s)",
				boot.NodeSpiffeID, certPath, boot.Cert.NotAfter.Format(time.RFC3339))
			return boot, nil
		}
		log.Printf("token bootstrap: persisted credential %s expired %s; re-bootstrapping",
			certPath, boot.Cert.NotAfter.Format(time.RFC3339))
	}

	boot, err := bootstrapFromToken(ctx, controlAddr, tokenPath, trustDomain, nodeID)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return nil, fmt.Errorf("token bootstrap: create credential dir: %w", err)
	}
	if err := boot.Save(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("token bootstrap: persist credential: %w", err)
	}
	return boot, nil
}

// bootstrapFromToken reads the projected SA token at tokenPath, generates a
// P-384 node key + CSR for spiffe://<trustDomain>/node/<nodeID>, and calls
// BootstrapWithToken on the control plane at controlAddr (a gRPC target; a
// leading http:// or https:// scheme from a reused --control-addr value is
// stripped). The returned Bootstrap holds the locally generated key and the
// signed chain; callers persist it with Bootstrap.Save so the RemoteSigner
// flow can reload it on later starts.
func bootstrapFromToken(ctx context.Context, controlAddr, tokenPath, trustDomain, nodeID string) (*ca.Bootstrap, error) {
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("token bootstrap: read token %q: %w", tokenPath, err)
	}
	token := strings.TrimSpace(string(tokenBytes))
	if token == "" {
		return nil, fmt.Errorf("token bootstrap: token file %q is empty", tokenPath)
	}

	nodeSpiffeID := ca.NodeSPIFFEID(trustDomain, nodeID)
	key, csr, err := ca.GenerateNodeCSR(nodeSpiffeID)
	if err != nil {
		return nil, fmt.Errorf("token bootstrap: generate CSR for %q: %w", nodeSpiffeID, err)
	}

	ctx, cancel := context.WithTimeout(ctx, tokenBootstrapTimeout)
	defer cancel()

	// TODO(PKI-2b, BLOCKING before production): the channel is insecure — mTLS
	// is impossible here because this RPC exists precisely to obtain the node
	// certificate. The exposure is not limited to this call: the bearer SA
	// token crosses in cleartext (passively capturable and redeemable for this
	// node's cert), and the returned chain becomes the node's trust anchor for
	// ADS, /svid/sign, AND workload mTLS peer verification, so a MITM here
	// compromises the whole node's mesh trust for the cert TTL. Mitigation:
	// one-way TLS verified against a pre-distributed root (kube-root-ca.crt
	// from the token projection, or an operator-provisioned Meridian root),
	// plus chain verification against that pinned root on the response.
	target := stripURLScheme(controlAddr)
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("token bootstrap: dial %q: %w", target, err)
	}
	defer func() {
		if cerr := conn.Close(); cerr != nil {
			log.Printf("token bootstrap: close conn to %q: %v", target, cerr)
		}
	}()

	resp, err := ca.BootstrapWithToken(ctx, conn, token, string(ca.EncodeCSRPEM(csr)))
	if err != nil {
		return nil, fmt.Errorf("token bootstrap: rpc to %q: %w", target, err)
	}

	keyPEM, err := ca.EncodeKeyPEM(key)
	if err != nil {
		return nil, fmt.Errorf("token bootstrap: encode key: %w", err)
	}
	// LoadBootstrap validates the response fail-closed: chain parses, the
	// leaf's public key matches our generated key, and the URI SAN is a
	// well-formed /node/<id> SPIFFE ID.
	boot, err := ca.LoadBootstrap([]byte(resp.CertChainPEM), keyPEM)
	if err != nil {
		return nil, fmt.Errorf("token bootstrap: control plane returned unusable credential: %w", err)
	}
	if boot.NodeSpiffeID != nodeSpiffeID {
		return nil, fmt.Errorf("token bootstrap: issued cert is for %q, requested %q",
			boot.NodeSpiffeID, nodeSpiffeID)
	}
	return boot, nil
}

// stripURLScheme turns a REST-style address (https://host:port) into a plain
// gRPC dial target (host:port); plain targets pass through unchanged.
func stripURLScheme(addr string) string {
	for _, scheme := range []string{"https://", "http://"} {
		if rest, ok := strings.CutPrefix(addr, scheme); ok {
			return rest
		}
	}
	return addr
}
