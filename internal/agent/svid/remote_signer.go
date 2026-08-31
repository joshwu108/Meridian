package svid

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"time"
)

// RemoteSigner implements Signer by posting CSRs to the control plane's
// POST /svid/sign REST endpoint over mTLS (PKI-3). The agent presents its
// bootstrap TLS certificate on every request.
//
// Usage: replace LocalSigner in production; LocalSigner remains for dev/test.
type RemoteSigner struct {
	client   *http.Client
	endpoint string // e.g. "https://control-plane:9443/svid/sign"
}

// NewRemoteSigner constructs a RemoteSigner that dials endpoint with cert as
// its client certificate and verifies the server against trustPool.
func NewRemoteSigner(endpoint string, cert tls.Certificate, trustPool *x509.CertPool) *RemoteSigner {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      trustPool,
			MinVersion:   tls.VersionTLS13,
		},
	}
	return &RemoteSigner{
		endpoint: endpoint,
		client:   &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}
}

// Sign sends the DER-encoded CSR and spiffeID to the control plane and returns
// the signed certificate chain. Returns an error on any HTTP or CA failure.
func (s *RemoteSigner) Sign(ctx context.Context, csrDER []byte, spiffeID string) ([]*x509.Certificate, error) {
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, err := json.Marshal(struct {
		CSRPEM   string `json:"csr_pem"`
		SpiffeID string `json:"spiffe_id"`
	}{CSRPEM: string(csrPEM), SpiffeID: spiffeID})
	if err != nil {
		return nil, fmt.Errorf("remote signer: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("remote signer: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("remote signer: POST %s: %w", s.endpoint, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return nil, fmt.Errorf("remote signer: read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("remote signer: server returned %d: %s", resp.StatusCode, raw)
	}

	// Unwrap the REST envelope: {data: {chain_pem: "...", expires_at: "..."}}
	var envelope struct {
		Data struct {
			ChainPEM string `json:"chain_pem"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("remote signer: decode response: %w", err)
	}
	if envelope.Data.ChainPEM == "" {
		return nil, fmt.Errorf("remote signer: empty chain_pem in response")
	}

	return parseCertChainPEM([]byte(envelope.Data.ChainPEM))
}

// parseCertChainPEM decodes all CERTIFICATE PEM blocks from pemBytes.
func parseCertChainPEM(pemBytes []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no CERTIFICATE blocks in PEM")
	}
	return certs, nil
}
