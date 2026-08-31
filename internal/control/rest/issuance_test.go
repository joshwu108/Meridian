package rest_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joshuawu/meridian/internal/control/ca"
	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/internal/control/rest"
	"github.com/joshuawu/meridian/internal/control/store"
)

// startMTLSIssuanceServer creates an httptest server configured for mTLS
// backed by auth and registers the /svid/sign endpoint via WithCA.
func startMTLSIssuanceServer(t *testing.T, auth *ca.Authority) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	serverBoot, err := ca.IssueBootstrap(auth, "control-plane")
	if err != nil {
		t.Fatalf("IssueBootstrap server: %v", err)
	}
	serverTLSCert, err := serverBoot.TLSCertificate()
	if err != nil {
		t.Fatalf("server TLSCertificate: %v", err)
	}
	srv := rest.NewServer(store.NewMemory(), identity.NewRegistry()).WithCA(auth)
	ts := httptest.NewUnstartedServer(srv)
	ts.TLS = &tls.Config{
		Certificates: []tls.Certificate{serverTLSCert},
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    auth.TrustPool(),
		MinVersion:   tls.VersionTLS13,
	}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts, auth.TrustPool()
}

func makeNodeHTTPClient(t *testing.T, trustPool *x509.CertPool, boot *ca.Bootstrap) *http.Client {
	t.Helper()
	tlsCert, err := boot.TLSCertificate()
	if err != nil {
		t.Fatalf("TLSCertificate: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
				// InsecureSkipVerify skips hostname check only; we verify the
				// server cert chain manually below. The server presents a SPIFFE
				// URI SAN cert (no IP SANs) so IP-based hostname verification
				// always fails — same pattern as the ADS mTLS test.
				InsecureSkipVerify: true, //nolint:gosec // test only
				VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
					if len(rawCerts) == 0 {
						return nil // not our job in this test
					}
					cert, err := x509.ParseCertificate(rawCerts[0])
					if err != nil {
						return err
					}
					inter := x509.NewCertPool()
					for _, r := range rawCerts[1:] {
						if c, e := x509.ParseCertificate(r); e == nil {
							inter.AddCert(c)
						}
					}
					_, err = cert.Verify(x509.VerifyOptions{
						Roots:         trustPool,
						Intermediates: inter,
						KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
					})
					return err
				},
				MinVersion: tls.VersionTLS13,
			},
		},
	}
}

func makeWorkloadCSRPEM(t *testing.T, spiffeID string) string {
	t.Helper()
	_, csr, err := ca.GenerateCSR(spiffeID)
	if err != nil {
		t.Fatalf("GenerateCSR: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw}))
}

func postSignSVID(t *testing.T, client *http.Client, url, csrPemStr, spiffeID string) *http.Response {
	t.Helper()
	csrJSON, _ := json.Marshal(csrPemStr)
	idJSON, _ := json.Marshal(spiffeID)
	body := `{"csr_pem":` + string(csrJSON) + `,"spiffe_id":` + string(idJSON) + `}`
	resp, err := client.Post(url+"/svid/sign", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST /svid/sign: %v", err)
	}
	return resp
}

func TestIssuanceEndpointHappyPath(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	ts, pool := startMTLSIssuanceServer(t, auth)

	nodeBoot, err := ca.IssueBootstrap(auth, "node-1")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}
	client := makeNodeHTTPClient(t, pool, nodeBoot)

	spiffeID := ca.WorkloadSPIFFEID("cluster.local", "default", "svc-a")
	resp := postSignSVID(t, client, ts.URL, makeWorkloadCSRPEM(t, spiffeID), spiffeID)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201; body: %s", resp.StatusCode, body)
	}

	var env struct {
		Data struct {
			ChainPEM  string `json:"chain_pem"`
			ExpiresAt string `json:"expires_at"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Data.ChainPEM == "" {
		t.Fatal("chain_pem empty")
	}
	if env.Data.ExpiresAt == "" {
		t.Fatal("expires_at empty")
	}

	// Parse and verify the returned chain.
	var certs []*x509.Certificate
	rest2 := []byte(env.Data.ChainPEM)
	for {
		var block *pem.Block
		block, rest2 = pem.Decode(rest2)
		if block == nil {
			break
		}
		c, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			t.Fatalf("parse cert: %v", e)
		}
		certs = append(certs, c)
	}
	if len(certs) < 2 {
		t.Fatalf("want >= 2 certs, got %d", len(certs))
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         auth.TrustPool(),
		Intermediates: inter,
		CurrentTime:   certs[0].NotBefore.Add(1),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("chain verify: %v", err)
	}
}

func TestIssuanceEndpointRejectsNodeCertRequest(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	ts, pool := startMTLSIssuanceServer(t, auth)
	nodeBoot, _ := ca.IssueBootstrap(auth, "node-1")
	client := makeNodeHTTPClient(t, pool, nodeBoot)

	nodeSpiffeID := ca.NodeSPIFFEID("cluster.local", "evil-node")
	_, nodeCsr, _ := ca.GenerateNodeCSR(nodeSpiffeID)
	csrStr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: nodeCsr.Raw}))

	resp := postSignSVID(t, client, ts.URL, csrStr, nodeSpiffeID)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnprocessableEntity {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 403 or 422; body: %s", resp.StatusCode, b)
	}
}

func TestIssuanceEndpointRejectsMalformedCSR(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	ts, pool := startMTLSIssuanceServer(t, auth)
	nodeBoot, _ := ca.IssueBootstrap(auth, "node-2")
	client := makeNodeHTTPClient(t, pool, nodeBoot)

	resp := postSignSVID(t, client, ts.URL, "not-a-pem", ca.WorkloadSPIFFEID("cluster.local", "ns", "svc"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 400; body: %s", resp.StatusCode, b)
	}
}

func TestIssuanceEndpointNoCA(t *testing.T) {
	// Without WithCA, /svid/sign is not registered → 404.
	srv := rest.NewServer(store.NewMemory(), identity.NewRegistry())
	ts := httptest.NewTLSServer(srv)
	t.Cleanup(ts.Close)

	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		},
	}
	resp, err := client.Post(ts.URL+"/svid/sign", "application/json",
		strings.NewReader(`{"csr_pem":"x","spiffe_id":"spiffe://x/y"}`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 404 or 501", resp.StatusCode)
	}
}
