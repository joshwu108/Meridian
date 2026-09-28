package cli

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"
)

// CertRotate asks the agent's admin server to rotate the workload SVID
// immediately (POST /cert/rotate, bypassing the 2/3-TTL schedule) and prints
// the new certificate's expiry.
func CertRotate(cfg Config, w io.Writer) error {
	var env envelope
	if err := postJSON(cfg.AgentAddr+"/cert/rotate", &env); err != nil {
		return err
	}
	var data struct {
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(env.Data, &data); err != nil {
		return fmt.Errorf("decode rotate response: %w", err)
	}
	if data.ExpiresAt == "" {
		return fmt.Errorf("agent reported no expiry for the rotated certificate")
	}
	fmt.Fprintf(w, "certificate rotated; new expiry: %s\n", data.ExpiresAt)
	return nil
}

// CertInspect reads a PEM certificate file and prints human-readable info.
func CertInspect(certFile string, w io.Writer) error {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read %q: %w", certFile, err)
	}
	var count int
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse certificate #%d: %w", count+1, err)
		}
		count++
		printCert(w, count, cert)
	}
	if count == 0 {
		return fmt.Errorf("no CERTIFICATE PEM blocks found in %q", certFile)
	}
	return nil
}

// CertVerify reads certFile and verifies it against caFile.
func CertVerify(certFile, caFile string, w io.Writer) error {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("read cert %q: %w", certFile, err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("read ca %q: %w", caFile, err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return fmt.Errorf("no CA certs found in %q", caFile)
	}

	block, rest := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("no CERTIFICATE PEM block in %q", certFile)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
	}
	inter := x509.NewCertPool()
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			if c, e := x509.ParseCertificate(b.Bytes); e == nil {
				inter.AddCert(c)
			}
		}
	}

	opts := x509.VerifyOptions{Roots: pool, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	if _, err := leaf.Verify(opts); err != nil {
		fmt.Fprintf(w, "FAIL: %v\n", err)
		return err
	}
	fmt.Fprintf(w, "OK: %s verifies against %s\n", certFile, caFile)
	return nil
}

func printCert(w io.Writer, n int, cert *x509.Certificate) {
	fmt.Fprintf(w, "Certificate #%d:\n", n)
	fmt.Fprintf(w, "  Subject:   %s\n", cert.Subject.CommonName)
	fmt.Fprintf(w, "  Issuer:    %s\n", cert.Issuer.CommonName)
	fmt.Fprintf(w, "  Serial:    %s\n", cert.SerialNumber)
	fmt.Fprintf(w, "  NotBefore: %s\n", cert.NotBefore.UTC().Format(time.RFC3339))
	fmt.Fprintf(w, "  NotAfter:  %s\n", cert.NotAfter.UTC().Format(time.RFC3339))
	remaining := time.Until(cert.NotAfter)
	if remaining < 0 {
		fmt.Fprintf(w, "  Status:    EXPIRED (%.0f hours ago)\n", -remaining.Hours())
	} else {
		fmt.Fprintf(w, "  Status:    valid (%.0f hours remaining)\n", remaining.Hours())
	}
	for _, u := range cert.URIs {
		fmt.Fprintf(w, "  SPIFFE ID: %s\n", u)
	}
	for _, d := range cert.DNSNames {
		fmt.Fprintf(w, "  DNS SAN:   %s\n", d)
	}
}
