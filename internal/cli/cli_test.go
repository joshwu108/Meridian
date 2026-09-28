package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/joshuawu/meridian/internal/control/ca"
)

// fakeServer creates a test HTTP server with canned JSON responses.
func fakeServer(t *testing.T, routes map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	for path, data := range routes {
		data := data
		mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
		})
	}
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestStatusBothReachable(t *testing.T) {
	agentTS := fakeServer(t, map[string]any{"/status": map[string]string{"status": "ok"}})
	ctrlTS := fakeServer(t, map[string]any{"/status": map[string]string{"version": "v1"}})
	cfg := Config{AgentAddr: agentTS.URL, ControlAddr: ctrlTS.URL}
	var buf bytes.Buffer
	if err := Status(cfg, &buf); err != nil {
		t.Fatalf("Status: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "agent:") || !strings.Contains(out, "control:") {
		t.Fatalf("missing agent/control in output:\n%s", out)
	}
}

func TestStatusAgentUnreachable(t *testing.T) {
	ctrlTS := fakeServer(t, map[string]any{"/status": map[string]string{}})
	cfg := Config{AgentAddr: "http://127.0.0.1:1", ControlAddr: ctrlTS.URL}
	var buf bytes.Buffer
	_ = Status(cfg, &buf)
	if !strings.Contains(buf.String(), "unreachable") {
		t.Fatalf("expected unreachable in output:\n%s", buf.String())
	}
}

func TestPolicyListEmpty(t *testing.T) {
	ts := fakeServer(t, map[string]any{"/policies": []any{}})
	var buf bytes.Buffer
	if err := PolicyList(Config{ControlAddr: ts.URL}, &buf); err != nil {
		t.Fatalf("PolicyList: %v", err)
	}
	if !strings.Contains(buf.String(), "no policies") {
		t.Fatalf("expected 'no policies':\n%s", buf.String())
	}
}

func TestPolicyListWithRules(t *testing.T) {
	rules := []map[string]any{
		{"Key": map[string]any{"SrcIdentity": 1, "DstIdentity": 2, "DstPort": 443, "Protocol": 6, "Direction": 0}, "Verdict": map[string]any{"Action": 0, "Flags": 1}},
	}
	ts := fakeServer(t, map[string]any{"/policies": rules})
	var buf bytes.Buffer
	if err := PolicyList(Config{ControlAddr: ts.URL}, &buf); err != nil {
		t.Fatalf("PolicyList: %v", err)
	}
	if !strings.Contains(buf.String(), "ALLOW") {
		t.Fatalf("expected ALLOW:\n%s", buf.String())
	}
}

func TestServicesListEmpty(t *testing.T) {
	ts := fakeServer(t, map[string]any{"/services": []any{}})
	var buf bytes.Buffer
	if err := ServicesList(Config{ControlAddr: ts.URL}, &buf); err != nil {
		t.Fatalf("ServicesList: %v", err)
	}
	if !strings.Contains(buf.String(), "no services") {
		t.Fatalf("expected 'no services':\n%s", buf.String())
	}
}

func TestMapDump(t *testing.T) {
	ts := fakeServer(t, map[string]any{"/maps/dump": map[string]any{"identities": []any{}, "policies": []any{}}})
	var buf bytes.Buffer
	if err := MapDump(Config{AgentAddr: ts.URL}, &buf); err != nil {
		t.Fatalf("MapDump: %v", err)
	}
	if !strings.Contains(buf.String(), "identities") {
		t.Fatalf("expected identities:\n%s", buf.String())
	}
}

func TestCertInspect(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	boot, err := ca.IssueBootstrap(auth, "node-test")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}
	certPEM := ca.EncodeCertPEM(boot.Chain...)

	f, err := os.CreateTemp("", "meridian-cert-*.pem")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	_, _ = f.Write(certPEM)
	f.Close()

	var buf bytes.Buffer
	if err := CertInspect(f.Name(), &buf); err != nil {
		t.Fatalf("CertInspect: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "SPIFFE ID") {
		t.Fatalf("expected SPIFFE ID:\n%s", out)
	}
	if !strings.Contains(out, "cluster.local") {
		t.Fatalf("expected cluster.local:\n%s", out)
	}
	if !strings.Contains(out, "valid") || strings.Contains(out, "EXPIRED") {
		t.Fatalf("expected valid status:\n%s", out)
	}
}

func TestCertInspectNoFile(t *testing.T) {
	if err := CertInspect("/nonexistent/path/cert.pem", &bytes.Buffer{}); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestCertRotate(t *testing.T) {
	mux := http.NewServeMux()
	var gotMethod string
	mux.HandleFunc("/cert/rotate", func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"success": true,
			"data":    map[string]string{"expires_at": "2026-09-29T12:00:00Z"},
		})
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	var buf bytes.Buffer
	if err := CertRotate(Config{AgentAddr: ts.URL}, &buf); err != nil {
		t.Fatalf("CertRotate: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method = %q, want POST", gotMethod)
	}
	out := buf.String()
	if !strings.Contains(out, "2026-09-29T12:00:00Z") {
		t.Fatalf("expected new expiry in output:\n%s", out)
	}
	if !strings.Contains(out, "rotated") {
		t.Fatalf("expected rotation confirmation in output:\n%s", out)
	}
}

func TestCertRotateServerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/cert/rotate", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"success":false,"error":"signer down"}`, http.StatusInternalServerError)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)

	if err := CertRotate(Config{AgentAddr: ts.URL}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error when the agent reports rotation failure")
	}
}

func TestCertRotateAgentUnreachable(t *testing.T) {
	if err := CertRotate(Config{AgentAddr: "http://127.0.0.1:1"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected error when agent is unreachable")
	}
}

func TestCertVerify(t *testing.T) {
	auth, err := ca.NewTestAuthority("cluster.local")
	if err != nil {
		t.Fatalf("NewTestAuthority: %v", err)
	}
	boot, err := ca.IssueBootstrap(auth, "node-v")
	if err != nil {
		t.Fatalf("IssueBootstrap: %v", err)
	}

	writeTemp := func(t *testing.T, data []byte) string {
		t.Helper()
		f, _ := os.CreateTemp("", "meridian-*.pem")
		_, _ = f.Write(data)
		f.Close()
		t.Cleanup(func() { os.Remove(f.Name()) })
		return f.Name()
	}

	certFile := writeTemp(t, ca.EncodeCertPEM(boot.Chain...))
	caFile := writeTemp(t, ca.EncodeCertPEM(auth.RootCert()))

	var buf bytes.Buffer
	if err := CertVerify(certFile, caFile, &buf); err != nil {
		t.Fatalf("CertVerify: %v", err)
	}
	if !strings.Contains(buf.String(), "OK") {
		t.Fatalf("expected OK:\n%s", buf.String())
	}
}
