package rest

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
)

func newTestServer() *Server {
	return NewServer(store.NewMemory(), identity.NewRegistry())
}

func do(t *testing.T, s *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	return rec
}

func decodeEnvelope(t *testing.T, rec *httptest.ResponseRecorder) envelope {
	t.Helper()
	var env envelope
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode response: %v (body=%q)", err, rec.Body.String())
	}
	return env
}

func TestCreateAndListServiceRoundTrip(t *testing.T) {
	s := newTestServer()

	rec := do(t, s, http.MethodPost, "/services", `{"name":"svc-a","spiffeId":"spiffe://example/svc-a","namespace":"default","podIpv4":"10.0.0.1"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /services = %d, want 201 (body=%q)", rec.Code, rec.Body.String())
	}
	env := decodeEnvelope(t, rec)
	created, ok := env.Data.(map[string]any)
	if !ok {
		t.Fatalf("response data not an object: %#v", env.Data)
	}
	if id, _ := created["ID"].(float64); id == 0 {
		t.Fatalf("server did not allocate a non-zero ID: got %#v", created["ID"])
	}

	list := do(t, s, http.MethodGet, "/services", "")
	if list.Code != http.StatusOK {
		t.Fatalf("GET /services = %d, want 200", list.Code)
	}
	if !strings.Contains(list.Body.String(), "svc-a") {
		t.Fatalf("GET /services missing created service: %q", list.Body.String())
	}
}

func TestCreateServiceFailClosed(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"malformed json", `{"name":`},
		{"unknown field", `{"name":"svc-a","spiffeId":"spiffe://x","bogus":true}`},
		{"missing name", `{"spiffeId":"spiffe://example/x"}`},
		{"missing spiffe id", `{"name":"svc-a"}`},
		{"trailing data", `{"name":"svc-a","spiffeId":"spiffe://x"}{}`},
		{"client supplied id", `{"ID":7,"name":"svc-a","spiffeId":"spiffe://x"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer()
			rec := do(t, s, http.MethodPost, "/services", tc.body)
			if rec.Code < 400 || rec.Code >= 500 {
				t.Fatalf("POST /services %q = %d, want 4xx", tc.body, rec.Code)
			}
			env := decodeEnvelope(t, rec)
			if env.Error == nil || env.Error.Code == "" {
				t.Fatalf("expected structured error envelope, got %#v", env)
			}
		})
	}
}

func TestCreateAndListPolicyRoundTrip(t *testing.T) {
	s := newTestServer()

	body := `{"Key":{"SrcIdentity":1,"DstIdentity":2,"DstPort":8080,"Protocol":6,"Direction":0},"Verdict":{"Action":0,"Flags":0}}`
	rec := do(t, s, http.MethodPost, "/policies", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /policies = %d, want 201 (body=%q)", rec.Code, rec.Body.String())
	}

	list := do(t, s, http.MethodGet, "/policies", "")
	if list.Code != http.StatusOK {
		t.Fatalf("GET /policies = %d, want 200", list.Code)
	}
	env := decodeEnvelope(t, list)
	rules, ok := env.Data.([]any)
	if !ok || len(rules) != 1 {
		t.Fatalf("GET /policies data = %#v, want one rule", env.Data)
	}
}

func TestCreatePolicyFailClosed(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"malformed json", `{"Key":`},
		{"unknown identity src", `{"Key":{"SrcIdentity":0,"DstIdentity":2,"DstPort":80,"Protocol":6,"Direction":0},"Verdict":{"Action":0}}`},
		{"unknown identity dst", `{"Key":{"SrcIdentity":1,"DstIdentity":0,"DstPort":80,"Protocol":6,"Direction":0},"Verdict":{"Action":0}}`},
		{"zero port", `{"Key":{"SrcIdentity":1,"DstIdentity":2,"DstPort":0,"Protocol":6,"Direction":0},"Verdict":{"Action":0}}`},
		{"bad direction", `{"Key":{"SrcIdentity":1,"DstIdentity":2,"DstPort":80,"Protocol":6,"Direction":9},"Verdict":{"Action":0}}`},
		{"bad action", `{"Key":{"SrcIdentity":1,"DstIdentity":2,"DstPort":80,"Protocol":6,"Direction":0},"Verdict":{"Action":42}}`},
		{"unknown field", `{"Key":{"SrcIdentity":1,"DstIdentity":2,"DstPort":80,"Protocol":6,"Direction":0},"Verdict":{"Action":0},"bogus":1}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestServer()
			rec := do(t, s, http.MethodPost, "/policies", tc.body)
			if rec.Code < 400 || rec.Code >= 500 {
				t.Fatalf("POST /policies %q = %d, want 4xx", tc.body, rec.Code)
			}
			if env := decodeEnvelope(t, rec); env.Error == nil {
				t.Fatalf("expected error envelope, got %#v", env)
			}
		})
	}
}

func TestStatusReportsCounts(t *testing.T) {
	s := newTestServer()
	if rec := do(t, s, http.MethodPost, "/services", `{"name":"svc-a","spiffeId":"spiffe://x"}`); rec.Code != http.StatusCreated {
		t.Fatalf("seed service: %d", rec.Code)
	}
	body := `{"Key":{"SrcIdentity":1,"DstIdentity":2,"DstPort":80,"Protocol":6,"Direction":0},"Verdict":{"Action":0}}`
	if rec := do(t, s, http.MethodPost, "/policies", body); rec.Code != http.StatusCreated {
		t.Fatalf("seed policy: %d", rec.Code)
	}

	rec := do(t, s, http.MethodGet, "/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /status = %d, want 200", rec.Code)
	}
	var env struct {
		Data statusBody `json:"data"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if env.Data.Status != "ok" || env.Data.Identities != 1 || env.Data.Policies != 1 {
		t.Fatalf("status = %+v, want {ok 1 1}", env.Data)
	}
}

func TestUnknownRouteAndMethod(t *testing.T) {
	s := newTestServer()

	if rec := do(t, s, http.MethodGet, "/nope", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("GET /nope = %d, want 404", rec.Code)
	}
	// /policies exists for POST and GET only; DELETE must not be routed.
	if rec := do(t, s, http.MethodDelete, "/policies", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE /policies = %d, want 405", rec.Code)
	}
}

func TestValidServiceIsPersistedExactly(t *testing.T) {
	s := newTestServer()
	body, _ := json.Marshal(map[string]any{"name": "svc-a", "spiffeId": "spiffe://example/svc-a"})
	rec := do(t, s, http.MethodPost, "/services", string(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /services = %d", rec.Code)
	}

	var env struct {
		Data wire.Identity `json:"data"`
	}
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Data.ID == wire.IdentityUnknown {
		t.Fatalf("allocated ID is 0")
	}
	if env.Data.SpiffeID != "spiffe://example/svc-a" || env.Data.Name != "svc-a" {
		t.Fatalf("persisted identity mismatch: %+v", env.Data)
	}
}
