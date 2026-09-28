package admin

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeStatus struct{ msg string }

func (f *fakeStatus) Status() any { return map[string]string{"msg": f.msg} }

// newTestMux builds the HTTP mux the same way Serve does, for use with httptest.
func newTestMux(status StatusSource) http.Handler {
	s := &httpServer{status: status, logf: func(string, ...any) {}}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", s.handleStatus)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func TestAdminStatusEndpoint(t *testing.T) {
	ts := httptest.NewServer(newTestMux(&fakeStatus{msg: "running"}))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if envelope["success"] != true {
		t.Fatalf("success = %v, want true", envelope["success"])
	}
	data, ok := envelope["data"].(map[string]any)
	if !ok {
		t.Fatalf("data is %T, want map", envelope["data"])
	}
	if data["msg"] != "running" {
		t.Fatalf("msg = %v, want \"running\"", data["msg"])
	}
}

func TestAdminHealthzEndpoint(t *testing.T) {
	ts := httptest.NewServer(newTestMux(nil))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "ok\n" {
		t.Fatalf("body = %q, want \"ok\\n\"", body)
	}
}

func TestAdminNilStatusSource(t *testing.T) {
	ts := httptest.NewServer(newTestMux(nil))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/status")
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestAdminContextCancellation(t *testing.T) {
	srv := NewServer("127.0.0.1:0", nil, WithLogf(func(string, ...any) {}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned non-nil on cancellation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not stop after context cancellation")
	}
}

func TestAdminServerImplementsInterface(t *testing.T) {
	if NewServer("127.0.0.1:0", nil) == nil {
		t.Fatal("NewServer returned nil")
	}
}

// fakeRotator implements CertRotator with a canned result.
type fakeRotator struct {
	expiry time.Time
	err    error
	calls  int
}

func (f *fakeRotator) ForceRotate(context.Context) (time.Time, error) {
	f.calls++
	return f.expiry, f.err
}

func newRotateServer(t *testing.T, rotator CertRotator) *httptest.Server {
	t.Helper()
	s := &httpServer{logf: func(string, ...any) {}}
	if rotator != nil {
		WithCertRotator(rotator)(s)
	}
	ts := httptest.NewServer(http.HandlerFunc(s.handleCertRotate))
	t.Cleanup(ts.Close)
	return ts
}

func decodeEnvelope(t *testing.T, r io.Reader) map[string]any {
	t.Helper()
	var env map[string]any
	if err := json.NewDecoder(r).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	return env
}

func TestAdminCertRotate(t *testing.T) {
	expiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)
	rotator := &fakeRotator{expiry: expiry}
	ts := newRotateServer(t, rotator)

	resp, err := http.Post(ts.URL, "application/json", nil)
	if err != nil {
		t.Fatalf("POST /cert/rotate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	env := decodeEnvelope(t, resp.Body)
	if env["success"] != true {
		t.Fatalf("success = %v, want true", env["success"])
	}
	data, ok := env["data"].(map[string]any)
	if !ok {
		t.Fatalf("data is %T, want map", env["data"])
	}
	if got, want := data["expires_at"], expiry.Format(time.RFC3339); got != want {
		t.Fatalf("expires_at = %v, want %v", got, want)
	}
	if rotator.calls != 1 {
		t.Fatalf("rotator calls = %d, want 1", rotator.calls)
	}
}

func TestAdminCertRotateRejectsGET(t *testing.T) {
	rotator := &fakeRotator{expiry: time.Now()}
	ts := newRotateServer(t, rotator)

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("GET /cert/rotate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	if rotator.calls != 0 {
		t.Fatalf("rotator called %d times on GET, want 0", rotator.calls)
	}
}

func TestAdminCertRotateNoRotator(t *testing.T) {
	ts := newRotateServer(t, nil)

	resp, err := http.Post(ts.URL, "application/json", nil)
	if err != nil {
		t.Fatalf("POST /cert/rotate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when no rotator is configured", resp.StatusCode)
	}
}

func TestAdminCertRotateRotatorError(t *testing.T) {
	ts := newRotateServer(t, &fakeRotator{err: errors.New("signer down")})

	resp, err := http.Post(ts.URL, "application/json", nil)
	if err != nil {
		t.Fatalf("POST /cert/rotate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 on rotator failure", resp.StatusCode)
	}
	env := decodeEnvelope(t, resp.Body)
	if env["success"] != false {
		t.Fatalf("success = %v, want false", env["success"])
	}
}
