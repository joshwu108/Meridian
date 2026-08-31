package admin

import (
	"context"
	"encoding/json"
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
	var _ Server = NewServer("127.0.0.1:0", nil)
}
