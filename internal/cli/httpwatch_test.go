package cli

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPWatchNotImplemented(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/http/watch" {
			t.Errorf("path = %q, want /http/watch", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotImplemented)
	}))
	defer ts.Close()

	var out strings.Builder
	err := HTTPWatch(context.Background(), Config{AgentAddr: ts.URL}, &out)
	if err != nil {
		t.Fatalf("HTTPWatch on 501: %v", err)
	}
	if !strings.Contains(out.String(), "not yet available") {
		t.Fatalf("output = %q, want pending message", out.String())
	}
}

func TestHTTPWatchStreamsDataLines(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"method\":\"GET\",\"path\":\"/a\"}\n\n")
		fmt.Fprint(w, "data: {\"method\":\"POST\",\"path\":\"/b\"}\n\n")
	}))
	defer ts.Close()

	var out strings.Builder
	err := HTTPWatch(context.Background(), Config{AgentAddr: ts.URL}, &out)
	if err != nil {
		t.Fatalf("HTTPWatch: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[0], "/a") || !strings.Contains(lines[1], "/b") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestHTTPWatchErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer ts.Close()

	var out strings.Builder
	err := HTTPWatch(context.Background(), Config{AgentAddr: ts.URL}, &out)
	if err == nil {
		t.Fatal("expected error on 500 status")
	}
}
