package admin

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeEventSource implements FlowSource with a pre-loaded channel.
type fakeEventSource struct{ ch chan string }

func (f *fakeEventSource) Subscribe() <-chan string { return f.ch }

func newHTTPWatchMux(src FlowSource) http.Handler {
	s := &httpServer{httpEvents: src, logf: func(string, ...any) {}}
	mux := http.NewServeMux()
	mux.HandleFunc("/http/watch", s.handleHTTPWatch)
	return mux
}

// TestHTTPWatchNotImplementedWithoutSource verifies /http/watch returns 501
// when no L7 event source is configured — the CLI prints a pending message.
func TestHTTPWatchNotImplementedWithoutSource(t *testing.T) {
	ts := httptest.NewServer(newHTTPWatchMux(nil))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/http/watch")
	if err != nil {
		t.Fatalf("GET /http/watch: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", resp.StatusCode)
	}
}

// TestHTTPWatchStreamsEvents verifies /http/watch streams SSE data lines from
// the configured event source.
func TestHTTPWatchStreamsEvents(t *testing.T) {
	src := &fakeEventSource{ch: make(chan string, 2)}
	src.ch <- `{"method":"GET","path":"/api/users","verdict":"allow"}`
	src.ch <- `{"method":"POST","path":"/admin","verdict":"deny"}`
	close(src.ch)

	ts := httptest.NewServer(newHTTPWatchMux(src))
	defer ts.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(ts.URL + "/http/watch")
	if err != nil {
		t.Fatalf("GET /http/watch: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Fatalf("Content-Type = %q, want text/event-stream", ct)
	}

	var dataLines []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			dataLines = append(dataLines, strings.TrimPrefix(line, "data: "))
		}
	}
	if len(dataLines) != 2 {
		t.Fatalf("got %d data lines, want 2: %v", len(dataLines), dataLines)
	}
	if !strings.Contains(dataLines[0], "/api/users") || !strings.Contains(dataLines[1], "deny") {
		t.Fatalf("unexpected events: %v", dataLines)
	}
}
