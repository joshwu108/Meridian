// Package cli provides the meridian command-line client. It talks to the
// control plane REST API and the agent admin HTTP server via plain HTTP (no
// mTLS at the CLI layer — the admin surface is loopback-only by design).
package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config holds the addresses the CLI uses.
type Config struct {
	ControlAddr string // e.g. "http://localhost:8080"
	AgentAddr   string // e.g. "http://localhost:9902"
}

// DefaultConfig returns sensible localhost defaults.
func DefaultConfig() Config {
	return Config{
		ControlAddr: "http://localhost:8080",
		AgentAddr:   "http://localhost:9902",
	}
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

// getJSON fetches url and decodes the JSON body into dst.
func getJSON(url string, dst any) error {
	resp, err := httpClient.Get(url)
	if err != nil {
		return fmt.Errorf("GET %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s: status %d: %s", url, resp.StatusCode, body)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// postJSON POSTs to url (empty body) and decodes the JSON response into dst.
func postJSON(url string, dst any) error {
	resp, err := httpClient.Post(url, "application/json", nil)
	if err != nil {
		return fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: status %d: %s", url, resp.StatusCode, body)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

// envelope is the REST server's standard response shape.
type envelope struct {
	Data  json.RawMessage `json:"data"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}
