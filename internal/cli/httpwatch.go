package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// HTTPWatch connects to the agent's /http/watch SSE endpoint and streams L7
// trace events (method, path, src/dst identity, status, latency) to w until
// ctx is cancelled. The endpoint is served by the agent admin server when
// go.opentelemetry.io/otel is provisioned (Phase 5 / shortcoming #8).
//
// Until OTLP is wired, the agent returns a 501 and this command prints a
// helpful message indicating the feature is pending.
func HTTPWatch(ctx context.Context, cfg Config, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		cfg.AgentAddr+"/http/watch", nil)
	if err != nil {
		return fmt.Errorf("http watch: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http watch: connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotImplemented {
		fmt.Fprintln(w, "meridian http watch: not yet available — requires Phase 5 OTLP wiring")
		fmt.Fprintln(w, "see shortcoming #8 in test/integration/orig_dest_test.go")
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("http watch: status %d: %s", resp.StatusCode, body)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			fmt.Fprintln(w, strings.TrimPrefix(line, "data: "))
		}
		if ctx.Err() != nil {
			return nil
		}
	}
	return scanner.Err()
}
