package cli

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// FlowsWatch connects to the agent's /flows/watch SSE endpoint and streams
// flow events to w until ctx is cancelled or the connection drops.
func FlowsWatch(ctx context.Context, cfg Config, w io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.AgentAddr+"/flows/watch", nil)
	if err != nil {
		return fmt.Errorf("flows watch: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("flows watch: connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("flows watch: status %d: %s", resp.StatusCode, body)
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
