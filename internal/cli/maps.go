package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

// MapDump fetches and pretty-prints the agent's identity and policy map
// contents from the /maps/dump endpoint.
func MapDump(cfg Config, w io.Writer) error {
	var env envelope
	if err := getJSON(cfg.AgentAddr+"/maps/dump", &env); err != nil {
		return err
	}
	pretty, err := json.MarshalIndent(env.Data, "", "  ")
	if err != nil {
		return fmt.Errorf("format map dump: %w", err)
	}
	_, err = fmt.Fprintf(w, "%s\n", pretty)
	return err
}
