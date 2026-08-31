package cli

import (
	"encoding/json"
	"fmt"
	"io"
)

// Status prints agent and control-plane status to w.
func Status(cfg Config, w io.Writer) error {
	var agentEnv envelope
	if err := getJSON(cfg.AgentAddr+"/status", &agentEnv); err != nil {
		fmt.Fprintf(w, "agent:   unreachable (%v)\n", err)
	} else {
		pretty, _ := json.MarshalIndent(agentEnv.Data, "", "  ")
		fmt.Fprintf(w, "agent:   %s\n", pretty)
	}

	var ctrlEnv envelope
	if err := getJSON(cfg.ControlAddr+"/status", &ctrlEnv); err != nil {
		fmt.Fprintf(w, "control: unreachable (%v)\n", err)
	} else {
		pretty, _ := json.MarshalIndent(ctrlEnv.Data, "", "  ")
		fmt.Fprintf(w, "control: %s\n", pretty)
	}
	return nil
}
