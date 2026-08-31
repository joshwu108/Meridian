package cli

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/joshuawu/meridian/pkg/wire"
)

// PolicyList prints all compiled policy rules from the control plane.
func PolicyList(cfg Config, w io.Writer) error {
	var env envelope
	if err := getJSON(cfg.ControlAddr+"/policies", &env); err != nil {
		return err
	}
	var rules []wire.PolicyRule
	if err := json.Unmarshal(env.Data, &rules); err != nil {
		return fmt.Errorf("decode policies: %w", err)
	}
	if len(rules) == 0 {
		fmt.Fprintln(w, "(no policies)")
		return nil
	}
	fmt.Fprintf(w, "%-8s %-8s %-6s %-5s %-4s  %-8s %s\n",
		"SRC_ID", "DST_ID", "PORT", "PROTO", "DIR", "ACTION", "FLAGS")
	for _, r := range rules {
		dir := "ingress"
		if r.Key.Direction == wire.DirectionEgress {
			dir = "egress"
		}
		action := actionName(r.Verdict.Action)
		fmt.Fprintf(w, "%-8d %-8d %-6d %-5d %-4s  %-8s 0x%02x\n",
			r.Key.SrcIdentity, r.Key.DstIdentity, r.Key.DstPort,
			r.Key.Protocol, dir[:3], action, r.Verdict.Flags)
	}
	return nil
}

// ServicesList prints all registered service identities.
func ServicesList(cfg Config, w io.Writer) error {
	var env envelope
	if err := getJSON(cfg.ControlAddr+"/services", &env); err != nil {
		return err
	}
	var identities []wire.Identity
	if err := json.Unmarshal(env.Data, &identities); err != nil {
		return fmt.Errorf("decode services: %w", err)
	}
	if len(identities) == 0 {
		fmt.Fprintln(w, "(no services)")
		return nil
	}
	fmt.Fprintf(w, "%-6s %-40s %-15s %s\n", "ID", "SPIFFE_ID", "POD_IP", "NAME")
	for _, id := range identities {
		fmt.Fprintf(w, "%-6d %-40s %-15s %s/%s\n",
			id.ID, id.SpiffeID, id.PodIPv4, id.Namespace, id.Name)
	}
	return nil
}

func actionName(a wire.PolicyAction) string {
	switch a {
	case wire.PolicyActionAllow:
		return "ALLOW"
	case wire.PolicyActionDeny:
		return "DENY"
	case wire.PolicyActionRedirectProxy:
		return "REDIRECT"
	default:
		return fmt.Sprintf("?(%d)", a)
	}
}
