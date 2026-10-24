package main

import "fmt"

// credentialGapReason explains why startPhase4 could not establish a node
// identity, for the branch where neither the standalone CA nor the remote
// signer path is reachable.
//
// It exists because the single message that branch used to log — "neither
// --standalone nor --control-addr given" — is wrong in the common case.
// --control-addr on its own lands here too: the remote path additionally
// needs a bootstrap credential (--token-path, or --bootstrap-cert and
// --bootstrap-key). Operators read the old line as "my --control-addr was
// ignored" and went looking in the wrong place.
//
// Takes plain values rather than phase4Options so it stays in an untagged
// file and is testable on a non-Linux host.
func credentialGapReason(standalone bool, controlAddr, bootstrapCert, tokenPath string) string {
	switch {
	case standalone:
		// Not reachable from the current call site; stated explicitly so a
		// future caller cannot get a misleading string out of this.
		return "node identity unavailable despite --standalone"
	case controlAddr == "":
		return "neither --standalone nor --control-addr given"
	case bootstrapCert == "" && tokenPath == "":
		return fmt.Sprintf("--control-addr=%s given but no node bootstrap credential: "+
			"set --token-path (projected ServiceAccount token) or "+
			"--bootstrap-cert with --bootstrap-key", controlAddr)
	default:
		return fmt.Sprintf("--control-addr=%s given but the node bootstrap credential is incomplete", controlAddr)
	}
}
