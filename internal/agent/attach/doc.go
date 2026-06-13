// Package attach owns TC attachment contracts for agent-managed interfaces.
package attach

import "context"

// ProgramRef is the minimal program handle required by the attachment manager.
// *ebpf.Program satisfies this contract.
type ProgramRef interface {
	FD() int
	Pin(string) error
}

// Manager applies and removes TC attachments for a specific link.
type Manager interface {
	EnsureAttached(context.Context, string) error
	ReplaceProgram(context.Context, string, ProgramRef, string) error
	Detach(context.Context, string) error
}
