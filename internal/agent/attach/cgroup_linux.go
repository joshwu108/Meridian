//go:build linux

package attach

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// CgroupSockOpsManager attaches the sock_ops program to a cgroup v2 directory
// (BPF_CGROUP_SOCK_OPS) so the kernel runs it on every TCP established callback
// for sockets in that cgroup — the MER-48 gated SOCKHASH population path.
//
// It takes a *ebpf.Program (loaded via bpfobj — depguard forbids attach/ from
// importing bpf/ directly) rather than the ProgramRef interface TCManager uses,
// because link.AttachCgroup needs the concrete program handle.
//
// Lifecycle is idempotent within a manager instance: EnsureAttached is a no-op
// once attached; Detach closes the link and is a no-op if not attached.
type CgroupSockOpsManager struct {
	program *ebpf.Program
	lnk     link.Link
}

// NewCgroupSockOpsManager returns a manager for the given sock_ops program.
func NewCgroupSockOpsManager(program *ebpf.Program) *CgroupSockOpsManager {
	return &CgroupSockOpsManager{program: program}
}

// EnsureAttached attaches sock_ops to the cgroup v2 directory at cgroupPath.
// Calling it again while already attached is a no-op (idempotent).
func (m *CgroupSockOpsManager) EnsureAttached(cgroupPath string) error {
	if m.program == nil {
		return errors.New("attach: sock_ops program is nil")
	}
	if cgroupPath == "" {
		return errors.New("attach: cgroup path is empty")
	}
	if m.lnk != nil {
		return nil
	}
	lnk, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupSockOps,
		Program: m.program,
	})
	if err != nil {
		return fmt.Errorf("attach: sock_ops to cgroup %q: %w", cgroupPath, err)
	}
	m.lnk = lnk
	return nil
}

// Detach removes the cgroup attachment. Idempotent: a no-op if not attached.
func (m *CgroupSockOpsManager) Detach() error {
	if m.lnk == nil {
		return nil
	}
	err := m.lnk.Close()
	m.lnk = nil
	if err != nil {
		return fmt.Errorf("attach: detach sock_ops from cgroup: %w", err)
	}
	return nil
}
