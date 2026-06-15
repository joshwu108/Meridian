//go:build linux

package attach

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// SkMsgSockhashManager attaches the sk_msg program to the `sockhash` map with
// BPF_SK_MSG_VERDICT so the kernel runs it on sendmsg for every socket member of
// the map — the MER-50 redirect fast path. The attach target is the sockhash map
// fd, not a cgroup.
//
// sk_msg verdict programs attach via the raw prog-attach syscall (no bpf_link on
// 5.15), so this uses link.RawAttachProgram / RawDetachProgram rather than a
// closable Link. Lifecycle is idempotent within the manager instance.
type SkMsgSockhashManager struct {
	program    *ebpf.Program
	sockhashFD int
	attached   bool
}

// NewSkMsgSockhashManager returns a manager attaching sk_msg to the sockhash fd.
func NewSkMsgSockhashManager(program *ebpf.Program, sockhashFD int) *SkMsgSockhashManager {
	return &SkMsgSockhashManager{program: program, sockhashFD: sockhashFD}
}

// EnsureAttached attaches sk_msg to the sockhash map (BPF_SK_MSG_VERDICT).
// Calling it again while already attached is a no-op (idempotent).
func (m *SkMsgSockhashManager) EnsureAttached() error {
	if m.program == nil {
		return errors.New("attach: sk_msg program is nil")
	}
	if m.sockhashFD <= 0 {
		return fmt.Errorf("attach: invalid sockhash fd %d", m.sockhashFD)
	}
	if m.attached {
		return nil
	}
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{
		Target:  m.sockhashFD,
		Program: m.program,
		Attach:  ebpf.AttachSkMsgVerdict,
	}); err != nil {
		return fmt.Errorf("attach: sk_msg to sockhash: %w", err)
	}
	m.attached = true
	return nil
}

// Detach removes the sk_msg verdict attachment. Idempotent.
func (m *SkMsgSockhashManager) Detach() error {
	if !m.attached {
		return nil
	}
	err := link.RawDetachProgram(link.RawDetachProgramOptions{
		Target:  m.sockhashFD,
		Program: m.program,
		Attach:  ebpf.AttachSkMsgVerdict,
	})
	m.attached = false
	if err != nil {
		return fmt.Errorf("attach: detach sk_msg from sockhash: %w", err)
	}
	return nil
}
