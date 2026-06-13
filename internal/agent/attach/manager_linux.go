//go:build linux

package attach

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	defaultFilterName = "meridian-ingress"
	defaultPriority   = uint16(1)
	defaultHandle     = uint32(1)
)

// TCManager manages clsact + direct-action BPF filter lifecycle on one link.
// It is safe to re-run; repeated EnsureAttached calls are idempotent.
type TCManager struct {
	program    ProgramRef
	programPin string

	filterName string
	priority   uint16
	handle     uint32
}

var _ Manager = (*TCManager)(nil)

// NewManager returns the default production TC attachment manager.
func NewManager(program ProgramRef, programPin string) *TCManager {
	return &TCManager{
		program:    program,
		programPin: programPin,
		filterName: defaultFilterName,
		priority:   defaultPriority,
		handle:     defaultHandle,
	}
}

// EnsureAttached installs clsact (create-or-replace) and the ingress direct-
// action BPF filter for the manager's configured program.
func (m *TCManager) EnsureAttached(ctx context.Context, ifName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("attach: link %q lookup: %w", ifName, err)
	}
	if err := m.replacePinnedProgram(); err != nil {
		return err
	}
	if err := ensureClsact(link); err != nil {
		return fmt.Errorf("attach: ensure clsact on %q: %w", ifName, err)
	}
	if err := m.replaceFilter(link); err != nil {
		return fmt.Errorf("attach: ensure ingress filter on %q: %w", ifName, err)
	}
	return nil
}

// ReplaceProgram swaps the manager's program and replaces the attached filter.
func (m *TCManager) ReplaceProgram(ctx context.Context, ifName string, program ProgramRef, programPin string) error {
	if program == nil {
		return errors.New("attach: replacement program is nil")
	}
	if programPin == "" {
		return errors.New("attach: replacement program pin path is empty")
	}
	m.program = program
	m.programPin = programPin
	return m.EnsureAttached(ctx, ifName)
}

// Detach removes the manager-owned ingress BPF filter and clsact qdisc.
// Missing resources are treated as success so repeated cleanup is idempotent.
func (m *TCManager) Detach(ctx context.Context, ifName string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		if isNotFound(err) {
			return nil
		}
		return fmt.Errorf("attach: link %q lookup: %w", ifName, err)
	}
	if err := m.deleteManagedFilters(link); err != nil {
		return fmt.Errorf("attach: delete ingress filter on %q: %w", ifName, err)
	}
	qdisc := clsactQdisc(link.Attrs().Index)
	if err := netlink.QdiscDel(qdisc); err != nil && !isNotFound(err) {
		return fmt.Errorf("attach: delete clsact on %q: %w", ifName, err)
	}
	return nil
}

func (m *TCManager) replacePinnedProgram() error {
	if m.program == nil {
		return errors.New("attach: program is nil")
	}
	if m.programPin == "" {
		return errors.New("attach: program pin path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(m.programPin), 0o700); err != nil {
		return fmt.Errorf("attach: create program pin dir: %w", err)
	}

	if err := m.program.Pin(m.programPin); err != nil {
		if !errors.Is(err, syscall.EEXIST) && !errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("attach: pin program at %s: %w", m.programPin, err)
		}
		if rmErr := os.Remove(m.programPin); rmErr != nil && !errors.Is(rmErr, fs.ErrNotExist) {
			return fmt.Errorf("attach: remove stale program pin %s: %w", m.programPin, rmErr)
		}
		if pinErr := m.program.Pin(m.programPin); pinErr != nil {
			return fmt.Errorf("attach: re-pin program at %s: %w", m.programPin, pinErr)
		}
	}
	return nil
}

func ensureClsact(link netlink.Link) error {
	return netlink.QdiscReplace(clsactQdisc(link.Attrs().Index))
}

func clsactQdisc(linkIndex int) *netlink.GenericQdisc {
	return &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: linkIndex,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
}

func (m *TCManager) replaceFilter(link netlink.Link) error {
	fd := m.program.FD()
	if fd <= 0 {
		return fmt.Errorf("attach: invalid program fd %d", fd)
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    m.handle,
			Priority:  m.priority,
			Protocol:  uint16(unix.ETH_P_ALL),
		},
		Fd:           fd,
		Name:         m.filterName,
		DirectAction: true,
	}
	return netlink.FilterReplace(filter)
}

func (m *TCManager) deleteManagedFilters(link netlink.Link) error {
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		if isNotFound(err) || errors.Is(err, syscall.EINVAL) {
			return nil
		}
		return err
	}
	for _, f := range filters {
		bpf, ok := f.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		if bpf.Name != m.filterName {
			continue
		}
		if err := netlink.FilterDel(f); err != nil && !isNotFound(err) {
			return err
		}
	}
	return nil
}

func isNotFound(err error) bool {
	var linkNotFound netlink.LinkNotFoundError
	return errors.As(err, &linkNotFound) ||
		errors.Is(err, syscall.ENOENT) ||
		errors.Is(err, fs.ErrNotExist)
}
