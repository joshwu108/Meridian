//go:build linux

package attach

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

type fakeProgram struct {
	fd       int
	pinErrs  []error
	pinCalls int
}

func (f *fakeProgram) FD() int { return f.fd }

func (f *fakeProgram) Pin(string) error {
	f.pinCalls++
	idx := f.pinCalls - 1
	if idx < len(f.pinErrs) {
		return f.pinErrs[idx]
	}
	return nil
}

func TestReplaceProgramValidatesInput(t *testing.T) {
	mgr := &TCManager{}
	ctx := context.Background()

	if err := mgr.ReplaceProgram(ctx, "does-not-matter", nil, "/tmp/x"); err == nil || !strings.Contains(err.Error(), "replacement program is nil") {
		t.Fatalf("expected nil-program validation error, got %v", err)
	}
	if err := mgr.ReplaceProgram(ctx, "does-not-matter", &fakeProgram{fd: 1}, ""); err == nil || !strings.Contains(err.Error(), "replacement program pin path is empty") {
		t.Fatalf("expected empty-pin validation error, got %v", err)
	}
}

func TestEnsureAttachedHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mgr := &TCManager{}
	if err := mgr.EnsureAttached(ctx, "ignored"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestDetachHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	mgr := &TCManager{}
	if err := mgr.Detach(ctx, "ignored"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestReplacePinnedProgramValidatesConfiguration(t *testing.T) {
	mgr := &TCManager{}
	if err := mgr.replacePinnedProgram(); err == nil || !strings.Contains(err.Error(), "program is nil") {
		t.Fatalf("expected nil program error, got %v", err)
	}

	mgr.program = &fakeProgram{fd: 1}
	if err := mgr.replacePinnedProgram(); err == nil || !strings.Contains(err.Error(), "program pin path is empty") {
		t.Fatalf("expected empty pin path error, got %v", err)
	}
}

func TestReplacePinnedProgramHandlesEEXISTWithRePin(t *testing.T) {
	tmp := t.TempDir()
	pinPath := filepath.Join(tmp, "prog")
	prog := &fakeProgram{fd: 1, pinErrs: []error{fs.ErrExist, nil}}
	mgr := &TCManager{
		program:    prog,
		programPin: pinPath,
	}

	if err := mgr.replacePinnedProgram(); err != nil {
		t.Fatalf("replacePinnedProgram returned error: %v", err)
	}
	if prog.pinCalls != 2 {
		t.Fatalf("pin calls = %d, want 2", prog.pinCalls)
	}
}

func TestReplacePinnedProgramReturnsRePinFailure(t *testing.T) {
	tmp := t.TempDir()
	pinPath := filepath.Join(tmp, "prog")
	rePinErr := errors.New("re-pin failed")
	prog := &fakeProgram{fd: 1, pinErrs: []error{syscall.EEXIST, rePinErr}}
	mgr := &TCManager{
		program:    prog,
		programPin: pinPath,
	}

	err := mgr.replacePinnedProgram()
	if err == nil || !strings.Contains(err.Error(), "re-pin program") {
		t.Fatalf("expected re-pin error, got %v", err)
	}
	if !errors.Is(err, rePinErr) {
		t.Fatalf("expected wrapped re-pin failure, got %v", err)
	}
}

func TestReplacePinnedProgramReturnsInitialPinFailure(t *testing.T) {
	tmp := t.TempDir()
	pinPath := filepath.Join(tmp, "prog")
	pinErr := errors.New("pin failed")
	prog := &fakeProgram{fd: 1, pinErrs: []error{pinErr}}
	mgr := &TCManager{
		program:    prog,
		programPin: pinPath,
	}

	err := mgr.replacePinnedProgram()
	if err == nil || !strings.Contains(err.Error(), "pin program") {
		t.Fatalf("expected pin error, got %v", err)
	}
	if !errors.Is(err, pinErr) {
		t.Fatalf("expected wrapped pin failure, got %v", err)
	}
}

