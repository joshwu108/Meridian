package supervisor

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/joshuawu/meridian/internal/agent/attach"
	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/internal/agent/linkwatch"
	"github.com/joshuawu/meridian/pkg/wire"
)

type StartupOptions struct {
	PinDir         string
	PolicyFile     string
	Interface      string
	ProgramPinPath string

	// LinkWatcher, when non-nil, drives RTNLGRP_LINK-based TC attach/detach for
	// host-side pod veths alongside the static Interface lifecycle.
	// LinkWatchOnError receives per-interface attach/detach failures; the loop
	// continues on each error (state, not events, is truth).
	LinkWatcher      linkwatch.Watcher
	LinkWatchOnError linkwatch.AttachErrorFunc
}

type startupResources struct {
	IdentityMap   any
	PolicyMap     any
	AttachProgram attach.ProgramRef
	// Telemetry is the flow-event consumer the supervisor constructs but does
	// not start (held as any so the cross-platform runner stays free of the
	// linux-only telemetry.Consumer type). Its fd is released by Close.
	Telemetry any
	Close     func() error
	Opaque    any
}

type startupDeps struct {
	openResources    func(context.Context, StartupOptions) (startupResources, error)
	loadSnapshot     func(string) (wire.PolicySnapshot, error)
	buildPlan        func(wire.PolicySnapshot, wire.PolicySnapshot) wire.CommitPlan
	newWriter        func(identityMap, policyMap any) (datapath.Writer, error)
	newAttachManager func(program attach.ProgramRef, programPinPath string) attach.Manager
}

type StartupRuntime struct {
	resources     startupResources
	writer        datapath.Writer
	attachManager attach.Manager
	iface         string
	attached      bool

	mu     sync.Mutex
	closed bool
}

func (r *StartupRuntime) Opaque() any {
	return r.resources.Opaque
}

func (r *StartupRuntime) Writer() datapath.Writer {
	return r.writer
}

func (r *StartupRuntime) Close(ctx context.Context) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	r.mu.Unlock()

	var closeErr error
	if r.attached && r.attachManager != nil && r.iface != "" {
		if err := r.attachManager.Detach(ctx, r.iface); err != nil {
			closeErr = fmt.Errorf("startup cleanup detach %q: %w", r.iface, err)
		}
	}
	if r.resources.Close != nil {
		if err := r.resources.Close(); err != nil && closeErr == nil {
			closeErr = fmt.Errorf("startup cleanup close resources: %w", err)
		}
	}
	return closeErr
}

type StartupRunner struct {
	opts StartupOptions
	deps startupDeps

	mu              sync.Mutex
	started         bool
	currentSnapshot wire.PolicySnapshot
	runtime         *StartupRuntime
}

func newStartupRunner(opts StartupOptions, deps startupDeps) *StartupRunner {
	return &StartupRunner{
		opts: opts,
		deps: deps,
	}
}

func (r *StartupRunner) Startup(ctx context.Context) (*StartupRuntime, error) {
	r.mu.Lock()
	if r.started {
		runtime := r.runtime
		r.mu.Unlock()
		return runtime, nil
	}
	r.mu.Unlock()

	resources, err := r.deps.openResources(ctx, r.opts)
	if err != nil {
		return nil, fmt.Errorf("startup open pinned maps: %w", err)
	}

	cleanup := func(manager attach.Manager, attached bool) {
		if attached && manager != nil && r.opts.Interface != "" {
			_ = manager.Detach(context.Background(), r.opts.Interface)
		}
		if resources.Close != nil {
			_ = resources.Close()
		}
	}

	if resources.IdentityMap == nil {
		cleanup(nil, false)
		return nil, errors.New("startup open pinned maps: missing identity_map handle")
	}
	if resources.PolicyMap == nil {
		cleanup(nil, false)
		return nil, errors.New("startup open pinned maps: missing policy_map handle")
	}
	if r.opts.Interface != "" && resources.AttachProgram == nil {
		cleanup(nil, false)
		return nil, errors.New("startup open pinned maps: missing attach program")
	}

	desired, err := r.deps.loadSnapshot(r.opts.PolicyFile)
	if err != nil {
		cleanup(nil, false)
		return nil, fmt.Errorf("startup seed state: %w", err)
	}
	plan := r.deps.buildPlan(r.currentSnapshot, desired)

	writer, err := r.deps.newWriter(resources.IdentityMap, resources.PolicyMap)
	if err != nil {
		cleanup(nil, false)
		return nil, fmt.Errorf("startup initialize datapath writer: %w", err)
	}
	if err := writer.Apply(ctx, plan); err != nil {
		cleanup(nil, false)
		return nil, fmt.Errorf("startup seed state apply: %w", err)
	}

	var manager attach.Manager
	attached := false
	if r.opts.Interface != "" {
		manager = r.deps.newAttachManager(resources.AttachProgram, r.opts.ProgramPinPath)
		if err := manager.EnsureAttached(ctx, r.opts.Interface); err != nil {
			cleanup(manager, true)
			return nil, fmt.Errorf("startup attach tc programs on %q: %w", r.opts.Interface, err)
		}
		attached = true
	}

	runtime := &StartupRuntime{
		resources:     resources,
		writer:        writer,
		attachManager: manager,
		iface:         r.opts.Interface,
		attached:      attached,
	}

	r.mu.Lock()
	r.started = true
	r.currentSnapshot = desired
	r.runtime = runtime
	r.mu.Unlock()

	return runtime, nil
}

func (r *StartupRunner) Run(ctx context.Context) error {
	runtime, err := r.Startup(ctx)
	if err != nil {
		return err
	}

	var runErr error
	if r.opts.LinkWatcher != nil {
		// Resolve the attacher: prefer the manager created for the static
		// interface; fall back to a fresh one when no Interface is set but a
		// program ref is available (dynamic-only lifecycle).
		var a linkwatch.Attacher = runtime.attachManager
		if a == nil && runtime.resources.AttachProgram != nil {
			a = r.deps.newAttachManager(runtime.resources.AttachProgram, r.opts.ProgramPinPath)
		}
		if a != nil {
			watchErrCh := make(chan error, 1)
			go func() {
				for {
					err := linkwatch.Run(ctx, r.opts.LinkWatcher, a, r.opts.LinkWatchOnError)
					// non-nil → fatal (subscribe failed) or ctx cancelled → stop.
					// nil with ctx done → clean shutdown.
					// nil with ctx alive → ENOBUFS or clean channel close; loop
					// immediately to reconcile + resubscribe (state, not events,
					// is truth — ARCHITECTURE failure matrix).
					if err != nil || ctx.Err() != nil {
						watchErrCh <- err
						return
					}
				}
			}()
			select {
			case <-ctx.Done():
			case err := <-watchErrCh:
				if err != nil && !errors.Is(err, context.Canceled) {
					runErr = fmt.Errorf("linkwatch: %w", err)
				}
			}
		} else {
			<-ctx.Done()
		}
	} else {
		<-ctx.Done()
	}

	if closeErr := runtime.Close(context.Background()); closeErr != nil && runErr == nil {
		return closeErr
	}
	return runErr
}
