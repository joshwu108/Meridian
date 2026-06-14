//go:build linux

package supervisor

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/joshuawu/meridian/internal/agent/attach"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/config"
	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/internal/agent/telemetry"
	"github.com/joshuawu/meridian/pkg/wire"
)

func (r *StartupRuntime) CounterObjects() (*bpfobj.CounterObjects, error) {
	return bpfobj.AsCounterObjects(r.Opaque())
}

// Consumer returns the flow-event consumer the supervisor constructed over the
// pinned flow_events ring buffer. The supervisor owns its lifecycle (MER-27)
// and releases its fd on Close; the agent main loop drives Run.
func (r *StartupRuntime) Consumer() (*telemetry.Consumer, error) {
	consumer, ok := r.resources.Telemetry.(*telemetry.Consumer)
	if !ok || consumer == nil {
		return nil, fmt.Errorf("startup runtime telemetry consumer is %T, want *telemetry.Consumer", r.resources.Telemetry)
	}
	return consumer, nil
}

func NewDefaultStartupRunner(opts StartupOptions) *StartupRunner {
	deps := startupDeps{
		openResources: func(_ context.Context, opts StartupOptions) (startupResources, error) {
			objs, err := bpfobj.LoadCounter(opts.PinDir)
			if err != nil {
				return startupResources{}, err
			}
			// Construct the flow-event consumer now so the supervisor owns its
			// lifecycle (MER-27). The supervisor never calls Run — that is the
			// agent main loop's job — so the New-but-never-Run path is the norm
			// here; Close releases the ringbuf reader fd on shutdown even when
			// Run is never reached (review A-4 / D-8, MER-39).
			consumer, err := telemetry.New(objs.FlowEvents)
			if err != nil {
				_ = objs.Close()
				return startupResources{}, fmt.Errorf("construct telemetry consumer: %w", err)
			}
			return startupResources{
				IdentityMap:   objs.IdentityMap,
				PolicyMap:     objs.PolicyMap,
				AttachProgram: objs.MeridianCounter,
				Telemetry:     consumer,
				Close: func() error {
					closeErr := consumer.Close()
					if cerr := objs.Close(); cerr != nil && closeErr == nil {
						closeErr = cerr
					}
					return closeErr
				},
				Opaque: objs,
			}, nil
		},
		loadSnapshot: func(path string) (wire.PolicySnapshot, error) {
			if path == "" {
				return wire.PolicySnapshot{}, nil
			}
			return config.LoadPolicySnapshot(path)
		},
		buildPlan: config.BuildCommitPlan,
		newWriter: func(identityMap, policyMap any) (datapath.Writer, error) {
			idMap, ok := identityMap.(*ebpf.Map)
			if !ok {
				return nil, fmt.Errorf("identity map handle is %T, want *ebpf.Map", identityMap)
			}
			polMap, ok := policyMap.(*ebpf.Map)
			if !ok {
				return nil, fmt.Errorf("policy map handle is %T, want *ebpf.Map", policyMap)
			}
			return datapath.NewWriter(idMap, polMap), nil
		},
		newAttachManager: func(program attach.ProgramRef, programPinPath string) attach.Manager {
			return attach.NewManager(program, programPinPath)
		},
	}

	if opts.ProgramPinPath == "" {
		opts.ProgramPinPath = filepath.Join(opts.PinDir, "counter_prog")
	}
	return newStartupRunner(opts, deps)
}

// NewPolicyStartupRunner is the MER-29 product-path entry: it loads tc_ingress,
// seeds identity/policy maps from static YAML via datapath.Writer, then attaches
// the production ingress program before any traffic is generated (D16 ordering).
func NewPolicyStartupRunner(opts StartupOptions) *StartupRunner {
	deps := startupDeps{
		openResources: func(_ context.Context, opts StartupOptions) (startupResources, error) {
			objs, err := bpfobj.LoadTcIngress(opts.PinDir)
			if err != nil {
				return startupResources{}, err
			}
			return startupResources{
				IdentityMap:   objs.IdentityMap,
				PolicyMap:     objs.PolicyMap,
				AttachProgram: objs.MeridianTcIngress,
				Close: func() error {
					return objs.Close()
				},
				Opaque: objs,
			}, nil
		},
		loadSnapshot: func(path string) (wire.PolicySnapshot, error) {
			if path == "" {
				return wire.PolicySnapshot{}, nil
			}
			return config.LoadPolicySnapshot(path)
		},
		buildPlan: config.BuildCommitPlan,
		newWriter: func(identityMap, policyMap any) (datapath.Writer, error) {
			idMap, ok := identityMap.(*ebpf.Map)
			if !ok {
				return nil, fmt.Errorf("identity map handle is %T, want *ebpf.Map", identityMap)
			}
			polMap, ok := policyMap.(*ebpf.Map)
			if !ok {
				return nil, fmt.Errorf("policy map handle is %T, want *ebpf.Map", policyMap)
			}
			return datapath.NewWriter(idMap, polMap), nil
		},
		newAttachManager: func(program attach.ProgramRef, programPinPath string) attach.Manager {
			return attach.NewManager(program, programPinPath)
		},
	}

	if opts.ProgramPinPath == "" {
		opts.ProgramPinPath = filepath.Join(opts.PinDir, "tc_ingress_prog")
	}
	return newStartupRunner(opts, deps)
}

// TcIngressObjects returns the loaded tc_ingress collection for integration
// tests that need direct map handles (e.g. denied_flows_map assertions).
func (r *StartupRuntime) TcIngressObjects() (*bpfobj.TcIngressObjects, error) {
	return bpfobj.AsTcIngressObjects(r.Opaque())
}
