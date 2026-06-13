//go:build linux

package supervisor

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/joshuawu/meridian/bpf"
	"github.com/joshuawu/meridian/internal/agent/attach"
	"github.com/joshuawu/meridian/internal/agent/bpfobj"
	"github.com/joshuawu/meridian/internal/agent/config"
	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/pkg/wire"
)

func (r *StartupRuntime) CounterObjects() (*bpf.CounterObjects, error) {
	objs, ok := r.Opaque().(*bpf.CounterObjects)
	if !ok || objs == nil {
		return nil, fmt.Errorf("startup runtime opaque objects are %T, want *bpf.CounterObjects", r.Opaque())
	}
	return objs, nil
}

func NewDefaultStartupRunner(opts StartupOptions) *StartupRunner {
	deps := startupDeps{
		openResources: func(_ context.Context, opts StartupOptions) (startupResources, error) {
			objs, err := bpfobj.LoadCounter(opts.PinDir)
			if err != nil {
				return startupResources{}, err
			}
			return startupResources{
				IdentityMap:   objs.IdentityMap,
				PolicyMap:     objs.PolicyMap,
				AttachProgram: objs.MeridianCounter,
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
		opts.ProgramPinPath = filepath.Join(opts.PinDir, "counter_prog")
	}
	return newStartupRunner(opts, deps)
}
