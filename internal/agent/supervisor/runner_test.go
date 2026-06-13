package supervisor

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/joshuawu/meridian/internal/agent/attach"
	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/pkg/wire"
)

type fakeWriter struct {
	applyFn    func(wire.CommitPlan) error
	applyCalls int
}

func (w *fakeWriter) Apply(_ context.Context, plan wire.CommitPlan) error {
	w.applyCalls++
	if w.applyFn != nil {
		return w.applyFn(plan)
	}
	return nil
}

type fakeAttachManager struct {
	ensureErr   error
	ensureCalls int
	detachCalls int
}

func (m *fakeAttachManager) EnsureAttached(_ context.Context, _ string) error {
	m.ensureCalls++
	return m.ensureErr
}

func (m *fakeAttachManager) ReplaceProgram(_ context.Context, _ string, _ attach.ProgramRef, _ string) error {
	return nil
}

func (m *fakeAttachManager) Detach(_ context.Context, _ string) error {
	m.detachCalls++
	return nil
}

func TestStartupRunnerStartupOrderAndIdempotency(t *testing.T) {
	var order []string
	writer := &fakeWriter{applyFn: func(_ wire.CommitPlan) error {
		order = append(order, "writer.apply")
		return nil
	}}
	manager := &fakeAttachManager{}
	closed := 0

	deps := startupDeps{
		openResources: func(_ context.Context, _ StartupOptions) (startupResources, error) {
			order = append(order, "open-maps")
			return startupResources{
				IdentityMap:   struct{}{},
				PolicyMap:     struct{}{},
				AttachProgram: fakeProgramRef{},
				Close: func() error {
					closed++
					return nil
				},
			}, nil
		},
		loadSnapshot: func(_ string) (wire.PolicySnapshot, error) {
			order = append(order, "load-snapshot")
			return wire.PolicySnapshot{
				Identities: []wire.Identity{{ID: 1, PodIPv4: "10.0.0.1"}},
			}, nil
		},
		buildPlan: func(_, _ wire.PolicySnapshot) wire.CommitPlan {
			order = append(order, "build-plan")
			return wire.CommitPlan{
				IdentityUpserts: []wire.Identity{{ID: 1, PodIPv4: "10.0.0.1"}},
			}
		},
		newWriter: func(_, _ any) (datapath.Writer, error) {
			order = append(order, "new-writer")
			return writer, nil
		},
		newAttachManager: func(_ attach.ProgramRef, _ string) attach.Manager {
			order = append(order, "new-attach-manager")
			return manager
		},
	}

	runner := newStartupRunner(StartupOptions{Interface: "eth0"}, deps)
	firstRuntime, err := runner.Startup(context.Background())
	if err != nil {
		t.Fatalf("Startup() error = %v", err)
	}
	secondRuntime, err := runner.Startup(context.Background())
	if err != nil {
		t.Fatalf("Startup() second call error = %v", err)
	}
	if firstRuntime != secondRuntime {
		t.Fatalf("Startup() second call should return the same runtime instance")
	}

	wantOrder := []string{
		"open-maps",
		"load-snapshot",
		"build-plan",
		"new-writer",
		"writer.apply",
		"new-attach-manager",
	}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("startup order mismatch:\n got=%v\nwant=%v", order, wantOrder)
	}
	if writer.applyCalls != 1 {
		t.Fatalf("writer apply calls = %d, want 1", writer.applyCalls)
	}
	if manager.ensureCalls != 1 {
		t.Fatalf("attach ensure calls = %d, want 1", manager.ensureCalls)
	}
	if closed != 0 {
		t.Fatalf("resources should stay open after successful startup, close calls = %d", closed)
	}
}

func TestStartupRunnerRestartSafety(t *testing.T) {
	type pinnedState struct {
		identities map[wire.IdentityID]wire.Identity
		policies   map[wire.PolicyRuleKey]wire.PolicyVerdict
	}
	state := &pinnedState{
		identities: map[wire.IdentityID]wire.Identity{},
		policies:   map[wire.PolicyRuleKey]wire.PolicyVerdict{},
	}
	openCalls := 0

	openResources := func(_ context.Context, _ StartupOptions) (startupResources, error) {
		openCalls++
		return startupResources{
			IdentityMap:   state,
			PolicyMap:     state,
			AttachProgram: fakeProgramRef{},
			Close:         func() error { return nil },
		}, nil
	}
	buildPlan := func(current, desired wire.PolicySnapshot) wire.CommitPlan {
		return wire.CommitPlan{
			IdentityUpserts: desired.Identities,
			PolicyUpserts:   desired.Policies,
		}
	}
	newWriter := func(identityMap, _ any) (datapath.Writer, error) {
		pinned := identityMap.(*pinnedState)
		return &fakeWriter{
			applyFn: func(plan wire.CommitPlan) error {
				for _, id := range plan.IdentityUpserts {
					pinned.identities[id.ID] = id
				}
				for _, policy := range plan.PolicyUpserts {
					pinned.policies[policy.Key] = policy.Verdict
				}
				return nil
			},
		}, nil
	}
	deps := startupDeps{
		openResources: openResources,
		loadSnapshot: func(_ string) (wire.PolicySnapshot, error) {
			return wire.PolicySnapshot{
				Identities: []wire.Identity{{ID: 42, PodIPv4: "10.0.0.42"}},
				Policies: []wire.PolicyRule{{
					Key: wire.PolicyRuleKey{
						SrcIdentity: 42,
						DstIdentity: 7,
						DstPort:     8080,
						Protocol:    6,
						Direction:   wire.DirectionIngress,
					},
					Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
				}},
			}, nil
		},
		buildPlan: buildPlan,
		newWriter: newWriter,
		newAttachManager: func(_ attach.ProgramRef, _ string) attach.Manager {
			return &fakeAttachManager{}
		},
	}

	first := newStartupRunner(StartupOptions{Interface: "eth0"}, deps)
	if _, err := first.Startup(context.Background()); err != nil {
		t.Fatalf("first startup error = %v", err)
	}

	second := newStartupRunner(StartupOptions{Interface: "eth0"}, deps)
	if _, err := second.Startup(context.Background()); err != nil {
		t.Fatalf("second startup error = %v", err)
	}

	if openCalls != 2 {
		t.Fatalf("open resources calls = %d, want 2", openCalls)
	}
	if len(state.identities) != 1 || state.identities[42].PodIPv4 != "10.0.0.42" {
		t.Fatalf("restart should preserve/re-converge identities, got %+v", state.identities)
	}
	if len(state.policies) != 1 {
		t.Fatalf("restart should preserve/re-converge policies, got %+v", state.policies)
	}
}

func TestStartupRunnerMissingMaps(t *testing.T) {
	closed := 0
	runner := newStartupRunner(StartupOptions{}, startupDeps{
		openResources: func(_ context.Context, _ StartupOptions) (startupResources, error) {
			return startupResources{
				IdentityMap: nil,
				PolicyMap:   struct{}{},
				Close: func() error {
					closed++
					return nil
				},
			}, nil
		},
		loadSnapshot: func(_ string) (wire.PolicySnapshot, error) { return wire.PolicySnapshot{}, nil },
		buildPlan:    func(_, _ wire.PolicySnapshot) wire.CommitPlan { return wire.CommitPlan{} },
		newWriter: func(_, _ any) (datapath.Writer, error) {
			t.Fatalf("newWriter should not be called when maps are missing")
			return nil, nil
		},
		newAttachManager: func(_ attach.ProgramRef, _ string) attach.Manager {
			t.Fatalf("newAttachManager should not be called when maps are missing")
			return nil
		},
	})

	_, err := runner.Startup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "missing identity_map handle") {
		t.Fatalf("expected missing identity_map error, got %v", err)
	}
	if closed != 1 {
		t.Fatalf("resources should be closed on missing maps failure, close calls=%d", closed)
	}
}

func TestStartupRunnerAttachFailureRecovery(t *testing.T) {
	manager := &fakeAttachManager{ensureErr: errors.New("attach failed")}
	closed := 0
	runner := newStartupRunner(StartupOptions{Interface: "eth0"}, startupDeps{
		openResources: func(_ context.Context, _ StartupOptions) (startupResources, error) {
			return startupResources{
				IdentityMap:   struct{}{},
				PolicyMap:     struct{}{},
				AttachProgram: fakeProgramRef{},
				Close: func() error {
					closed++
					return nil
				},
			}, nil
		},
		loadSnapshot: func(_ string) (wire.PolicySnapshot, error) { return wire.PolicySnapshot{}, nil },
		buildPlan:    func(_, _ wire.PolicySnapshot) wire.CommitPlan { return wire.CommitPlan{} },
		newWriter: func(_, _ any) (datapath.Writer, error) {
			return &fakeWriter{}, nil
		},
		newAttachManager: func(_ attach.ProgramRef, _ string) attach.Manager {
			return manager
		},
	})

	_, err := runner.Startup(context.Background())
	if err == nil || !strings.Contains(err.Error(), "attach tc programs") {
		t.Fatalf("expected attach failure error, got %v", err)
	}
	if manager.detachCalls != 1 {
		t.Fatalf("attach failure should trigger detach cleanup, detach calls=%d", manager.detachCalls)
	}
	if closed != 1 {
		t.Fatalf("attach failure should close resources, close calls=%d", closed)
	}
}

type fakeProgramRef struct{}

func (fakeProgramRef) FD() int          { return 1 }
func (fakeProgramRef) Pin(string) error { return nil }
