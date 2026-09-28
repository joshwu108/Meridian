package k8s

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/joshuawu/meridian/pkg/wire"
)

// capturingStore records PutPolicy / DeletePolicy calls and signals each one.
type capturingStore struct {
	mu      sync.Mutex
	puts    []wire.PolicyRule
	deletes []wire.PolicyRuleKey
	changed chan struct{}
}

func newCapturingStore() *capturingStore {
	return &capturingStore{changed: make(chan struct{}, 64)}
}

func (s *capturingStore) PutPolicy(_ context.Context, rule wire.PolicyRule) error {
	s.mu.Lock()
	s.puts = append(s.puts, rule)
	s.mu.Unlock()
	s.changed <- struct{}{}
	return nil
}

func (s *capturingStore) DeletePolicy(_ context.Context, key wire.PolicyRuleKey) error {
	s.mu.Lock()
	s.deletes = append(s.deletes, key)
	s.mu.Unlock()
	s.changed <- struct{}{}
	return nil
}

func (s *capturingStore) snapshot() ([]wire.PolicyRule, []wire.PolicyRuleKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]wire.PolicyRule(nil), s.puts...), append([]wire.PolicyRuleKey(nil), s.deletes...)
}

// waitForCalls blocks until at least n store mutations happened, or fails.
func (s *capturingStore) waitForCalls(t *testing.T, n int) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for i := 0; i < n; i++ {
		select {
		case <-s.changed:
		case <-deadline:
			puts, dels := s.snapshot()
			t.Fatalf("timed out waiting for %d store calls (got %d puts, %d deletes)",
				n, len(puts), len(dels))
		}
	}
}

func testResolver() *StaticResolver {
	return &StaticResolver{
		BySpiffeID: map[string]wire.IdentityID{
			"spiffe://cluster.local/workload/payments/frontend": 101,
			"spiffe://cluster.local/workload/payments/backend":  102,
		},
		ByNamespace: map[string][]wire.IdentityID{
			"payments": {201, 202},
		},
	}
}

func TestCompilePolicyRules(t *testing.T) {
	pol := testPolicy(MeridianPolicySpec{
		Selector: WorkloadSelector{Namespace: "payments"},
		Sources: []string{
			"spiffe://cluster.local/workload/payments/frontend",
		},
		Ports:  []uint16{8443, 9090},
		Action: PolicyActionNameDeny,
	})
	rules, err := CompilePolicyRules(context.Background(), pol, testResolver())
	if err != nil {
		t.Fatalf("CompilePolicyRules: %v", err)
	}
	// 1 source × 2 destinations × 2 ports × 1 protocol (default tcp) = 4 rules.
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4: %+v", len(rules), rules)
	}
	seen := make(map[wire.PolicyRuleKey]bool)
	for _, r := range rules {
		if r.Key.SrcIdentity != 101 {
			t.Errorf("rule src = %d, want 101", r.Key.SrcIdentity)
		}
		if r.Key.DstIdentity != 201 && r.Key.DstIdentity != 202 {
			t.Errorf("rule dst = %d, want 201 or 202", r.Key.DstIdentity)
		}
		if r.Key.Protocol != ProtocolTCP {
			t.Errorf("rule protocol = %d, want tcp (%d)", r.Key.Protocol, ProtocolTCP)
		}
		if r.Key.Direction != wire.DirectionIngress {
			t.Errorf("rule direction = %d, want ingress", r.Key.Direction)
		}
		if r.Verdict.Action != wire.PolicyActionDeny {
			t.Errorf("rule action = %d, want deny", r.Verdict.Action)
		}
		if seen[r.Key] {
			t.Errorf("duplicate rule key %+v", r.Key)
		}
		seen[r.Key] = true
	}
}

func TestCompilePolicyRulesUnknownSource(t *testing.T) {
	pol := testPolicy(MeridianPolicySpec{
		Selector: WorkloadSelector{Namespace: "payments"},
		Sources:  []string{"spiffe://cluster.local/workload/ghost/nobody"},
		Ports:    []uint16{80},
		Action:   PolicyActionNameAllow,
	})
	if _, err := CompilePolicyRules(context.Background(), pol, testResolver()); err == nil {
		t.Fatalf("CompilePolicyRules with unknown source = nil error, want error (fail closed)")
	}
}

func policyUnstructured(t *testing.T, name string, spec MeridianPolicySpec) *unstructured.Unstructured {
	t.Helper()
	pol := testPolicy(spec)
	pol.Name = name
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pol)
	if err != nil {
		t.Fatalf("to unstructured: %v", err)
	}
	return &unstructured.Unstructured{Object: obj}
}

func newFakeDynamicClient(objects ...runtime.Object) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme,
		map[schema.GroupVersionResource]string{
			PolicyGVR(): PolicyKind + "List",
		}, objects...)
}

func startPolicyWatcher(t *testing.T, client *dynamicfake.FakeDynamicClient, store PolicyStore) context.CancelFunc {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	w := NewPolicyWatcher(client, store, testResolver())
	errCh := make(chan error, 1)
	go func() { errCh <- w.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-errCh:
			if err != nil && ctx.Err() == nil {
				t.Errorf("watcher exited: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("watcher did not stop")
		}
	})
	return cancel
}

func TestPolicyWatcherPutsExistingPolicy(t *testing.T) {
	spec := validPolicySpec()
	client := newFakeDynamicClient(policyUnstructured(t, "pre-existing", spec))
	store := newCapturingStore()
	startPolicyWatcher(t, client, store)

	// 1 source × 2 destinations × 1 port = 2 rules.
	store.waitForCalls(t, 2)
	puts, _ := store.snapshot()
	if len(puts) != 2 {
		t.Fatalf("got %d puts, want 2: %+v", len(puts), puts)
	}
	for _, r := range puts {
		if r.Key.DstPort != 8443 || r.Verdict.Action != wire.PolicyActionAllow {
			t.Errorf("unexpected rule %+v", r)
		}
	}
}

func TestPolicyWatcherPutsCreatedPolicy(t *testing.T) {
	client := newFakeDynamicClient()
	store := newCapturingStore()
	startPolicyWatcher(t, client, store)

	spec := validPolicySpec()
	spec.Ports = []uint16{443}
	_, err := client.Resource(PolicyGVR()).Namespace("payments").
		Create(context.Background(), policyUnstructured(t, "late-arrival", spec), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	store.waitForCalls(t, 2)
	puts, _ := store.snapshot()
	for _, r := range puts {
		if r.Key.DstPort != 443 {
			t.Errorf("rule port = %d, want 443", r.Key.DstPort)
		}
	}
}

func TestPolicyWatcherDeletesRemovedPolicy(t *testing.T) {
	spec := validPolicySpec()
	client := newFakeDynamicClient(policyUnstructured(t, "doomed", spec))
	store := newCapturingStore()
	resolver := testResolver()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := NewPolicyWatcher(client, store, resolver)
	go func() { _ = w.Run(ctx) }()
	store.waitForCalls(t, 2) // initial puts

	// Resolver drift after the initial put: the namespace now resolves to a
	// different identity set. Cleanup must still remove the keys that were
	// actually applied, not what the spec would compile to today.
	resolver.mu.Lock()
	resolver.ByNamespace["payments"] = []wire.IdentityID{999}
	resolver.mu.Unlock()

	err := client.Resource(PolicyGVR()).Namespace("payments").
		Delete(context.Background(), "doomed", metav1.DeleteOptions{})
	if err != nil {
		t.Fatalf("delete policy: %v", err)
	}

	store.waitForCalls(t, 2) // the deletes
	puts, dels := store.snapshot()
	if len(dels) != 2 {
		t.Fatalf("got %d deletes, want 2 (puts were %+v)", len(dels), puts)
	}
	putKeys := map[wire.PolicyRuleKey]bool{}
	for _, r := range puts {
		putKeys[r.Key] = true
	}
	for _, k := range dels {
		if !putKeys[k] {
			t.Errorf("deleted key %+v was never put", k)
		}
	}
}

func TestPolicyWatcherSkipsInvalidPolicy(t *testing.T) {
	bad := validPolicySpec()
	bad.Action = "bogus"
	good := validPolicySpec()

	client := newFakeDynamicClient(
		policyUnstructured(t, "bad-policy", bad),
		policyUnstructured(t, "good-policy", good),
	)
	store := newCapturingStore()
	var logMu sync.Mutex
	var logged []string
	w := NewPolicyWatcher(client, store, testResolver())
	w.logf = func(format string, args ...any) {
		logMu.Lock()
		logged = append(logged, fmt.Sprintf(format, args...))
		logMu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	store.waitForCalls(t, 2) // only the good policy's 2 rules
	puts, _ := store.snapshot()
	if len(puts) != 2 {
		t.Fatalf("got %d puts, want 2 (bad policy must be skipped)", len(puts))
	}
	logMu.Lock()
	defer logMu.Unlock()
	if len(logged) == 0 {
		t.Errorf("invalid policy was skipped silently, want a log line")
	}
}

func TestCompilePolicyRulesExplicitProtocols(t *testing.T) {
	pol := testPolicy(MeridianPolicySpec{
		Selector:  WorkloadSelector{Namespace: "payments"},
		Sources:   []string{"spiffe://cluster.local/workload/payments/frontend"},
		Ports:     []uint16{53},
		Protocols: []string{"tcp", "udp"},
		Action:    PolicyActionNameAllow,
	})
	rules, err := CompilePolicyRules(context.Background(), pol, testResolver())
	if err != nil {
		t.Fatalf("CompilePolicyRules: %v", err)
	}
	// 1 source × 2 destinations × 1 port × 2 protocols = 4 rules.
	if len(rules) != 4 {
		t.Fatalf("got %d rules, want 4", len(rules))
	}
	protocols := map[uint8]int{}
	for _, r := range rules {
		protocols[r.Key.Protocol]++
	}
	if protocols[ProtocolTCP] != 2 || protocols[ProtocolUDP] != 2 {
		t.Fatalf("protocol spread = %v, want 2×tcp and 2×udp", protocols)
	}
}

func TestPolicyWatcherUpdateReplacesStaleRules(t *testing.T) {
	spec := validPolicySpec()
	client := newFakeDynamicClient(policyUnstructured(t, "evolving", spec))
	store := newCapturingStore()
	startPolicyWatcher(t, client, store)
	store.waitForCalls(t, 2) // initial puts on port 8443

	updated := spec
	updated.Ports = []uint16{9443}
	obj := policyUnstructured(t, "evolving", updated)
	_, err := client.Resource(PolicyGVR()).Namespace("payments").
		Update(context.Background(), obj, metav1.UpdateOptions{})
	if err != nil {
		t.Fatalf("update policy: %v", err)
	}

	// The update must put the 2 new rules and delete the 2 stale keys.
	store.waitForCalls(t, 4)
	puts, dels := store.snapshot()
	for _, r := range puts[2:] {
		if r.Key.DstPort != 9443 {
			t.Errorf("post-update put port = %d, want 9443", r.Key.DstPort)
		}
	}
	if len(dels) != 2 {
		t.Fatalf("got %d deletes, want 2 stale keys removed", len(dels))
	}
	for _, k := range dels {
		if k.DstPort != 8443 {
			t.Errorf("deleted key port = %d, want stale 8443", k.DstPort)
		}
	}
}

// TestCompilePolicyRulesCapsExpansion pins the compiled-rule expansion
// bound: a spec at the per-field validation limits combined with a large
// destination set must be refused, not expanded.
func TestCompilePolicyRulesCapsExpansion(t *testing.T) {
	sources := make([]string, MaxPolicySources)
	bySpiffe := make(map[string]wire.IdentityID, MaxPolicySources)
	for i := range sources {
		sources[i] = fmt.Sprintf("spiffe://cluster.local/workload/ns/w%d", i)
		bySpiffe[sources[i]] = wire.IdentityID(1000 + i)
	}
	ports := make([]uint16, MaxPolicyPorts)
	for i := range ports {
		ports[i] = uint16(i + 1)
	}
	dsts := make([]wire.IdentityID, 9) // 64×9×64×2 = 73728 > cap
	for i := range dsts {
		dsts[i] = wire.IdentityID(2000 + i)
	}
	resolver := &StaticResolver{
		BySpiffeID:  bySpiffe,
		ByNamespace: map[string][]wire.IdentityID{"payments": dsts},
	}
	pol := testPolicy(MeridianPolicySpec{
		Selector:  WorkloadSelector{Namespace: "payments"},
		Sources:   sources,
		Ports:     ports,
		Protocols: []string{"tcp", "udp"},
		Action:    PolicyActionNameAllow,
	})
	_, err := CompilePolicyRules(context.Background(), pol, resolver)
	if err == nil {
		t.Fatalf("oversized expansion accepted, want error")
	}
	if !strings.Contains(err.Error(), "rules") {
		t.Fatalf("error = %q, want a rule-count bound message", err)
	}
}
