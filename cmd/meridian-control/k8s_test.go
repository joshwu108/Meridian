package main

import (
	"context"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/joshuawu/meridian/internal/control/k8s"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
)

func TestK8sEnabled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		kubeconfig string
		env        map[string]string
		want       bool
	}{
		{
			name: "no kubeconfig and not in a pod: informers stay off",
			want: false,
		},
		{
			name:       "explicit --kubeconfig enables them off-cluster",
			kubeconfig: "/home/dev/.kube/config",
			want:       true,
		},
		{
			name: "in-cluster is detected without a flag",
			env:  map[string]string{"KUBERNETES_SERVICE_HOST": "10.96.0.1"},
			want: true,
		},
		{
			name:       "flag wins when both are present",
			kubeconfig: "/home/dev/.kube/config",
			env:        map[string]string{"KUBERNETES_SERVICE_HOST": "10.96.0.1"},
			want:       true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lookup := func(key string) string { return tc.env[key] }
			if got := k8sEnabled(tc.kubeconfig, lookup); got != tc.want {
				t.Errorf("k8sEnabled(%q) = %v, want %v", tc.kubeconfig, got, tc.want)
			}
		})
	}
}

// TestKubeRESTConfigRejectsMissingKubeconfig checks the error path surfaces
// the bad path rather than silently falling back to in-cluster.
func TestKubeRESTConfigRejectsMissingKubeconfig(t *testing.T) {
	t.Parallel()

	_, err := kubeRESTConfig(t.TempDir() + "/does-not-exist.yaml")
	if err == nil {
		t.Fatal("kubeRESTConfig(missing file) = nil error, want failure")
	}
}

// policyScheme registers the MeridianPolicy list kind the fake dynamic
// client needs to serve a watch for the CRD's GVR.
func policyScheme() (*runtime.Scheme, map[schema.GroupVersionResource]string) {
	return runtime.NewScheme(), map[schema.GroupVersionResource]string{
		k8s.PolicyGVR(): "MeridianPolicyList",
	}
}

// newPolicyObject builds an unstructured MeridianPolicy allowing frontend to
// reach the payments namespace on 8080/tcp.
func newPolicyObject() *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetUnstructuredContent(map[string]any{
		"apiVersion": k8s.GroupName + "/" + k8s.Version,
		"kind":       "MeridianPolicy",
		"metadata": map[string]any{
			"name":      "allow-frontend",
			"namespace": "payments",
		},
		"spec": map[string]any{
			"selector": map[string]any{"namespace": "payments"},
			"sources":  []any{"spiffe://cluster.local/workload/payments/frontend"},
			"ports":    []any{int64(8080)},
			"action":   "allow",
		},
	})
	return u
}

// TestRunPolicyWatcherCompilesCRDIntoStore is the startup-path test: the
// goroutine main launches must take a MeridianPolicy already present at the
// apiserver and land compiled rules in the store, which is what ADS then
// ships to agents. Driven with a fake dynamic client and the StaticResolver,
// so it needs no apiserver (T1).
func TestRunPolicyWatcherCompilesCRDIntoStore(t *testing.T) {
	t.Parallel()

	scheme, listKinds := policyScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme, listKinds, newPolicyObject())

	resolver := &k8s.StaticResolver{
		BySpiffeID: map[string]wire.IdentityID{
			"spiffe://cluster.local/workload/payments/frontend": 101,
		},
		ByNamespace: map[string][]wire.IdentityID{
			"payments": {201},
		},
	}

	st := store.NewMemory()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runPolicyWatcher(ctx, client, st, resolver, func(string, ...any) {})
	}()

	want := wire.PolicyRuleKey{
		SrcIdentity: 101,
		DstIdentity: 201,
		DstPort:     8080,
		Protocol:    k8s.ProtocolTCP,
		Direction:   wire.DirectionIngress,
	}

	deadline := time.After(10 * time.Second)
	for {
		rules, err := st.ListPolicies(ctx)
		if err != nil {
			t.Fatalf("ListPolicies: %v", err)
		}
		if len(rules) == 1 && rules[0].Key == want {
			if rules[0].Verdict.Action != wire.PolicyActionAllow {
				t.Fatalf("compiled verdict = %v, want allow", rules[0].Verdict.Action)
			}
			break
		}
		select {
		case <-deadline:
			t.Fatalf("policy never reached the store; got %+v, want one rule %+v", rules, want)
		case <-time.After(20 * time.Millisecond):
		}
	}

	// Cancelling ctx must stop the watcher goroutine: main relies on this
	// for a clean shutdown.
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runPolicyWatcher did not return after ctx cancel")
	}
}

// TestRunPolicyWatcherStopsOnCancel covers the no-op case: an empty cluster
// still has to start and shut down cleanly.
func TestRunPolicyWatcherStopsOnCancel(t *testing.T) {
	t.Parallel()

	scheme, listKinds := policyScheme()
	client := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPolicyWatcher(ctx, client, store.NewMemory(), &k8s.StaticResolver{}, func(string, ...any) {})
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runPolicyWatcher did not return after ctx cancel")
	}
}
