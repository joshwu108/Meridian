//go:build e2e

// Package e2e holds the Kubernetes control-plane demo test (Phase 7): a real
// kube-apiserver (envtest) with the MeridianPolicy CRD installed, exercising
// the policy ingestion path CRD → dynamic informer → store.PutPolicy. No
// agent, proxy, or eBPF involved.
//
// Requires the envtest binaries (kube-apiserver, etcd):
//
//	go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
//	export KUBEBUILDER_ASSETS="$(setup-envtest use 1.31.x -p path)"
//	go test -tags e2e ./test/e2e/
//
// The test skips when the binaries are not available so plain CI stays green.
package e2e

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/joshuawu/meridian/internal/control/k8s"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
)

const (
	demoNamespace    = "payments"
	demoSourceSPIFFE = "spiffe://cluster.local/workload/payments/frontend"
	demoSourceID     = wire.IdentityID(101)
	demoBackendID    = wire.IdentityID(202)
	demoPort         = uint16(8443)
)

// startEnvtest stands up a kube-apiserver with the MeridianPolicy CRD from
// the Helm chart and returns clients. Skips when envtest binaries are absent.
func startEnvtest(t *testing.T) (dynamic.Interface, kubernetes.Interface) {
	t.Helper()
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		// envtest can also discover binaries in its default store; probe for it.
		home, err := os.UserHomeDir()
		defaultStore := ""
		if err == nil {
			defaultStore = filepath.Join(home, ".local", "share", "kubebuilder-envtest")
		}
		if defaultStore == "" || !dirExists(defaultStore) {
			t.Skip("KUBEBUILDER_ASSETS not set and no default envtest store; " +
				"install with setup-envtest to run this test")
		}
	}

	env := &envtest.Environment{
		CRDDirectoryPaths: []string{
			filepath.Join("..", "..", "deploy", "helm", "meridian", "crds"),
		},
		ErrorIfCRDPathMissing: true,
	}
	cfg, err := env.Start()
	if err != nil {
		t.Fatalf("start envtest control plane: %v", err)
	}
	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Errorf("stop envtest: %v", err)
		}
	})

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("dynamic client: %v", err)
	}
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("clientset: %v", err)
	}
	return dyn, clientset
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// TestK8sPolicyIngestionDemo verifies the control-plane policy ingestion
// path end to end against a real apiserver:
//
//  1. envtest control plane up, MeridianPolicy CRD registered
//  2. MeridianPolicy object created
//  3. the policy informer compiles it and calls the store's Put
//  4. the store holds the expected wire.PolicyRule
//  5. teardown is clean (informer stops, envtest stops)
func TestK8sPolicyIngestionDemo(t *testing.T) {
	dyn, clientset := startEnvtest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Namespace for the policy object.
	_, err := clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: demoNamespace},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	// Real memory-backed store; its Watch channel is the assertion seam.
	st := store.NewMemory()
	events := st.Watch(ctx)

	resolver := &k8s.StaticResolver{
		BySpiffeID:  map[string]wire.IdentityID{demoSourceSPIFFE: demoSourceID},
		ByNamespace: map[string][]wire.IdentityID{demoNamespace: {demoBackendID}},
	}

	watcherCtx, stopWatcher := context.WithCancel(ctx)
	watcherDone := make(chan error, 1)
	go func() {
		watcherDone <- k8s.NewPolicyWatcher(dyn, st, resolver).Run(watcherCtx)
	}()

	// Create the MeridianPolicy through the real apiserver (schema-validated
	// against the CRD from the Helm chart).
	pol := k8s.MeridianPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: k8s.GroupName + "/" + k8s.Version,
			Kind:       k8s.PolicyKind,
		},
		ObjectMeta: metav1.ObjectMeta{Name: "allow-frontend", Namespace: demoNamespace},
		Spec: k8s.MeridianPolicySpec{
			Selector: k8s.WorkloadSelector{Namespace: demoNamespace},
			Sources:  []string{demoSourceSPIFFE},
			Ports:    []uint16{demoPort},
			Action:   k8s.PolicyActionNameAllow,
		},
	}
	obj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(&pol)
	if err != nil {
		t.Fatalf("to unstructured: %v", err)
	}
	_, err = dyn.Resource(k8s.PolicyGVR()).Namespace(demoNamespace).
		Create(ctx, &unstructured.Unstructured{Object: obj}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create MeridianPolicy: %v", err)
	}

	// The informer must call PutPolicy: wait for the store event, then
	// assert the compiled rule is exactly what the CRD described.
	select {
	case <-events:
	case <-time.After(30 * time.Second):
		t.Fatalf("store never saw a policy change after MeridianPolicy create")
	}

	rules, err := st.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("list policies: %v", err)
	}
	want := wire.PolicyRule{
		Key: wire.PolicyRuleKey{
			SrcIdentity: demoSourceID,
			DstIdentity: demoBackendID,
			DstPort:     demoPort,
			Protocol:    k8s.ProtocolTCP,
			Direction:   wire.DirectionIngress,
		},
		Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow},
	}
	if len(rules) != 1 || rules[0] != want {
		t.Fatalf("store rules = %+v, want exactly %+v", rules, want)
	}

	// Clean teardown: informer stops promptly, envtest stops in Cleanup.
	stopWatcher()
	select {
	case <-watcherDone:
	case <-time.After(10 * time.Second):
		t.Fatalf("policy watcher did not stop after cancel")
	}
}
