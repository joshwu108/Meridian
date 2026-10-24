package main

import (
	"context"
	"fmt"
	"os"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/internal/control/k8s"
)

// logFunc matches the log.Printf shape the k8s watchers take.
type logFunc func(string, ...any)

// k8sEnabled reports whether the Kubernetes watchers should run. An explicit
// --kubeconfig always enables them; otherwise they come up only when the
// in-cluster environment is present, so the binary stays runnable as a plain
// REST+ADS server on a laptop.
func k8sEnabled(kubeconfig string, lookupEnv func(string) string) bool {
	return kubeconfig != "" || lookupEnv("KUBERNETES_SERVICE_HOST") != ""
}

// kubeRESTConfig builds the client config: from the named kubeconfig file
// when given, otherwise from the in-cluster ServiceAccount.
func kubeRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("load kubeconfig %q: %w", kubeconfig, err)
		}
		return cfg, nil
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("in-cluster config (pass --kubeconfig when running outside a pod): %w", err)
	}
	return cfg, nil
}

// startK8sWatchers brings up the pod and MeridianPolicy informers against
// cfg and returns once both are running.
//
// The two are wired together deliberately. The policy informer compiles a
// MeridianPolicy's SPIFFE sources and namespace/label selector into numeric
// identities through an IdentityResolver, and the only resolver that knows
// those mappings is backed by the pod informer's cache. Starting the policy
// informer alone — the shape the chart implied — would compile nothing: every
// object would be skipped with "no registered identity" and MeridianPolicy
// would stay inert while looking wired.
func startK8sWatchers(
	ctx context.Context,
	cfg *rest.Config,
	registry *identity.Registry,
	st k8sStore,
	logf logFunc,
) error {
	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("build kubernetes client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("build dynamic client: %w", err)
	}

	podWatcher := k8s.NewWatcher(clientset, registry, st)
	resolver := k8s.NewPodResolver(podWatcher.PodLister(), podWatcher.PodIdentity)

	go func() {
		if err := podWatcher.Run(ctx); err != nil && ctx.Err() == nil {
			logf("meridian-control: pod informer stopped: %v", err)
		}
	}()
	go runPolicyWatcher(ctx, dyn, st, resolver, logf)

	return nil
}

// k8sStore is the store surface both watchers need.
type k8sStore interface {
	k8s.PodStore
	k8s.PolicyStore
}

// runPolicyWatcher runs the MeridianPolicy informer until ctx is cancelled.
// Split out from startK8sWatchers so it can be driven with a fake dynamic
// client and a StaticResolver in a T1 test, with no apiserver involved.
func runPolicyWatcher(
	ctx context.Context,
	client dynamic.Interface,
	st k8s.PolicyStore,
	resolver k8s.IdentityResolver,
	logf logFunc,
) {
	if err := k8s.NewPolicyWatcher(client, st, resolver).Run(ctx); err != nil && ctx.Err() == nil {
		logf("meridian-control: meridianpolicy informer stopped: %v", err)
	}
}

// osLookupEnv adapts os.Getenv to the lookup seam k8sEnabled takes.
func osLookupEnv(key string) string { return os.Getenv(key) }
