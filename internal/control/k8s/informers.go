// Package k8s implements Kubernetes watchers for the Meridian control plane.
// Pod and Service informers feed the identity registry and
// policy store so Meridian tracks workload identities automatically.
//
// Testing note: these informers require a real or fake kube-apiserver.
// Unit tests use fake.NewSimpleClientset from k8s.io/client-go/kubernetes/fake.
// Integration tests need envtest or a Kind cluster.
package k8s

import (
	"context"
	"fmt"
	"log"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	informersv1 "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/pkg/wire"
)

// podResyncInterval is the pod informer's full-resync period. The policy
// informer uses a matching interval (policyResyncInterval).
const podResyncInterval = 30 * time.Second

// PodStore is the subset of control.Store needed by the pod informer.
type PodStore interface {
	PutIdentity(context.Context, wire.Identity) error
	DeleteIdentity(context.Context, wire.IdentityID) error
}

// Watcher drives the Pod informer loop. It registers identities in the
// Meridian identity registry whenever pods with the
// "meridian.io/spiffe-id" annotation appear or disappear.
type Watcher struct {
	client   kubernetes.Interface
	registry *identity.Registry
	store    PodStore
	logf     func(string, ...any)

	// factory is built in NewWatcher rather than in Run so PodLister is
	// usable before the loop starts: PodResolver has to be handed to the
	// policy informer at construction time, and both informers then come
	// from this one factory and share a single pod watch and cache.
	// Constructing it starts no goroutines and opens no connections —
	// factory.Start in Run does that.
	factory informers.SharedInformerFactory
	pods    informersv1.PodInformer
}

// NewWatcher returns a Watcher backed by client.
func NewWatcher(client kubernetes.Interface, registry *identity.Registry, store PodStore) *Watcher {
	factory := informers.NewSharedInformerFactory(client, podResyncInterval)
	return &Watcher{
		client:   client,
		registry: registry,
		store:    store,
		logf:     log.Printf,
		factory:  factory,
		pods:     factory.Core().V1().Pods(),
	}
}

// PodLister returns the shared pod informer's lister. Reads only serve from
// cache, so results are empty until Run has synced.
func (w *Watcher) PodLister() listersv1.PodLister {
	return w.pods.Lister()
}

// PodIdentity reports the identity this watcher registered for pod, matching
// the registry key onPodAdd allocates under (the pod name). It is the
// PodIdentityFunc to pair with PodLister when building a PodResolver.
func (w *Watcher) PodIdentity(pod *corev1.Pod) (wire.IdentityID, bool) {
	if pod == nil {
		return wire.IdentityUnknown, false
	}
	return w.registry.LookupByName(pod.Name)
}

// Run starts the Pod informer and blocks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) error {
	factory := w.factory
	podInformer := w.pods.Informer()

	_, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj any) { w.onPodAdd(ctx, obj) },
		UpdateFunc: func(_, obj any) { w.onPodAdd(ctx, obj) },
		DeleteFunc: func(obj any) { w.onPodDelete(ctx, obj) },
	})
	if err != nil {
		return fmt.Errorf("k8s watcher: add event handler: %w", err)
	}

	factory.Start(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return fmt.Errorf("k8s watcher: cache sync timed out")
	}
	w.logf("k8s watcher: pod informer ready")

	<-ctx.Done()
	return nil
}

// ListPods returns all pods currently in the informer cache (for reconcile).
func (w *Watcher) ListPods(ctx context.Context, namespace string) ([]*corev1.Pod, error) {
	list, err := w.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8s: list pods: %w", err)
	}
	pods := make([]*corev1.Pod, len(list.Items))
	for i := range list.Items {
		pods[i] = &list.Items[i]
	}
	return pods, nil
}

// ListPodsWithLabel returns pods with the given label selector.
func (w *Watcher) ListPodsWithLabel(ctx context.Context, namespace, selector string) ([]*corev1.Pod, error) {
	sel, err := labels.Parse(selector)
	if err != nil {
		return nil, fmt.Errorf("k8s: parse selector %q: %w", selector, err)
	}
	list, err := w.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: sel.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("k8s: list pods: %w", err)
	}
	pods := make([]*corev1.Pod, len(list.Items))
	for i := range list.Items {
		pods[i] = &list.Items[i]
	}
	return pods, nil
}

func (w *Watcher) onPodAdd(ctx context.Context, obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	spiffeID, ok := pod.Annotations[SpiffeIDAnnotation]
	if !ok || spiffeID == "" {
		return
	}
	if pod.Status.PodIP == "" {
		return
	}
	id, err := w.registry.Allocate(pod.Name)
	if err != nil {
		w.logf("k8s watcher: allocate identity for pod %s/%s: %v",
			pod.Namespace, pod.Name, err)
		return
	}
	ident := wire.Identity{
		ID:        id,
		SpiffeID:  spiffeID,
		PodIPv4:   pod.Status.PodIP,
		Namespace: pod.Namespace,
		Name:      pod.Name,
	}
	if err := w.store.PutIdentity(ctx, ident); err != nil {
		w.logf("k8s watcher: put identity for pod %s/%s: %v",
			pod.Namespace, pod.Name, err)
	}
}

func (w *Watcher) onPodDelete(ctx context.Context, obj any) {
	pod, ok := obj.(*corev1.Pod)
	if !ok {
		return
	}
	id, ok := w.registry.LookupByName(pod.Name)
	if !ok {
		return
	}
	if err := w.store.DeleteIdentity(ctx, id); err != nil {
		w.logf("k8s watcher: delete identity for pod %s/%s: %v",
			pod.Namespace, pod.Name, err)
	}
}
