// PodResolver (Phase 7): the production IdentityResolver. It answers the
// policy compiler's selector and SPIFFE ID questions from the pod informer's
// lister cache, so policy resolution never round-trips to the apiserver.
package k8s

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	listersv1 "k8s.io/client-go/listers/core/v1"

	"github.com/joshuawu/meridian/pkg/wire"
)

// SpiffeIDAnnotation marks a pod as meshed and carries its SPIFFE URI. The
// pod informer registers identities for annotated pods; PodResolver resolves
// SPIFFE IDs back through the same annotation.
const SpiffeIDAnnotation = "meridian.io/spiffe-id"

// PodIdentityFunc returns the numeric identity registered for a pod.
// ok=false means the pod has no registered identity (e.g. not yet processed
// by the informer, or unmeshed).
type PodIdentityFunc func(pod *corev1.Pod) (wire.IdentityID, bool)

// PodResolver resolves policy selectors and SPIFFE IDs against the pod
// informer's lister. It fails closed per the IdentityResolver contract: a
// selector that matches no registered identity is an error, never an empty
// allow.
type PodResolver struct {
	lister   listersv1.PodLister
	identify PodIdentityFunc
}

// NewPodResolver returns a PodResolver reading pods from lister and mapping
// them to identities with identify.
func NewPodResolver(lister listersv1.PodLister, identify PodIdentityFunc) *PodResolver {
	return &PodResolver{lister: lister, identify: identify}
}

var _ IdentityResolver = (*PodResolver)(nil)

// ResolveSelector lists pods in sel.Namespace matching sel.Labels and
// returns their identity IDs, deduplicated and sorted. Pods without a
// registered identity are skipped; zero resolved identities is an error.
func (r *PodResolver) ResolveSelector(_ context.Context, sel WorkloadSelector) ([]wire.IdentityID, error) {
	pods, err := r.lister.Pods(sel.Namespace).List(labels.SelectorFromSet(sel.Labels))
	if err != nil {
		return nil, fmt.Errorf("list pods in namespace %q: %w", sel.Namespace, err)
	}

	seen := make(map[wire.IdentityID]bool, len(pods))
	ids := make([]wire.IdentityID, 0, len(pods))
	for _, pod := range pods {
		id, ok := r.identify(pod)
		if !ok || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no registered identities match selector namespace=%q labels=%v",
			sel.Namespace, sel.Labels)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}

// ResolveSpiffeID finds the pod annotated with spiffeID and returns its
// registered identity. A pod carrying the annotation but lacking a
// registered identity is a miss (fail closed).
func (r *PodResolver) ResolveSpiffeID(_ context.Context, spiffeID string) (wire.IdentityID, bool) {
	pods, err := r.lister.List(labels.Everything())
	if err != nil {
		return wire.IdentityUnknown, false
	}
	for _, pod := range pods {
		if pod.Annotations[SpiffeIDAnnotation] != spiffeID {
			continue
		}
		if id, ok := r.identify(pod); ok {
			return id, true
		}
	}
	return wire.IdentityUnknown, false
}
