package k8s

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	listersv1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/joshuawu/meridian/pkg/wire"
)

// newFakePodLister wraps a slice of pods in a real cache-backed PodLister.
func newFakePodLister(t *testing.T, pods ...*corev1.Pod) listersv1.PodLister {
	t.Helper()
	indexer := cache.NewIndexer(cache.MetaNamespaceKeyFunc, cache.Indexers{
		cache.NamespaceIndex: cache.MetaNamespaceIndexFunc,
	})
	for _, pod := range pods {
		if err := indexer.Add(pod); err != nil {
			t.Fatalf("add pod %s/%s to indexer: %v", pod.Namespace, pod.Name, err)
		}
	}
	return listersv1.NewPodLister(indexer)
}

func testPod(namespace, name, spiffeID string, labels map[string]string) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Labels:    labels,
		},
	}
	if spiffeID != "" {
		pod.Annotations = map[string]string{SpiffeIDAnnotation: spiffeID}
	}
	return pod
}

// identityByName maps pod name → identity ID, the shape a registry-backed
// labeler has in production.
func identityByName(ids map[string]wire.IdentityID) PodIdentityFunc {
	return func(pod *corev1.Pod) (wire.IdentityID, bool) {
		id, ok := ids[pod.Name]
		return id, ok
	}
}

func TestPodResolverImplementsIdentityResolver(t *testing.T) {
	var _ IdentityResolver = (*PodResolver)(nil)
}

func TestPodResolverResolveSelector(t *testing.T) {
	appLabels := map[string]string{"app": "api"}
	lister := newFakePodLister(t,
		testPod("prod", "api-1", "spiffe://cluster.local/ns/prod/sa/api", appLabels),
		testPod("prod", "api-2", "spiffe://cluster.local/ns/prod/sa/api", appLabels),
		testPod("prod", "db-1", "spiffe://cluster.local/ns/prod/sa/db", map[string]string{"app": "db"}),
		testPod("staging", "api-1", "spiffe://cluster.local/ns/staging/sa/api", appLabels),
	)

	tests := []struct {
		name    string
		ids     map[string]wire.IdentityID
		sel     WorkloadSelector
		want    []wire.IdentityID
		wantErr bool
	}{
		{
			name: "namespace and labels match",
			ids:  map[string]wire.IdentityID{"api-1": 10, "api-2": 11, "db-1": 20},
			sel:  WorkloadSelector{Namespace: "prod", Labels: map[string]string{"app": "api"}},
			want: []wire.IdentityID{10, 11},
		},
		{
			name: "namespace only matches all pods in namespace",
			ids:  map[string]wire.IdentityID{"api-1": 10, "api-2": 11, "db-1": 20},
			sel:  WorkloadSelector{Namespace: "prod"},
			want: []wire.IdentityID{10, 11, 20},
		},
		{
			name: "duplicate identity IDs are deduplicated",
			ids:  map[string]wire.IdentityID{"api-1": 10, "api-2": 10},
			sel:  WorkloadSelector{Namespace: "prod", Labels: map[string]string{"app": "api"}},
			want: []wire.IdentityID{10},
		},
		{
			name:    "no matching pods fails closed",
			ids:     map[string]wire.IdentityID{"api-1": 10},
			sel:     WorkloadSelector{Namespace: "prod", Labels: map[string]string{"app": "missing"}},
			wantErr: true,
		},
		{
			name:    "matches without registered identities fail closed",
			ids:     map[string]wire.IdentityID{},
			sel:     WorkloadSelector{Namespace: "prod", Labels: map[string]string{"app": "api"}},
			wantErr: true,
		},
		{
			name: "pods without identity are skipped when others resolve",
			ids:  map[string]wire.IdentityID{"api-1": 10},
			sel:  WorkloadSelector{Namespace: "prod", Labels: map[string]string{"app": "api"}},
			want: []wire.IdentityID{10},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewPodResolver(lister, identityByName(tt.ids))
			got, err := r.ResolveSelector(context.Background(), tt.sel)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveSelector(%+v) = %v, want error", tt.sel, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveSelector(%+v): %v", tt.sel, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ResolveSelector(%+v) = %v, want %v", tt.sel, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("ResolveSelector(%+v) = %v, want %v", tt.sel, got, tt.want)
				}
			}
		})
	}
}

func TestPodResolverResolveSpiffeID(t *testing.T) {
	lister := newFakePodLister(t,
		testPod("prod", "api-1", "spiffe://cluster.local/ns/prod/sa/api", nil),
		testPod("prod", "plain-1", "", nil), // unmeshed pod, no annotation
	)
	ids := map[string]wire.IdentityID{"api-1": 10}
	r := NewPodResolver(lister, identityByName(ids))

	t.Run("annotation match returns identity", func(t *testing.T) {
		id, ok := r.ResolveSpiffeID(context.Background(), "spiffe://cluster.local/ns/prod/sa/api")
		if !ok || id != 10 {
			t.Fatalf("ResolveSpiffeID = (%v, %v), want (10, true)", id, ok)
		}
	})

	t.Run("unknown SPIFFE ID misses", func(t *testing.T) {
		id, ok := r.ResolveSpiffeID(context.Background(), "spiffe://cluster.local/ns/prod/sa/ghost")
		if ok {
			t.Fatalf("ResolveSpiffeID = (%v, %v), want miss", id, ok)
		}
	})

	t.Run("annotated pod without registered identity misses", func(t *testing.T) {
		empty := NewPodResolver(lister, identityByName(nil))
		id, ok := empty.ResolveSpiffeID(context.Background(), "spiffe://cluster.local/ns/prod/sa/api")
		if ok {
			t.Fatalf("ResolveSpiffeID = (%v, %v), want miss", id, ok)
		}
	})
}
