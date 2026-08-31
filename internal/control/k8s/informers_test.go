package k8s

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/joshuawu/meridian/internal/control/identity"
	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
)

// fakePodStore tracks Put/Delete calls.
type fakePodStore struct {
	puts    []wire.Identity
	deletes []wire.IdentityID
}

func (f *fakePodStore) PutIdentity(_ context.Context, id wire.Identity) error {
	f.puts = append(f.puts, id)
	return nil
}

func (f *fakePodStore) DeleteIdentity(_ context.Context, id wire.IdentityID) error {
	f.deletes = append(f.deletes, id)
	return nil
}

func TestWatcherOnPodAdd(t *testing.T) {
	client := fake.NewSimpleClientset()
	reg := identity.NewRegistry()
	st := &fakePodStore{}

	w := NewWatcher(client, reg, st)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "svc-a",
			Namespace: "default",
			Annotations: map[string]string{
				"meridian.io/spiffe-id": "spiffe://cluster.local/ns/default/sa/svc-a",
			},
		},
		Status: corev1.PodStatus{PodIP: "10.0.0.5"},
	}

	w.onPodAdd(context.Background(), pod)

	if len(st.puts) != 1 {
		t.Fatalf("expected 1 PutIdentity call, got %d", len(st.puts))
	}
	if st.puts[0].SpiffeID != "spiffe://cluster.local/ns/default/sa/svc-a" {
		t.Fatalf("unexpected SpiffeID: %s", st.puts[0].SpiffeID)
	}
	if st.puts[0].PodIPv4 != "10.0.0.5" {
		t.Fatalf("unexpected PodIPv4: %s", st.puts[0].PodIPv4)
	}
}

func TestWatcherSkipsPodWithoutAnnotation(t *testing.T) {
	client := fake.NewSimpleClientset()
	reg := identity.NewRegistry()
	st := &fakePodStore{}
	w := NewWatcher(client, reg, st)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "unlabelled", Namespace: "default"},
		Status:     corev1.PodStatus{PodIP: "10.0.0.6"},
	}
	w.onPodAdd(context.Background(), pod)

	if len(st.puts) != 0 {
		t.Fatalf("expected 0 PutIdentity calls for pod without annotation, got %d", len(st.puts))
	}
}

func TestWatcherSkipsPodWithoutIP(t *testing.T) {
	client := fake.NewSimpleClientset()
	reg := identity.NewRegistry()
	st := &fakePodStore{}
	w := NewWatcher(client, reg, st)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "no-ip", Namespace: "default",
			Annotations: map[string]string{"meridian.io/spiffe-id": "spiffe://x/y"},
		},
		Status: corev1.PodStatus{PodIP: ""},
	}
	w.onPodAdd(context.Background(), pod)
	if len(st.puts) != 0 {
		t.Fatalf("expected 0 PutIdentity calls for pod without IP")
	}
}

func TestWatcherOnPodDelete(t *testing.T) {
	client := fake.NewSimpleClientset()
	reg := identity.NewRegistry()
	st := &fakePodStore{}
	w := NewWatcher(client, reg, st)

	// Add first so registry has the name.
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "svc-b", Namespace: "default",
			Annotations: map[string]string{"meridian.io/spiffe-id": "spiffe://x/svc-b"},
		},
		Status: corev1.PodStatus{PodIP: "10.0.0.7"},
	}
	w.onPodAdd(context.Background(), pod)
	if len(st.puts) != 1 {
		t.Fatalf("setup: expected 1 put")
	}
	w.onPodDelete(context.Background(), pod)
	if len(st.deletes) != 1 {
		t.Fatalf("expected 1 DeleteIdentity call, got %d", len(st.deletes))
	}
}

func TestListPods(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "p1", Namespace: "default"},
	}
	client := fake.NewSimpleClientset(pod)
	reg := identity.NewRegistry()
	st := store.NewMemory()
	w := NewWatcher(client, reg, st)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	pods, err := w.ListPods(ctx, "default")
	if err != nil {
		t.Fatalf("ListPods: %v", err)
	}
	if len(pods) != 1 || pods[0].Name != "p1" {
		t.Fatalf("unexpected pods: %v", pods)
	}
}
