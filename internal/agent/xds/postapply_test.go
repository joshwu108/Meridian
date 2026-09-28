package xds

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/joshuawu/meridian/internal/control/store"
	"github.com/joshuawu/meridian/pkg/wire"
)

// planRecorder collects the CommitPlans handed to the post-apply callback.
type planRecorder struct {
	mu    sync.Mutex
	plans []wire.CommitPlan
}

func (r *planRecorder) record(p wire.CommitPlan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plans = append(r.plans, p)
}

func (r *planRecorder) hasIdentityUpsert(id wire.IdentityID) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, p := range r.plans {
		for _, up := range p.IdentityUpserts {
			if up.ID == id {
				return true
			}
		}
	}
	return false
}

func (r *planRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.plans)
}

// TestPostApplyCalledAfterApply verifies the WithPostApply callback fires with
// the applied CommitPlan once a push has been applied and ACKed, and that the
// writer had already applied the plan by the time the callback observed it.
func TestPostApplyCalledAfterApply(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutIdentity(ctx, sampleIdentity(7, "svc")); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
	if err := st.PutPolicy(ctx, samplePolicy(443)); err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	rec := &planRecorder{}
	w := newFakeWriter()
	c := NewClient(dialServer(t, st), w,
		WithLogf(func(string, ...any) {}),
		WithPostApply(rec.record),
	)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = c.Run(runCtx) }()

	waitFor(t, func() bool { return rec.hasIdentityUpsert(7) },
		"post-apply callback observed identity upsert")

	// By the time the callback fired, the writer must already hold the state
	// (callback comes after a successful Apply, never before).
	if _, idents := w.counts(); idents != 1 {
		t.Fatalf("writer identities = %d at callback time, want 1", idents)
	}
}

// TestPostApplyReceivesIncrementalPlan verifies a subsequent store change
// surfaces as a fresh plan containing only the delta.
func TestPostApplyReceivesIncrementalPlan(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutIdentity(ctx, sampleIdentity(2, "a")); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	rec := &planRecorder{}
	w := newFakeWriter()
	c := NewClient(dialServer(t, st), w,
		WithLogf(func(string, ...any) {}),
		WithPostApply(rec.record),
	)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = c.Run(runCtx) }()

	waitFor(t, func() bool { return rec.hasIdentityUpsert(2) }, "initial identity applied")

	if err := st.PutIdentity(ctx, sampleIdentity(3, "b")); err != nil {
		t.Fatalf("mutate: %v", err)
	}
	waitFor(t, func() bool { return rec.hasIdentityUpsert(3) }, "identity add propagated to callback")

	// The client's applied snapshot must agree with what the callback saw.
	_, idents := c.Applied()
	if len(idents) != 2 {
		t.Fatalf("Applied() identities = %d, want 2", len(idents))
	}
}

// TestPostApplyNotCalledOnNACK verifies the callback never fires for a rejected
// push (hold last-known-good: nothing was applied, so nothing to announce).
func TestPostApplyNotCalledOnNACK(t *testing.T) {
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	bs := &badServer{gotNACK: make(chan *discoveryv3.DiscoveryRequest, 1)}
	discoveryv3.RegisterAggregatedDiscoveryServiceServer(gs, bs)
	go func() { _ = gs.Serve(lis) }()
	defer gs.Stop()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer conn.Close()

	rec := &planRecorder{}
	c := NewClient(conn, newFakeWriter(),
		WithLogf(func(string, ...any) {}),
		WithPostApply(rec.record),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	select {
	case <-bs.gotNACK:
	case <-ctx.Done():
		t.Fatalf("no NACK received before timeout")
	}
	if n := rec.count(); n != 0 {
		t.Fatalf("post-apply callback fired %d time(s) for a NACKed push, want 0", n)
	}
}

// TestWithPostApplyNilIsIgnored verifies a nil callback leaves the client
// fully functional (option is a no-op).
func TestWithPostApplyNilIsIgnored(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	if err := st.PutIdentity(ctx, sampleIdentity(1, "svc")); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	w := newFakeWriter()
	c := NewClient(dialServer(t, st), w,
		WithLogf(func(string, ...any) {}),
		WithPostApply(nil),
	)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() { _ = c.Run(runCtx) }()

	waitFor(t, func() bool { _, i := w.counts(); return i == 1 }, "snapshot applied with nil callback")
}
