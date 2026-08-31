package proxyfeed

import (
	"context"
	"sync"
	"testing"

	"github.com/joshuawu/meridian/pkg/wire"
)

func TestFeedCurrentBeforePublish(t *testing.T) {
	f := NewFeed()
	snap, err := f.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if len(snap.Policies) != 0 {
		t.Fatalf("expected empty policies before first Publish, got %d", len(snap.Policies))
	}
	if snap.Version != "" {
		t.Fatalf("expected empty version before first Publish, got %q", snap.Version)
	}
}

func TestFeedPublishAndCurrent(t *testing.T) {
	f := NewFeed()
	snap := wire.ProxyPolicySnapshot{
		Version: "v1",
		Policies: []wire.PolicyRule{
			{Key: wire.PolicyRuleKey{DstPort: 443}, Verdict: wire.PolicyVerdict{Action: wire.PolicyActionAllow}},
		},
	}
	if err := f.Publish(context.Background(), snap); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, err := f.Current(context.Background())
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if got.Version != snap.Version {
		t.Fatalf("Version = %q, want %q", got.Version, snap.Version)
	}
	if len(got.Policies) != 1 {
		t.Fatalf("Policies len = %d, want 1", len(got.Policies))
	}
}

func TestFeedPublishReplacesSnapshot(t *testing.T) {
	f := NewFeed()

	snap1 := wire.ProxyPolicySnapshot{Version: "v1"}
	snap2 := wire.ProxyPolicySnapshot{Version: "v2",
		Policies: []wire.PolicyRule{
			{Key: wire.PolicyRuleKey{DstPort: 80}},
		},
	}

	_ = f.Publish(context.Background(), snap1)
	_ = f.Publish(context.Background(), snap2)

	got, _ := f.Current(context.Background())
	if got.Version != "v2" {
		t.Fatalf("Version = %q, want v2 after second Publish", got.Version)
	}
	if len(got.Policies) != 1 {
		t.Fatalf("Policies len = %d, want 1", len(got.Policies))
	}
}

// TestFeedConcurrentPublishAndCurrent verifies no data races under concurrent
// publish + read (run with -race).
func TestFeedConcurrentPublishAndCurrent(t *testing.T) {
	f := NewFeed()

	const goroutines = 10
	const iterations = 100
	var wg sync.WaitGroup

	// Writers.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				snap := wire.ProxyPolicySnapshot{Version: wire.PolicySnapshotVersion("v" + string(rune('0'+id)))}
				_ = f.Publish(context.Background(), snap)
			}
		}(i)
	}

	// Readers.
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = f.Current(context.Background())
			}
		}()
	}

	wg.Wait()
}

// TestFeedImplementsInterfaces is a compile-time check.
func TestFeedImplementsInterfaces(t *testing.T) {
	var _ Publisher = &Feed{}
}
