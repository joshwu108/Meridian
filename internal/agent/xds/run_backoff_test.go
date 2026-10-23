package xds

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/grpc"
)

// scriptedADS fails the first failDials stream opens, then returns a stream
// that delivers one response before breaking — i.e. a stream that made
// progress.
type scriptedADS struct {
	discoveryv3.AggregatedDiscoveryServiceClient
	mu        sync.Mutex
	calls     int
	failDials int
}

func (s *scriptedADS) StreamAggregatedResources(
	_ context.Context, _ ...grpc.CallOption,
) (discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesClient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.calls <= s.failDials {
		return nil, errors.New("connection refused")
	}
	return &scriptedStream{}, nil
}

// scriptedStream yields exactly one response, then fails.
type scriptedStream struct {
	discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesClient
	delivered bool
}

func (s *scriptedStream) Send(*discoveryv3.DiscoveryRequest) error { return nil }

func (s *scriptedStream) Recv() (*discoveryv3.DiscoveryResponse, error) {
	if !s.delivered {
		s.delivered = true
		// Contents are irrelevant: runStream marks progress on a successful
		// Recv, before handing off to handle.
		return &discoveryv3.DiscoveryResponse{
			TypeUrl: resourcev3.ClusterType, VersionInfo: "1", Nonce: "n1",
		}, nil
	}
	return nil, errors.New("stream broken")
}

var delayRe = regexp.MustCompile(`reconnecting in (\S+)`)

// TestRunResetsBackoffImmediatelyAfterProgress is the regression for the
// reset landing one reconnect cycle too late.
//
// Run computed the post-stream sleep from the attempt counter as it stood
// BEFORE the stream ran, and only folded in `progressed` after the sleep. So
// an agent that had escalated during an outage, reconnected, streamed happily,
// and then hit a single blip would still sleep the stale escalated delay (up
// to the full 30s ceiling) before retrying — exactly the fast-recovery case
// the progress tracking was added to serve. The unit tests on
// nextReconnectAttempt/reconnectBackoffRange could not catch it: the defect is
// the ORDER of operations in Run, not the arithmetic.
func TestRunResetsBackoffImmediatelyAfterProgress(t *testing.T) {
	const failDials = 2 // escalate to attempt==2 before the healthy stream

	var (
		mu     sync.Mutex
		delays []time.Duration
	)
	c := &Client{
		ads:      &scriptedADS{failDials: failDials},
		writer:   newFakeWriter(),
		accepted: map[string]string{},
		logf: func(format string, args ...any) {
			m := delayRe.FindStringSubmatch(sprintf(format, args...))
			if len(m) != 2 {
				return
			}
			d, err := time.ParseDuration(m[1])
			if err != nil {
				return
			}
			mu.Lock()
			delays = append(delays, d)
			mu.Unlock()
		},
	}

	// Stop once we have the two escalating delays plus the one that follows
	// the healthy stream.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	go func() {
		for {
			mu.Lock()
			n := len(delays)
			mu.Unlock()
			if n > failDials {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
	}()

	if err := c.Run(ctx); err != nil {
		t.Fatalf("Run returned %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(delays) <= failDials {
		t.Fatalf("only observed %d delays (%v); need the one after the healthy stream", len(delays), delays)
	}

	// Delays 0..failDials-1 come from genuinely failed dials and must escalate.
	for i := 1; i < failDials; i++ {
		if delays[i] <= delays[i-1] {
			t.Fatalf("delay %d (%v) did not escalate past delay %d (%v): %v",
				i, delays[i], i-1, delays[i-1], delays)
		}
	}

	// The delay AFTER the stream that made progress must be back at tier 0.
	_, tier0Max := reconnectBackoffRange(0)
	got := delays[failDials]
	if got >= tier0Max {
		t.Fatalf("delay after a healthy stream = %v, want < %v (tier 0); "+
			"backoff inherited stale escalation. all delays: %v", got, tier0Max, delays)
	}
}

// sprintf is fmt.Sprintf, aliased so the logf capture above reads clearly.
func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }
