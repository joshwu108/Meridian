// Package xds implements the agent-side ADS client (A-3, MER-79): it streams the
// CC-2 wire contract from meridian-control, decodes it via internal/cc2, diffs
// each snapshot against the last-applied state into a wire.CommitPlan, and applies
// it through the datapath.Writer (the sole wire↔bpf translator, D17). It ACKs only
// after a snapshot is fully applied and NACKs (holding last-known-good) on any
// decode/contract/apply failure — never partially applying and never transiently
// widening (CC-5). It is the production replacement for the MER-55 in-memory stub.
package xds

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"sync"
	"time"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/joshuawu/meridian/internal/agent/datapath"
	"github.com/joshuawu/meridian/internal/cc2"
	"github.com/joshuawu/meridian/pkg/wire"
)

// subscribeTypes are the CC-2 channels the agent consumes: CDS carries policy,
// EDS carries identity (ADR-0008 §1). LDS/RDS are reserved (Phase-5 L7) and not
// subscribed — the server keeps them empty.
var subscribeTypes = []string{resourcev3.ClusterType, resourcev3.EndpointType}

const (
	reconnectBase   = 200 * time.Millisecond
	reconnectJitter = 200 * time.Millisecond
)

// snapshot is the agent's view of desired state, accumulated across channels.
type snapshot struct {
	policies   []wire.PolicyRule
	identities []wire.Identity
}

// Client is the agent's ADS client. Construct with NewClient; Run drives it.
type Client struct {
	ads    discoveryv3.AggregatedDiscoveryServiceClient
	writer datapath.Writer
	logf   func(string, ...any)

	mu       sync.Mutex
	applied  snapshot          // last successfully applied desired state
	accepted map[string]string // type_url -> last-accepted version_info
}

// Option configures a Client.
type Option func(*Client)

// WithLogf overrides the debug logger (default log.Printf).
func WithLogf(logf func(string, ...any)) Option {
	return func(c *Client) {
		if logf != nil {
			c.logf = logf
		}
	}
}

// NewClient builds an ADS client over conn that applies snapshots through writer.
func NewClient(conn grpc.ClientConnInterface, writer datapath.Writer, opts ...Option) *Client {
	c := &Client{
		ads:      discoveryv3.NewAggregatedDiscoveryServiceClient(conn),
		writer:   writer,
		logf:     log.Printf,
		accepted: make(map[string]string),
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Run streams desired state and applies it until ctx is cancelled. On a stream
// error it holds the last-applied kernel state and reconnects with jittered
// backoff (last-known-good on control-plane loss, CC-5).
func (c *Client) Run(ctx context.Context) error {
	for {
		err := c.runStream(ctx)
		if ctx.Err() != nil {
			return nil
		}
		c.logf("ads-client: stream ended (%v); holding last-known-good, reconnecting", err)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(reconnectBase + time.Duration(rand.Int63n(int64(reconnectJitter)))):
		}
	}
}

func (c *Client) runStream(ctx context.Context) error {
	stream, err := c.ads.StreamAggregatedResources(ctx)
	if err != nil {
		return fmt.Errorf("open ADS stream: %w", err)
	}
	for _, t := range subscribeTypes {
		if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: t}); err != nil {
			return fmt.Errorf("subscribe %s: %w", t, err)
		}
	}
	for {
		resp, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("recv: %w", err)
		}
		if err := c.handle(ctx, stream, resp); err != nil {
			return err
		}
	}
}

// handle decodes one push, applies the resulting snapshot, and ACK/NACKs. It
// returns an error only on a stream-send failure (which triggers reconnect); a
// decode/apply failure is surfaced to the server as a NACK, not a stream error.
func (c *Client) handle(ctx context.Context, stream discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesClient, resp *discoveryv3.DiscoveryResponse) error {
	typeURL := resp.GetTypeUrl()
	candidate, err := c.candidateFor(typeURL, resp)
	if err != nil {
		c.logf("ads-client: NACK type=%s nonce=%s: %v", typeURL, resp.GetNonce(), err)
		return c.send(stream, &discoveryv3.DiscoveryRequest{
			TypeUrl:       typeURL,
			VersionInfo:   c.acceptedVersion(typeURL),
			ResponseNonce: resp.GetNonce(),
			ErrorDetail:   &spb.Status{Code: int32(codes.InvalidArgument), Message: err.Error()},
		})
	}

	plan := diff(c.snapshotCopy(), candidate)
	if err := c.writer.Apply(ctx, plan); err != nil {
		// Hold last-known-good: do not advance applied/accepted (CC-5).
		c.logf("ads-client: NACK type=%s nonce=%s: apply failed: %v", typeURL, resp.GetNonce(), err)
		return c.send(stream, &discoveryv3.DiscoveryRequest{
			TypeUrl:       typeURL,
			VersionInfo:   c.acceptedVersion(typeURL),
			ResponseNonce: resp.GetNonce(),
			ErrorDetail:   &spb.Status{Code: int32(codes.Internal), Message: err.Error()},
		})
	}

	c.commit(typeURL, resp.GetVersionInfo(), candidate)
	c.logf("ads-client: ACK type=%s version=%s nonce=%s (policies=%d identities=%d)",
		typeURL, resp.GetVersionInfo(), resp.GetNonce(), len(candidate.policies), len(candidate.identities))
	return c.send(stream, &discoveryv3.DiscoveryRequest{
		TypeUrl:       typeURL,
		VersionInfo:   resp.GetVersionInfo(),
		ResponseNonce: resp.GetNonce(),
	})
}

// candidateFor decodes the pushed channel and returns the full desired snapshot
// that results from merging it with the current state (ADS is per-type SotW).
func (c *Client) candidateFor(typeURL string, resp *discoveryv3.DiscoveryResponse) (snapshot, error) {
	cur := c.snapshotCopy()
	resources := resp.GetResources()
	switch typeURL {
	case resourcev3.ClusterType:
		policies := make([]wire.PolicyRule, 0, len(resources))
		for i, res := range resources {
			p, err := cc2.DecodePolicyRule(res)
			if err != nil {
				return snapshot{}, fmt.Errorf("cluster resource[%d]: %w", i, err)
			}
			policies = append(policies, p)
		}
		cur.policies = policies
		return cur, nil
	case resourcev3.EndpointType:
		identities := make([]wire.Identity, 0, len(resources))
		for i, res := range resources {
			id, err := cc2.DecodeIdentity(res)
			if err != nil {
				return snapshot{}, fmt.Errorf("endpoint resource[%d]: %w", i, err)
			}
			identities = append(identities, id)
		}
		cur.identities = identities
		return cur, nil
	default:
		if len(resources) != 0 {
			return snapshot{}, fmt.Errorf("unexpected %d resource(s) on %s", len(resources), typeURL)
		}
		return cur, nil
	}
}

func (c *Client) snapshotCopy() snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	return snapshot{
		policies:   append([]wire.PolicyRule(nil), c.applied.policies...),
		identities: append([]wire.Identity(nil), c.applied.identities...),
	}
}

func (c *Client) commit(typeURL, version string, snap snapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.applied = snap
	c.accepted[typeURL] = version
}

func (c *Client) acceptedVersion(typeURL string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.accepted[typeURL]
}

// Applied returns a copy of the last-applied desired state, for inspection.
func (c *Client) Applied() (policies []wire.PolicyRule, identities []wire.Identity) {
	s := c.snapshotCopy()
	return s.policies, s.identities
}

func (c *Client) send(stream discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesClient, req *discoveryv3.DiscoveryRequest) error {
	if err := stream.Send(req); err != nil {
		return fmt.Errorf("send ACK/NACK: %w", err)
	}
	return nil
}
