package ads

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"

	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/joshuawu/meridian/internal/cc2"
	"github.com/joshuawu/meridian/pkg/wire"
)

// StubAgent is an in-memory ADS client used to exercise the MER-54 server end to
// end (and, in MER-56, to drive the CP-3 conformance gate). It opens a single
// StreamAggregatedResources stream, subscribes to the resource types, decodes
// each pushed snapshot per the server's payload contract, and replies with an
// ACK on success or a NACK on a contract violation. It is NOT the production
// agent — it carries no datapath, only the xDS handshake and a decoded snapshot.
type StubAgent struct {
	client discoveryv3.AggregatedDiscoveryServiceClient
	logf   func(string, ...any)

	mu       sync.Mutex
	policies []wire.PolicyRule
	accepted map[string]string // type_url -> last-accepted version_info
}

// StubOption configures a StubAgent.
type StubOption func(*StubAgent)

// WithLogf overrides the debug logger (default: log.Printf). Pass a no-op to
// silence the stub in tests.
func WithLogf(logf func(string, ...any)) StubOption {
	return func(a *StubAgent) {
		if logf != nil {
			a.logf = logf
		}
	}
}

// NewStubAgent builds a StubAgent over an existing gRPC client connection (e.g.
// a bufconn dial in tests).
func NewStubAgent(conn grpc.ClientConnInterface, opts ...StubOption) *StubAgent {
	a := &StubAgent{
		client:   discoveryv3.NewAggregatedDiscoveryServiceClient(conn),
		logf:     log.Printf,
		accepted: make(map[string]string),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Run opens one ADS stream, subscribes to every resource type, and processes
// pushes until ctx is cancelled or the stream ends. It returns nil on a clean
// shutdown (context cancel or server EOF) and the underlying error otherwise.
// Reconnect is "call Run again with a fresh context": each call is a fresh
// stream that re-subscribes and re-receives current state.
func (a *StubAgent) Run(ctx context.Context) error {
	stream, err := a.client.StreamAggregatedResources(ctx)
	if err != nil {
		return fmt.Errorf("open ADS stream: %w", err)
	}

	// Initial, empty-nonce subscription for each resource type.
	for _, typeURL := range pushOrder {
		if err := stream.Send(&discoveryv3.DiscoveryRequest{TypeUrl: typeURL}); err != nil {
			return fmt.Errorf("subscribe %s: %w", typeURL, err)
		}
	}

	for {
		resp, err := stream.Recv()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("recv: %w", err)
		}

		policies, decodeErr := decodeSnapshot(resp)
		if decodeErr != nil {
			// NACK: keep last-accepted version; never adopt a config we cannot
			// decode (CC-5 fail-closed mirrored on the client side).
			a.logf("ads-stub: NACK type=%s nonce=%s: %v", resp.GetTypeUrl(), resp.GetNonce(), decodeErr)
			nack := &discoveryv3.DiscoveryRequest{
				TypeUrl:       resp.GetTypeUrl(),
				VersionInfo:   a.acceptedVersion(resp.GetTypeUrl()),
				ResponseNonce: resp.GetNonce(),
				ErrorDetail:   &spb.Status{Code: int32(codes.InvalidArgument), Message: decodeErr.Error()},
			}
			if err := stream.Send(nack); err != nil {
				return fmt.Errorf("send NACK: %w", err)
			}
			continue
		}

		a.accept(resp.GetTypeUrl(), resp.GetVersionInfo(), policies)
		a.logf("ads-stub: ACK type=%s version=%s nonce=%s policies=%d",
			resp.GetTypeUrl(), resp.GetVersionInfo(), resp.GetNonce(), len(policies))
		ack := &discoveryv3.DiscoveryRequest{
			TypeUrl:       resp.GetTypeUrl(),
			VersionInfo:   resp.GetVersionInfo(),
			ResponseNonce: resp.GetNonce(),
		}
		if err := stream.Send(ack); err != nil {
			return fmt.Errorf("send ACK: %w", err)
		}
	}
}

// Snapshot is the stub's last-accepted view: the decoded policy set and the
// accepted version per resource type.
type Snapshot struct {
	Policies []wire.PolicyRule
	Versions map[string]string
}

// Snapshot returns a deep copy of the last-accepted state. Safe for concurrent
// use with the running stream.
func (a *StubAgent) Snapshot() Snapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	versions := make(map[string]string, len(a.accepted))
	for k, v := range a.accepted {
		versions[k] = v
	}
	return Snapshot{
		Policies: append([]wire.PolicyRule(nil), a.policies...),
		Versions: versions,
	}
}

func (a *StubAgent) accept(typeURL, version string, policies []wire.PolicyRule) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.accepted[typeURL] = version
	// Policy state lives on the Cluster channel; other channels are
	// versioned-but-empty and carry no policy to adopt.
	if typeURL == resourcev3.ClusterType {
		a.policies = policies
	}
}

func (a *StubAgent) acceptedVersion(typeURL string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.accepted[typeURL]
}

// decodeSnapshot decodes the policy set carried by one DiscoveryResponse per the
// MER-54 server contract: policy rides the Cluster channel as a single
// wrapperspb.BytesValue Any wrapping a JSON []wire.PolicyRule; the other
// channels are versioned-but-empty. Any deviation (foreign channel payload,
// non-BytesValue resource, undecodable JSON, or more than one resource) is a
// contract violation and yields an error so the caller NACKs.
func decodeSnapshot(resp *discoveryv3.DiscoveryResponse) ([]wire.PolicyRule, error) {
	resources := resp.GetResources()
	switch resp.GetTypeUrl() {
	case resourcev3.ClusterType:
		// CDS: one CC-2 resource per policy.
		rules := make([]wire.PolicyRule, 0, len(resources))
		for i, res := range resources {
			r, err := cc2.DecodePolicyRule(res)
			if err != nil {
				return nil, fmt.Errorf("cluster resource[%d]: %w", i, err)
			}
			rules = append(rules, r)
		}
		return rules, nil
	case resourcev3.EndpointType:
		// EDS: one CC-2 resource per identity. The stub validates them
		// (fail-closed) but does not track them — CP-3 only inspects policies.
		for i, res := range resources {
			if _, err := cc2.DecodeIdentity(res); err != nil {
				return nil, fmt.Errorf("endpoint resource[%d]: %w", i, err)
			}
		}
		return nil, nil
	default:
		// LDS/RDS reserved, versioned-but-empty; a payload here is unexpected.
		if len(resources) != 0 {
			return nil, fmt.Errorf("unexpected %d resource(s) on %s", len(resources), resp.GetTypeUrl())
		}
		return nil, nil
	}
}
