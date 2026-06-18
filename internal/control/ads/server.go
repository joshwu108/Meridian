package ads

import (
	"context"
	"errors"
	"io"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoveryv3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/joshuawu/meridian/internal/cc2"
	"github.com/joshuawu/meridian/internal/control"
)

// pushOrder is the xDS make-before-break ordering: clusters before the
// endpoints that reference them, listeners before their routes (CDS→EDS,
// LDS→RDS). The server pushes subscribed types in this order on every change.
var pushOrder = []string{
	resourcev3.ClusterType,
	resourcev3.EndpointType,
	resourcev3.ListenerType,
	resourcev3.RouteType,
}

// stream is the subset of the generated ADS stream the handler needs; declaring
// it locally keeps the handler unit-testable without the full gRPC machinery.
type stream interface {
	Context() context.Context
	Send(*discoveryv3.DiscoveryResponse) error
	Recv() (*discoveryv3.DiscoveryRequest, error)
}

// Server is the control-plane ADS server. It is the sole consumer of the
// control.Store Watch() seam: a store change recompiles and pushes the
// subscribed resource types in pushOrder. It depends only on the Store
// interface, so it runs against any backend.
type Server struct {
	discoveryv3.UnimplementedAggregatedDiscoveryServiceServer
	store control.Store
}

// NewServer constructs an ADS server backed by store.
func NewServer(store control.Store) *Server {
	return &Server{store: store}
}

// StreamAggregatedResources serves one bidirectional ADS stream. It serves the
// generated gRPC interface by delegating to the testable handler below.
func (s *Server) StreamAggregatedResources(srv discoveryv3.AggregatedDiscoveryService_StreamAggregatedResourcesServer) error {
	return s.handle(srv)
}

// handle runs the stream loop: it reads requests in a helper goroutine and
// selects over inbound requests, Store change notifications, and stream
// teardown. Subscribed type_urls are (re)pushed in pushOrder on every change.
func (s *Server) handle(srv stream) error {
	ctx := srv.Context()
	state := newStreamState()
	watch := s.store.Watch(ctx)
	subscribed := make(map[string]bool)

	reqCh := make(chan *discoveryv3.DiscoveryRequest)
	errCh := make(chan error, 1)
	go func() {
		for {
			req, err := srv.Recv()
			if err != nil {
				errCh <- err
				return
			}
			select {
			case reqCh <- req:
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errCh:
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		case req := <-reqCh:
			if err := s.onRequest(srv, state, subscribed, req); err != nil {
				return err
			}
		case _, ok := <-watch:
			if !ok {
				// Watch channel closed (ctx cancelled); ctx.Done wins next loop.
				watch = nil
				continue
			}
			if err := s.pushAll(srv, state, subscribed); err != nil {
				return err
			}
		}
	}
}

// onRequest applies one inbound DiscoveryRequest to the stream state. An
// initial subscription triggers a push; an ACK advances accepted state; a NACK
// holds last-known-good (no re-push); a stale nonce is ignored.
func (s *Server) onRequest(srv stream, state *streamState, subscribed map[string]bool, req *discoveryv3.DiscoveryRequest) error {
	typeURL := req.GetTypeUrl()
	if typeURL == "" {
		return nil
	}
	switch state.classify(typeURL, req.GetResponseNonce(), req.GetErrorDetail() != nil) {
	case ackInitial:
		subscribed[typeURL] = true
		return s.push(srv, state, typeURL)
	case ackAck, ackNack, ackStale:
		// ACK: accepted advanced in classify. NACK: held last-known-good.
		// Stale: ignored. None re-push here.
		return nil
	default:
		return nil
	}
}

// pushAll re-pushes every subscribed type_url in make-before-break order.
func (s *Server) pushAll(srv stream, state *streamState, subscribed map[string]bool) error {
	for _, typeURL := range pushOrder {
		if subscribed[typeURL] {
			if err := s.push(srv, state, typeURL); err != nil {
				return err
			}
		}
	}
	return nil
}

// push builds and sends a versioned, nonce-stamped DiscoveryResponse for one
// type_url.
func (s *Server) push(srv stream, state *streamState, typeURL string) error {
	resources, err := s.resourcesFor(srv.Context(), typeURL)
	if err != nil {
		return err
	}
	version, nonce := state.preparePush(typeURL)
	return srv.Send(&discoveryv3.DiscoveryResponse{
		TypeUrl:     typeURL,
		VersionInfo: version,
		Nonce:       nonce,
		Resources:   resources,
		ControlPlane: &corev3.ControlPlane{
			Identifier: "meridian-control",
		},
	})
}

// resourcesFor returns the xDS resources for a type_url, encoded per the frozen
// CC-2 contract (ADR-0008 / internal/cc2): one resource per policy on the
// Cluster (CDS) channel and one per identity on the Endpoint (EDS) channel.
// LDS/RDS are reserved and versioned-but-empty until Phase 5 (L7).
func (s *Server) resourcesFor(ctx context.Context, typeURL string) ([]*anypb.Any, error) {
	switch typeURL {
	case resourcev3.ClusterType:
		policies, err := s.store.ListPolicies(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]*anypb.Any, 0, len(policies))
		for _, p := range policies {
			a, err := cc2.EncodePolicyRule(p)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		}
		return out, nil
	case resourcev3.EndpointType:
		identities, err := s.store.ListIdentities(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]*anypb.Any, 0, len(identities))
		for _, id := range identities {
			a, err := cc2.EncodeIdentity(id)
			if err != nil {
				return nil, err
			}
			out = append(out, a)
		}
		return out, nil
	default:
		return nil, nil
	}
}
