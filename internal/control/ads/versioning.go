// Package ads implements the control-plane Aggregated Discovery Service: a
// single bidirectional xDS stream that pushes Meridian's compiled policy state
// to agents and tracks the xDS version/nonce handshake per resource type.
//
// MER-54 ships the ADS transport + the version/nonce state machine + a
// Store.Watch()-driven ordered push. The resource *payload* encoding is the
// internal server↔stub contract for CP-1/CP-3 (MER-55/56); the real xDS
// resource model is frozen later under CC-2 (compiled-policy wire contract).
package ads

import (
	"strconv"
	"sync"
)

// ackKind classifies an inbound DiscoveryRequest relative to the server's
// outstanding push for that type_url.
type ackKind int

const (
	// ackInitial is a first/empty-nonce subscription request for a type_url.
	ackInitial ackKind = iota
	// ackAck acknowledges the outstanding push (nonce matches, no error):
	// the accepted version advances to the pushed version.
	ackAck
	// ackNack rejects the outstanding push (nonce matches, error_detail set):
	// the accepted version is held at its prior last-known-good value (CC-5).
	ackNack
	// ackStale is an empty/mismatched nonce against the outstanding push and
	// is ignored — it never changes accepted state.
	ackStale
)

// typeState is the per-type_url version/nonce bookkeeping within one stream.
type typeState struct {
	sentVersion    uint64 // latest version the server has pushed
	ackedVersion   uint64 // latest version the client ACKed (last-known-good)
	lastNonce      string // nonce of the outstanding push, "" once settled
	hasOutstanding bool   // a push awaits ACK/NACK
}

// streamState tracks version/nonce handshakes for a single ADS stream. ADS
// multiplexes every resource type over one stream, so the state is keyed by
// type_url. All methods are safe for concurrent use: the request-reader and
// the Watch-driven pusher touch it from different goroutines.
type streamState struct {
	mu       sync.Mutex
	byType   map[string]*typeState
	nonceSeq uint64 // stream-global, guarantees per-stream unique nonces
}

func newStreamState() *streamState {
	return &streamState{byType: make(map[string]*typeState)}
}

// getLocked returns (creating if needed) the per-type state. Caller holds mu.
func (s *streamState) getLocked(typeURL string) *typeState {
	ts, ok := s.byType[typeURL]
	if !ok {
		ts = &typeState{}
		s.byType[typeURL] = ts
	}
	return ts
}

// preparePush assigns the next version and a fresh, stream-unique nonce for a
// type_url, marks the push outstanding, and returns the strings to stamp on the
// DiscoveryResponse.
func (s *streamState) preparePush(typeURL string) (version, nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.getLocked(typeURL)
	ts.sentVersion++
	s.nonceSeq++
	nonce = strconv.FormatUint(s.nonceSeq, 10)
	ts.lastNonce = nonce
	ts.hasOutstanding = true
	return strconv.FormatUint(ts.sentVersion, 10), nonce
}

// classify interprets an inbound DiscoveryRequest and applies its effect on the
// accepted version. An empty responseNonce is an initial subscription. A nonce
// matching the outstanding push settles it: ACK advances the accepted version,
// NACK holds last-known-good. Any other nonce is stale and ignored.
func (s *streamState) classify(typeURL, responseNonce string, hasError bool) ackKind {
	s.mu.Lock()
	defer s.mu.Unlock()
	ts := s.getLocked(typeURL)

	if responseNonce == "" {
		return ackInitial
	}
	if !ts.hasOutstanding || responseNonce != ts.lastNonce {
		return ackStale
	}

	// The outstanding push is being settled.
	ts.hasOutstanding = false
	ts.lastNonce = ""
	if hasError {
		// CC-5: a rejected config never becomes accepted state.
		return ackNack
	}
	ts.ackedVersion = ts.sentVersion
	return ackAck
}

// acceptedVersion reports the last-known-good version for a type_url.
func (s *streamState) acceptedVersion(typeURL string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(typeURL).ackedVersion
}

// sentVersionOf reports the latest pushed version for a type_url.
func (s *streamState) sentVersionOf(typeURL string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.getLocked(typeURL).sentVersion
}
