package ads

import "testing"

const (
	testCluster  = "type.googleapis.com/envoy.config.cluster.v3.Cluster"
	testListener = "type.googleapis.com/envoy.config.listener.v3.Listener"
)

func TestPreparePushAdvancesVersionAndUniqueNonce(t *testing.T) {
	s := newStreamState()

	v1, n1 := s.preparePush(testCluster)
	v2, n2 := s.preparePush(testCluster)

	if v1 != "1" || v2 != "2" {
		t.Fatalf("version not monotonic: got %q then %q, want 1 then 2", v1, v2)
	}
	if n1 == n2 {
		t.Fatalf("nonces not unique: both %q", n1)
	}
	// Nonces are stream-global: a different type_url still gets a fresh nonce.
	_, n3 := s.preparePush(testListener)
	if n3 == n1 || n3 == n2 {
		t.Fatalf("cross-type nonce collided: %q", n3)
	}
}

func TestClassifyInitialRequest(t *testing.T) {
	s := newStreamState()
	if got := s.classify(testCluster, "", false); got != ackInitial {
		t.Fatalf("empty nonce should be ackInitial, got %v", got)
	}
}

func TestClassifyAckAdvancesAcceptedVersion(t *testing.T) {
	s := newStreamState()
	_, nonce := s.preparePush(testCluster)

	if got := s.classify(testCluster, nonce, false); got != ackAck {
		t.Fatalf("matching nonce + no error should be ackAck, got %v", got)
	}
	if got := s.acceptedVersion(testCluster); got != 1 {
		t.Fatalf("ACK should advance accepted version to 1, got %d", got)
	}
}

func TestClassifyNackHoldsLastKnownGood(t *testing.T) {
	s := newStreamState()

	// Push v1 and ACK it: accepted = 1.
	_, n1 := s.preparePush(testCluster)
	s.classify(testCluster, n1, false)
	if s.acceptedVersion(testCluster) != 1 {
		t.Fatalf("precondition: accepted should be 1")
	}

	// Push v2 and NACK it: accepted must stay at 1 (CC-5 last-known-good).
	_, n2 := s.preparePush(testCluster)
	if got := s.classify(testCluster, n2, true); got != ackNack {
		t.Fatalf("matching nonce + error should be ackNack, got %v", got)
	}
	if got := s.acceptedVersion(testCluster); got != 1 {
		t.Fatalf("NACK must hold accepted at 1, got %d", got)
	}
	if got := s.sentVersionOf(testCluster); got != 2 {
		t.Fatalf("sent version should still be 2 after NACK, got %d", got)
	}
}

func TestClassifyStaleNonceIgnored(t *testing.T) {
	s := newStreamState()
	_, nonce := s.preparePush(testCluster)

	tests := []struct {
		name  string
		nonce string
	}{
		{"unknown nonce", "does-not-exist"},
		{"matching after settle", nonce}, // settled below, replayed
	}

	// First settle the outstanding push with a correct ACK.
	if got := s.classify(testCluster, nonce, false); got != ackAck {
		t.Fatalf("setup ACK should be ackAck, got %v", got)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := s.acceptedVersion(testCluster)
			if got := s.classify(testCluster, tc.nonce, false); got != ackStale {
				t.Fatalf("replayed/unknown nonce should be ackStale, got %v", got)
			}
			if after := s.acceptedVersion(testCluster); after != before {
				t.Fatalf("stale request changed accepted version: %d -> %d", before, after)
			}
		})
	}
}

func TestClassifyResubscribeAfterSettle(t *testing.T) {
	s := newStreamState()
	_, n1 := s.preparePush(testCluster)
	s.classify(testCluster, n1, false)

	// A fresh empty-nonce request (client resubscribe/reconnect) is initial.
	if got := s.classify(testCluster, "", false); got != ackInitial {
		t.Fatalf("resubscribe with empty nonce should be ackInitial, got %v", got)
	}
}
