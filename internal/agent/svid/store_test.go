package svid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func makeTestEntry(t *testing.T, spiffeID string, ttl time.Duration) *Entry {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: spiffeID},
		NotBefore:    now,
		NotAfter:     now.Add(ttl),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return &Entry{
		SpiffeID:  spiffeID,
		Leaf:      leaf,
		Key:       key,
		Chain:     []*x509.Certificate{leaf},
		ExpiresAt: leaf.NotAfter,
	}
}

func TestStoreCurrentNilBeforeSet(t *testing.T) {
	s := NewStore()
	if s.Current() != nil {
		t.Fatal("expected nil before first Set")
	}
}

func TestStoreSetAndCurrent(t *testing.T) {
	s := NewStore()
	e := makeTestEntry(t, "spiffe://x/svc", 24*time.Hour)
	s.Set(e)
	if got := s.Current(); got != e {
		t.Fatalf("Current() = %v, want %v", got, e)
	}
}

func TestStoreSubscribeReceivesCurrentImmediately(t *testing.T) {
	s := NewStore()
	e := makeTestEntry(t, "spiffe://x/svc", 24*time.Hour)
	s.Set(e)

	ch := s.Subscribe()
	select {
	case got := <-ch:
		if got != e {
			t.Fatalf("got %v, want %v", got, e)
		}
	default:
		t.Fatal("expected current entry buffered into subscribe channel immediately")
	}
}

func TestStoreSubscribeReceivesRotation(t *testing.T) {
	s := NewStore()
	ch := s.Subscribe()

	// No current yet — channel should be empty.
	select {
	case <-ch:
		t.Fatal("expected empty channel before first Set")
	default:
	}

	e := makeTestEntry(t, "spiffe://x/svc", 24*time.Hour)
	s.Set(e)

	select {
	case got := <-ch:
		if got != e {
			t.Fatalf("got %v, want %v", got, e)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for entry notification")
	}
}

func TestStoreMultipleSubscribers(t *testing.T) {
	s := NewStore()
	ch1 := s.Subscribe()
	ch2 := s.Subscribe()

	e := makeTestEntry(t, "spiffe://x/svc", 24*time.Hour)
	s.Set(e)

	for i, ch := range []<-chan *Entry{ch1, ch2} {
		select {
		case got := <-ch:
			if got != e {
				t.Fatalf("subscriber %d got %v, want %v", i, got, e)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d timed out", i)
		}
	}
}

func TestStoreSetReplacesAndNotifies(t *testing.T) {
	s := NewStore()
	e1 := makeTestEntry(t, "spiffe://x/svc", 24*time.Hour)
	e2 := makeTestEntry(t, "spiffe://x/svc", 24*time.Hour)

	s.Set(e1)
	ch := s.Subscribe()
	<-ch // drain initial

	s.Set(e2)
	select {
	case got := <-ch:
		if got != e2 {
			t.Fatalf("rotation: got %v, want e2", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for rotation notification")
	}
	if s.Current() != e2 {
		t.Fatal("Current() should return e2 after rotation")
	}
}

func TestStoreUnsubscribeStopsDelivery(t *testing.T) {
	s := NewStore()
	ch := s.Subscribe()
	s.Unsubscribe(ch)

	s.Set(makeTestEntry(t, "spiffe://x/svc", 24*time.Hour))
	select {
	case e := <-ch:
		if e != nil {
			t.Fatal("received rotation after Unsubscribe")
		}
	default:
	}
}

func TestStoreUnsubscribeUnknownChannelIsNoop(t *testing.T) {
	s := NewStore()
	other := make(chan *Entry, 1)
	s.Unsubscribe(other) // must not panic or disturb real subscribers

	ch := s.Subscribe()
	s.Set(makeTestEntry(t, "spiffe://x/svc", 24*time.Hour))
	select {
	case <-ch:
	case <-time.After(time.Second):
		t.Fatal("subscriber missed rotation after unrelated Unsubscribe")
	}
}
