// Package svid manages SVID issuance and rotation for workload identities
// served by this node (agent half of PKI-4). The Store holds the current SVID
// atomically and notifies subscribers on rotation; the Manager drives the
// keygen → CSR → Sign → store → rotate-at-2/3-TTL lifecycle.
package svid

import (
	"crypto/ecdsa"
	"crypto/x509"
	"sync"
	"time"
)

// Entry is one issued SVID: the leaf certificate, its private key, the full
// chain (leaf + intermediate(s)), and a convenient expiry timestamp.
type Entry struct {
	SpiffeID  string
	Leaf      *x509.Certificate
	Key       *ecdsa.PrivateKey
	Chain     []*x509.Certificate // leaf + intermediate(s); suitable for tls.Certificate.Certificate
	ExpiresAt time.Time
}

// Store is a concurrency-safe holder of the latest SVID for one workload
// identity. It supports a fan-out subscriber model so the Workload API server
// and the node proxy can both receive rotations without polling.
type Store struct {
	mu      sync.RWMutex
	current *Entry
	subs    []chan *Entry
}

// NewStore returns an empty Store. The first Set call issues the initial SVID
// to all pending subscribers.
func NewStore() *Store {
	return &Store{}
}

// Set atomically replaces the current entry and notifies all subscribers
// non-blockingly (subscribers with a full channel buffer are skipped — they
// will receive the next rotation, which is acceptable for a 24h TTL cert).
func (s *Store) Set(e *Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = e
	for _, ch := range s.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

// Current returns the latest entry, or nil if no SVID has been issued yet.
func (s *Store) Current() *Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Subscribe returns a buffered channel (cap 1) that receives a copy of every
// new entry after the subscription point. If the store already holds an entry
// it is sent immediately so the subscriber does not block until the next
// rotation. Callers with a bounded lifetime (e.g. one per connection) must
// call Unsubscribe when done, or the subscriber list grows without bound.
func (s *Store) Subscribe() <-chan *Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch := make(chan *Entry, 1)
	if s.current != nil {
		ch <- s.current
	}
	s.subs = append(s.subs, ch)
	return ch
}

// Unsubscribe removes ch from the subscriber list. It is a no-op for a
// channel the store does not know. The channel is not closed (the subscriber
// owns its read side and simply stops receiving).
func (s *Store) Unsubscribe(ch <-chan *Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, sub := range s.subs {
		if sub == ch {
			s.subs = append(s.subs[:i], s.subs[i+1:]...)
			return
		}
	}
}
