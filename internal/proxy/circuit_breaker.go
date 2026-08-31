package proxy

import (
	"fmt"
	"sync"
	"time"
)

// CBState is the circuit breaker state.
type CBState uint8

const (
	CBClosed   CBState = iota // normal: requests pass through
	CBOpen                    // tripped: requests rejected immediately
	CBHalfOpen                // probe: one request allowed to test recovery
)

func (s CBState) String() string {
	switch s {
	case CBClosed:
		return "closed"
	case CBOpen:
		return "open"
	case CBHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen is returned by CircuitBreaker.Allow when the circuit is open.
var ErrCircuitOpen = fmt.Errorf("circuit breaker open")

// CircuitBreaker implements the consecutive-error circuit breaker described in
// PRD §4.8 (P5.2). It is safe for concurrent use.
//
// State transitions:
//
//	Closed → Open   : consecutiveErrors reaches Threshold
//	Open   → HalfOpen : ResetAfter elapses
//	HalfOpen → Closed : probe call succeeds (RecordSuccess)
//	HalfOpen → Open   : probe call fails (RecordFailure)
//
// The zero value is invalid; always construct with NewCircuitBreaker.
type CircuitBreaker struct {
	mu                sync.Mutex
	state             CBState
	consecutiveErrors int
	openedAt          time.Time

	// Configuration (immutable after construction).
	Threshold   int           // consecutive errors before opening
	ResetAfter  time.Duration // how long to stay open before half-open probe
	nowFn       func() time.Time
}

// NewCircuitBreaker returns a Closed circuit breaker with the given parameters.
func NewCircuitBreaker(threshold int, resetAfter time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		Threshold:  threshold,
		ResetAfter: resetAfter,
		nowFn:      time.Now,
	}
}

// Allow returns nil if a request is permitted, or ErrCircuitOpen if the
// circuit is open and the reset window has not elapsed. If the circuit is
// open and the reset window has elapsed the state is advanced to HalfOpen
// and nil is returned (allowing one probe request).
func (cb *CircuitBreaker) Allow() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	switch cb.state {
	case CBClosed:
		return nil
	case CBOpen:
		if cb.nowFn().Sub(cb.openedAt) >= cb.ResetAfter {
			cb.state = CBHalfOpen
			return nil // allow the probe
		}
		return ErrCircuitOpen
	case CBHalfOpen:
		// Only one probe at a time; subsequent callers are rejected.
		return ErrCircuitOpen
	}
	return nil
}

// RecordSuccess records a successful response. If the circuit was HalfOpen,
// it transitions back to Closed and resets the error counter.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.consecutiveErrors = 0
	cb.state = CBClosed
}

// RecordFailure records a failed response. If consecutiveErrors reaches
// Threshold the circuit opens. If already HalfOpen a single failure re-opens.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.consecutiveErrors++
	if cb.state == CBHalfOpen || cb.consecutiveErrors >= cb.Threshold {
		cb.state = CBOpen
		cb.openedAt = cb.nowFn()
		cb.consecutiveErrors = 0
	}
}

// State returns the current state (for metrics/diagnostics).
func (cb *CircuitBreaker) State() CBState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}
