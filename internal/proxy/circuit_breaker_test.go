package proxy

import (
	"testing"
	"time"
)

func newTestCB(threshold int, resetAfter time.Duration) *CircuitBreaker {
	return NewCircuitBreaker(threshold, resetAfter)
}

func TestCBInitiallyAllows(t *testing.T) {
	cb := newTestCB(3, time.Second)
	if err := cb.Allow(); err != nil {
		t.Fatalf("new CB should allow: %v", err)
	}
	if cb.State() != CBClosed {
		t.Fatalf("state = %s, want closed", cb.State())
	}
}

func TestCBOpensAfterThreshold(t *testing.T) {
	cb := newTestCB(3, time.Minute)
	for i := 0; i < 3; i++ {
		cb.RecordFailure()
	}
	if cb.State() != CBOpen {
		t.Fatalf("state = %s, want open after %d failures", cb.State(), 3)
	}
	if err := cb.Allow(); err != ErrCircuitOpen {
		t.Fatalf("Allow() = %v, want ErrCircuitOpen", err)
	}
}

func TestCBDoesNotOpenBelowThreshold(t *testing.T) {
	cb := newTestCB(3, time.Minute)
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.State() != CBClosed {
		t.Fatalf("state = %s, want closed after 2 of 3 failures", cb.State())
	}
	if err := cb.Allow(); err != nil {
		t.Fatalf("should still allow below threshold: %v", err)
	}
}

func TestCBSuccessResetsCounter(t *testing.T) {
	cb := newTestCB(3, time.Minute)
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure()
	// Only 2 failures after the success reset — should still be closed.
	if cb.State() != CBClosed {
		t.Fatalf("state = %s, want closed (counter reset by success)", cb.State())
	}
}

func TestCBTransitionsToHalfOpenAfterReset(t *testing.T) {
	var fakeNow time.Time
	cb := newTestCB(1, 100*time.Millisecond)
	cb.nowFn = func() time.Time { return fakeNow }

	fakeNow = time.Now()
	cb.RecordFailure() // trips open
	if cb.State() != CBOpen {
		t.Fatalf("state = %s, want open", cb.State())
	}

	// Advance time past reset window.
	fakeNow = fakeNow.Add(200 * time.Millisecond)

	if err := cb.Allow(); err != nil {
		t.Fatalf("Allow after reset window: want nil (half-open probe), got %v", err)
	}
	if cb.State() != CBHalfOpen {
		t.Fatalf("state = %s, want half-open", cb.State())
	}
}

func TestCBHalfOpenSuccessCloses(t *testing.T) {
	fakeNow := time.Now()
	cb := newTestCB(1, 10*time.Millisecond)
	cb.nowFn = func() time.Time { return fakeNow }

	cb.RecordFailure() // open
	fakeNow = fakeNow.Add(20 * time.Millisecond)
	_ = cb.Allow() // half-open probe
	cb.RecordSuccess()

	if cb.State() != CBClosed {
		t.Fatalf("state = %s, want closed after probe success", cb.State())
	}
	if err := cb.Allow(); err != nil {
		t.Fatalf("should allow after recovery: %v", err)
	}
}

func TestCBHalfOpenFailureReopens(t *testing.T) {
	fakeNow := time.Now()
	cb := newTestCB(1, 10*time.Millisecond)
	cb.nowFn = func() time.Time { return fakeNow }

	cb.RecordFailure() // open
	fakeNow = fakeNow.Add(20 * time.Millisecond)
	_ = cb.Allow()     // half-open
	cb.RecordFailure() // probe failed → reopen

	if cb.State() != CBOpen {
		t.Fatalf("state = %s, want open after half-open failure", cb.State())
	}
}

func TestCBOpenRejectsBeforeReset(t *testing.T) {
	fakeNow := time.Now()
	cb := newTestCB(1, time.Hour)
	cb.nowFn = func() time.Time { return fakeNow }

	cb.RecordFailure()
	fakeNow = fakeNow.Add(30 * time.Minute) // not yet past the 1h reset

	if err := cb.Allow(); err != ErrCircuitOpen {
		t.Fatalf("Allow before reset: want ErrCircuitOpen, got %v", err)
	}
}

func TestCBHalfOpenBlocksSecondConcurrentProbe(t *testing.T) {
	fakeNow := time.Now()
	cb := newTestCB(1, 10*time.Millisecond)
	cb.nowFn = func() time.Time { return fakeNow }

	cb.RecordFailure() // open
	fakeNow = fakeNow.Add(20 * time.Millisecond)

	// First Allow advances to half-open.
	if err := cb.Allow(); err != nil {
		t.Fatalf("first Allow: %v", err)
	}
	// Second Allow while half-open must be rejected.
	if err := cb.Allow(); err != ErrCircuitOpen {
		t.Fatalf("second Allow while half-open: want ErrCircuitOpen, got %v", err)
	}
}

func TestCBStateString(t *testing.T) {
	for _, tc := range []struct {
		s    CBState
		want string
	}{
		{CBClosed, "closed"},
		{CBOpen, "open"},
		{CBHalfOpen, "half-open"},
	} {
		if tc.s.String() != tc.want {
			t.Fatalf("CBState(%d).String() = %q, want %q", tc.s, tc.s.String(), tc.want)
		}
	}
}
