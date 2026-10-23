package xds

import (
	"testing"
	"time"
)

// TestReconnectBackoffGrowsExponentially pins the reconnect schedule: a control
// plane that stays down must be probed with geometrically increasing delay, not
// at a flat rate. The pre-fix client retried every 200-400ms forever, so a
// single agent generated ~3 dial attempts/second indefinitely and a fleet
// turned a control-plane outage into a thundering herd on recovery.
func TestReconnectBackoffGrowsExponentially(t *testing.T) {
	// Lower bound of attempt N must at least double the lower bound of N-1
	// until the ceiling is reached.
	var prevMin time.Duration
	for attempt := 0; attempt < 8; attempt++ {
		min, max := reconnectBackoffRange(attempt)

		if min <= 0 {
			t.Fatalf("attempt %d: min delay %v must be positive", attempt, min)
		}
		if max < min {
			t.Fatalf("attempt %d: max %v < min %v", attempt, max, min)
		}
		if max > reconnectMax {
			t.Fatalf("attempt %d: max %v exceeds ceiling %v", attempt, max, reconnectMax)
		}
		if attempt > 0 && min < reconnectMax {
			if want := prevMin * 2; min != want {
				t.Fatalf("attempt %d: min = %v, want %v (doubling)", attempt, min, want)
			}
		}
		prevMin = min
	}
}

// TestReconnectBackoffCapped ensures a long outage settles at the ceiling
// rather than growing without bound into multi-minute blackouts.
func TestReconnectBackoffCapped(t *testing.T) {
	for _, attempt := range []int{20, 100, 1000, 1 << 20} {
		min, max := reconnectBackoffRange(attempt)
		if min > reconnectMax || max > reconnectMax {
			t.Fatalf("attempt %d: range [%v,%v] exceeds ceiling %v", attempt, min, max, reconnectMax)
		}
		if min != reconnectMax {
			t.Fatalf("attempt %d: min = %v, want saturated %v", attempt, min, reconnectMax)
		}
	}
}

// TestReconnectBackoffJittered ensures each attempt carries jitter, so agents
// that lost the control plane together do not re-dial in lockstep.
func TestReconnectBackoffJittered(t *testing.T) {
	min, max := reconnectBackoffRange(0)
	if max <= min {
		t.Fatalf("attempt 0 has no jitter window: [%v,%v]", min, max)
	}
	d := reconnectDelay(0)
	if d < min || d >= max {
		t.Fatalf("reconnectDelay(0) = %v, want within [%v,%v)", d, min, max)
	}
}

// TestReconnectBackoffFirstRetryIsFast keeps a single dropped stream cheap:
// the first retry must stay sub-second so a transient blip is invisible.
func TestReconnectBackoffFirstRetryIsFast(t *testing.T) {
	if _, max := reconnectBackoffRange(0); max > time.Second {
		t.Fatalf("first retry upper bound %v too slow", max)
	}
}

// TestReconnectAttemptAfterProgress pins the tier chosen for the delay that
// follows a stream ending. This is applied BEFORE the delay is computed, so a
// healthy stream that blips recovers at tier 0 instead of inheriting the
// escalation left over from an earlier outage.
func TestReconnectAttemptAfterProgress(t *testing.T) {
	tests := []struct {
		name       string
		attempt    int
		progressed bool
		want       int
	}{
		{name: "healthy stream clears escalation", attempt: 7, progressed: true, want: 0},
		{name: "failed dial holds tier for this cycle", attempt: 7, progressed: false, want: 7},
		{name: "first failure retries at tier zero", attempt: 0, progressed: false, want: 0},
		{name: "immediate progress stays at zero", attempt: 0, progressed: true, want: 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := reconnectAttemptAfter(tc.attempt, tc.progressed); got != tc.want {
				t.Fatalf("reconnectAttemptAfter(%d,%v) = %d, want %d",
					tc.attempt, tc.progressed, got, tc.want)
			}
		})
	}
}

// TestReconnectBackoffNegativeAttemptClamped guards the defensive clamp so a
// caller bug degrades to the fastest tier rather than a negative shift.
func TestReconnectBackoffNegativeAttemptClamped(t *testing.T) {
	gotMin, gotMax := reconnectBackoffRange(-5)
	wantMin, wantMax := reconnectBackoffRange(0)
	if gotMin != wantMin || gotMax != wantMax {
		t.Fatalf("reconnectBackoffRange(-5) = [%v,%v], want tier 0 [%v,%v]",
			gotMin, gotMax, wantMin, wantMax)
	}
}

// TestReconnectDelayWithinEscalatedWindow samples an escalated tier, not just
// tier 0, so jitter is exercised after doubling.
func TestReconnectDelayWithinEscalatedWindow(t *testing.T) {
	const attempt = 4
	lo, hi := reconnectBackoffRange(attempt)
	for i := 0; i < 50; i++ {
		d := reconnectDelay(attempt)
		if d < lo || d >= hi {
			t.Fatalf("reconnectDelay(%d) = %v, want within [%v,%v)", attempt, d, lo, hi)
		}
	}
}
