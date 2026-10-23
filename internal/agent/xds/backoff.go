package xds

import (
	"math/rand"
	"time"
)

const (
	// reconnectBase is the lower bound of the first retry window. A single
	// dropped stream should recover fast enough to be invisible.
	reconnectBase = 200 * time.Millisecond
	// reconnectJitter is the width of the randomised window at attempt 0; it
	// scales with the delay so agents never re-dial in lockstep.
	reconnectJitter = 200 * time.Millisecond
	// reconnectMax caps the schedule. A control plane that is down for hours
	// is probed twice a minute per agent rather than three times a second.
	reconnectMax = 30 * time.Second
)

// reconnectBackoffRange returns the [min,max) delay window for a zero-based
// reconnect attempt: exponential growth from reconnectBase, saturating at
// reconnectMax. Separated from reconnectDelay so the schedule is assertable
// without sampling randomness.
func reconnectBackoffRange(attempt int) (time.Duration, time.Duration) {
	if attempt < 0 {
		attempt = 0
	}

	lo := reconnectBase
	jitter := reconnectJitter
	for i := 0; i < attempt; i++ {
		if lo >= reconnectMax {
			break
		}
		lo *= 2
		jitter *= 2
	}

	if lo >= reconnectMax {
		return reconnectMax, reconnectMax
	}
	hi := lo + jitter
	if hi > reconnectMax {
		hi = reconnectMax
	}
	return lo, hi
}

// reconnectDelay samples the backoff window for a zero-based attempt.
func reconnectDelay(attempt int) time.Duration {
	lo, hi := reconnectBackoffRange(attempt)
	if hi <= lo {
		return lo
	}
	return lo + time.Duration(rand.Int63n(int64(hi-lo)))
}

// reconnectAttemptAfter returns the escalation tier to use for the delay that
// follows a stream ending.
//
// It must be applied BEFORE reconnectDelay, not after the sleep: a stream that
// made progress (opened and delivered at least one response) proves the path
// is healthy, so the disconnect that follows starts a fresh escalation instead
// of inheriting the previous outage's ceiling. Folding the reset in afterwards
// would make a single blip on a long-lived stream wait out the stale delay —
// up to the full reconnectMax — before recovering.
//
// A stream that did not progress keeps the current tier; Run increments after
// sleeping, so consecutive failures still escalate 0,1,2,… and the first
// failure retries at tier 0.
func reconnectAttemptAfter(attempt int, progressed bool) int {
	if progressed {
		return 0
	}
	return attempt
}
