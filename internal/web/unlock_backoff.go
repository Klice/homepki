package web

import (
	"sync"
	"time"
)

// Defaults for unlockBackoff per LIFECYCLE.md §1.2:
// "After 5 failures within 60s, sleep 2s on subsequent attempts (linear
// backoff, capped at 30s)."
const (
	defaultBackoffWindow    = 60 * time.Second
	defaultBackoffThreshold = 5
	defaultBackoffStep      = 2 * time.Second
	defaultBackoffMax       = 30 * time.Second
)

// unlockBackoff is the in-process counter that throttles repeated wrong
// unlock attempts per LIFECYCLE.md §1.2. It is deliberately NOT persisted —
// a process restart clears the counter, which is acceptable for a
// single-operator tool and avoids the lockout-survives-restart trap.
//
// The throttle is a soft delay added to the response, not a rejection: a
// caller with the right passphrase still gets through, just slowly. That
// keeps the path forward clear while making brute-force expensive.
type unlockBackoff struct {
	mu       sync.Mutex
	failures []time.Time

	// Tunables. Production uses defaults from the consts above; tests
	// override these to keep the suite fast.
	Window    time.Duration
	Threshold int
	Step      time.Duration
	Max       time.Duration

	// now is overridable for deterministic tests; nil means time.Now.
	now func() time.Time
}

// newUnlockBackoff returns a backoff with LIFECYCLE.md §1.2 defaults.
func newUnlockBackoff() *unlockBackoff {
	return &unlockBackoff{
		Window:    defaultBackoffWindow,
		Threshold: defaultBackoffThreshold,
		Step:      defaultBackoffStep,
		Max:       defaultBackoffMax,
	}
}

// Failure records a failed unlock attempt at the current instant.
func (b *unlockBackoff) Failure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = append(b.failures, b.timeNow())
}

// Reset clears the failure counter. Called after a successful unlock so
// the operator isn't penalized for typos that preceded a correct entry.
func (b *unlockBackoff) Reset() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = nil
}

// Delay returns how long the next unlock attempt should sleep before
// returning a response. 0 when the threshold hasn't been crossed.
//
// Linear backoff: at threshold the delay is one Step; each additional
// failure adds another Step, capped at Max.
func (b *unlockBackoff) Delay() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.timeNow()
	cutoff := now.Add(-b.Window)
	pruned := b.failures[:0]
	for _, t := range b.failures {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}
	b.failures = pruned

	n := len(b.failures)
	if n < b.Threshold {
		return 0
	}
	d := time.Duration(n-b.Threshold+1) * b.Step
	if d > b.Max {
		d = b.Max
	}
	return d
}

func (b *unlockBackoff) timeNow() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}
