package web

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func fastBackoff() *unlockBackoff {
	b := newUnlockBackoff()
	// Tiny delays so the test suite stays sub-second even with backoff
	// engaged, but keep the threshold and ratios so we're testing the
	// real code path.
	b.Step = 5 * time.Millisecond
	b.Max = 30 * time.Millisecond
	return b
}

func TestUnlockBackoff_NoDelayBelowThreshold(t *testing.T) {
	b := fastBackoff()
	for range b.Threshold - 1 {
		b.Failure()
	}
	assert.Equal(t, time.Duration(0), b.Delay(), "delay below threshold")
}

func TestUnlockBackoff_LinearAfterThreshold(t *testing.T) {
	b := fastBackoff()
	cases := []struct {
		failures int
		want     time.Duration
	}{
		{5, 1 * b.Step},
		{6, 2 * b.Step},
		{7, 3 * b.Step},
		{8, 4 * b.Step},
	}
	for _, tc := range cases {
		// Reset and replay to <failures> count.
		b.Reset()
		for range tc.failures {
			b.Failure()
		}
		assert.Equal(t, tc.want, b.Delay(), "%d failures", tc.failures)
	}
}

func TestUnlockBackoff_CapsAtMax(t *testing.T) {
	b := fastBackoff()
	for range 100 {
		b.Failure()
	}
	assert.Equal(t, b.Max, b.Delay(), "should be capped at max")
}

func TestUnlockBackoff_ResetClears(t *testing.T) {
	b := fastBackoff()
	for range 10 {
		b.Failure()
	}
	require.NotEqual(t, time.Duration(0), b.Delay(), "expected non-zero delay before reset")
	b.Reset()
	assert.Equal(t, time.Duration(0), b.Delay(), "after reset")
}

func TestUnlockBackoff_OldFailuresFallOutOfWindow(t *testing.T) {
	b := fastBackoff()
	b.Window = 50 * time.Millisecond

	// Inject 6 failures from "the past" via a stub clock.
	past := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := past
	b.now = func() time.Time { return now }
	for range 6 {
		b.Failure()
	}
	require.NotEqual(t, time.Duration(0), b.Delay(), "expected delay to be non-zero before time passes")
	// Advance past the window — every failure now falls outside it.
	now = past.Add(b.Window + time.Millisecond)
	assert.Equal(t, time.Duration(0), b.Delay(), "delay after window slid past")
}

// ============== integration with handleUnlockPost ==============

// TestUnlockHandler_BackoffEngagedAfterRepeatedFailures relies on the
// server-side backoff. We swap the server's backoff for a fast one so
// the assertions are deterministic and quick.
func TestUnlockHandler_BackoffEngagedAfterRepeatedFailures(t *testing.T) {
	srv, db := testServer(t)
	fastSetup(t, srv, db)
	srv.keystore.Lock()
	srv.backoff = fastBackoff()

	c := newClient(t, srv)
	c.get("/unlock") // prime CSRF cookie

	// Five wrong attempts — none should hit the backoff yet.
	for range 5 {
		w := c.postForm("/unlock", url.Values{"passphrase": {"wrong"}})
		require.Equal(t, http.StatusBadRequest, w.Code, "wrong attempt")
	}

	// Sixth wrong attempt — backoff fires; the response just takes longer.
	start := time.Now()
	w := c.postForm("/unlock", url.Values{"passphrase": {"wrong"}})
	elapsed := time.Since(start)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.GreaterOrEqual(t, elapsed, srv.backoff.Step, "expected at least %v of backoff delay", srv.backoff.Step)

	// Correct passphrase still works (the backoff slows but doesn't reject).
	w = c.postForm("/unlock", url.Values{"passphrase": {validPassphrase}})
	assert.Equal(t, http.StatusSeeOther, w.Code, "correct passphrase after backoff: body=%q", w.Body.String())
	assert.True(t, srv.keystore.IsUnlocked(), "keystore should be unlocked after correct passphrase")
	// Successful unlock clears the counter.
	assert.Equal(t, time.Duration(0), srv.backoff.Delay(), "backoff delay after success")
}
