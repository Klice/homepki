package web

import (
	"net/http"
	"net/url"
	"testing"
	"time"
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
	if d := b.Delay(); d != 0 {
		t.Errorf("delay below threshold: got %v, want 0", d)
	}
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
		got := b.Delay()
		if got != tc.want {
			t.Errorf("%d failures: got %v, want %v", tc.failures, got, tc.want)
		}
	}
}

func TestUnlockBackoff_CapsAtMax(t *testing.T) {
	b := fastBackoff()
	for range 100 {
		b.Failure()
	}
	if d := b.Delay(); d != b.Max {
		t.Errorf("got %v, want capped at %v", d, b.Max)
	}
}

func TestUnlockBackoff_ResetClears(t *testing.T) {
	b := fastBackoff()
	for range 10 {
		b.Failure()
	}
	if b.Delay() == 0 {
		t.Fatal("expected non-zero delay before reset")
	}
	b.Reset()
	if d := b.Delay(); d != 0 {
		t.Errorf("after reset: got %v, want 0", d)
	}
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
	if b.Delay() == 0 {
		t.Fatal("expected delay to be non-zero before time passes")
	}
	// Advance past the window — every failure now falls outside it.
	now = past.Add(b.Window + time.Millisecond)
	if d := b.Delay(); d != 0 {
		t.Errorf("delay after window slid past: got %v, want 0", d)
	}
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
		if w.Code != http.StatusBadRequest {
			t.Fatalf("wrong attempt: got %d", w.Code)
		}
	}

	// Sixth wrong attempt — backoff fires; the response just takes longer.
	start := time.Now()
	w := c.postForm("/unlock", url.Values{"passphrase": {"wrong"}})
	elapsed := time.Since(start)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: %d", w.Code)
	}
	if elapsed < srv.backoff.Step {
		t.Errorf("expected at least %v of backoff delay, got %v", srv.backoff.Step, elapsed)
	}

	// Correct passphrase still works (the backoff slows but doesn't reject).
	w = c.postForm("/unlock", url.Values{"passphrase": {validPassphrase}})
	if w.Code != http.StatusSeeOther {
		t.Errorf("correct passphrase after backoff: got %d body=%q", w.Code, w.Body.String())
	}
	if !srv.keystore.IsUnlocked() {
		t.Error("keystore should be unlocked after correct passphrase")
	}
	// Successful unlock clears the counter.
	if d := srv.backoff.Delay(); d != 0 {
		t.Errorf("backoff delay after success: got %v, want 0", d)
	}
}
