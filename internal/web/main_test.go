package web

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain wraps go test with a goroutine-leak check after every test in
// this package finishes. The auto-lock and unlock-backoff paths spawn
// goroutines (time.AfterFunc, post-success Touch); a missed Stop or a
// dangling AfterFunc would otherwise pile up across the test run and
// only surface as flakiness later.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
