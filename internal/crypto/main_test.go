package crypto

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain wraps go test with a goroutine-leak check after every test in
// this package finishes. Catches regressions in the keystore concurrency
// path (Keystore.With + sync.WaitGroup.Go fan-out) where a missed Done
// or a leaked goroutine would otherwise pass tests silently and cause
// flakiness elsewhere.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
