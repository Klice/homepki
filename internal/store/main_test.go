package store

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain wraps go test with a goroutine-leak check. Catches connection-
// pool goroutines from *sql.DB that didn't get cleaned up via Close
// because a test forgot to defer it.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
