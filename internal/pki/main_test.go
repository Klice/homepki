package pki

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain wraps go test with a goroutine-leak check. PKI ops don't
// spawn goroutines themselves; this catches future regressions if any
// async signing path is added.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
