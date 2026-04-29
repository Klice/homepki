package config

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain wraps go test with a goroutine-leak check.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
