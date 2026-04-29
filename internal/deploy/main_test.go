package deploy

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain wraps go test with a goroutine-leak check. Run shells out via
// exec.CommandContext and the post-command timeout path uses goroutines
// internally; a leak here would point at a missed cancel or a stranded
// child process.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
