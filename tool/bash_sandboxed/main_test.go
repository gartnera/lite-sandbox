package bash_sandboxed

import (
	"os"
	"testing"
)

// TestMain starts compiling the shared monty runtime (see sharedMonty) in the
// background, so the one-off compile overlaps the tests that never run Python
// instead of stalling the first one that does.
func TestMain(m *testing.M) {
	go sharedMontyRunner()
	os.Exit(m.Run())
}
