package os_sandbox

import (
	"runtime"
	"testing"
)

// requireLinux skips a test that is only meaningful on Linux (e.g. process-group
// reaping semantics). The test still compiles on every platform.
func requireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("linux-only test")
	}
}

// requireDarwin skips a test that is only meaningful on macOS. The test still
// compiles on every platform.
func requireDarwin(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-only test")
	}
}
