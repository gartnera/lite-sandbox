package bash_sandboxed

import (
	"os"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// requireOSSandbox skips tests that exercise the real OS sandbox runtime
// (bwrap on Linux / sandbox-exec on macOS). They always compile but only run
// when OS_SANDBOX_TESTS is set, which CI does.
func requireOSSandbox(t *testing.T) {
	t.Helper()
	if os.Getenv("OS_SANDBOX_TESTS") == "" {
		t.Skip("requires OS sandbox runtime; set OS_SANDBOX_TESTS=1 to run (enabled in CI)")
	}
}

// newTestSandbox returns a Sandbox with no extra commands for use in tests.
// By default, git permissions use defaults (local_read=true, local_write=true,
// remote_read=true, remote_write=false).
func newTestSandbox() *Sandbox {
	return NewSandbox()
}

// boolPtr returns a pointer to a bool value.
func boolPtr(b bool) *bool {
	return &b
}

// newTestSandboxWithGitConfig returns a Sandbox configured with the given GitConfig.
func newTestSandboxWithGitConfig(gitCfg *config.GitConfig) *Sandbox {
	s := NewSandbox()
	s.UpdateConfig(&config.Config{Git: gitCfg}, "")
	return s
}

// newTestSandboxWithRuntimesConfig returns a Sandbox configured with the given RuntimesConfig.
func newTestSandboxWithRuntimesConfig(runtimesCfg *config.RuntimesConfig) *Sandbox {
	s := NewSandbox()
	s.UpdateConfig(&config.Config{Runtimes: runtimesCfg}, "")
	return s
}

// newTestSandboxWithOSSandbox returns a Sandbox with the OS sandbox enabled.
// Worker startup is lazy, so this only flips the osSandbox flag (no bwrap is
// spawned until a command is actually executed).
func newTestSandboxWithOSSandbox() *Sandbox {
	s := NewSandbox()
	s.UpdateConfig(&config.Config{OSSandbox: boolPtr(true)}, "")
	return s
}

// newTestSandboxWithLocalBinaryExecution returns a Sandbox with local binary execution enabled.
func newTestSandboxWithLocalBinaryExecution() *Sandbox {
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		LocalBinaryExecution: &config.LocalBinaryExecutionConfig{
			Enabled: boolPtr(true),
		},
	}, "")
	return s
}
