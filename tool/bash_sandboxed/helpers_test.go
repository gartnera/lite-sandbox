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
	s.updateConfig(&config.Config{Git: gitCfg}, "")
	return s
}

// newTestSandboxWithOSSandbox returns a Sandbox with the OS sandbox enabled.
// Worker startup is lazy, so this only flips the os_sandbox config toggle (no bwrap is
// spawned until a command is actually executed).
func newTestSandboxWithOSSandbox() *Sandbox {
	s := NewSandbox()
	s.updateConfig(&config.Config{OSSandbox: boolPtr(true)}, "")
	return s
}

// newTestSandboxWithLocalBinaryExecution returns a Sandbox with local binary execution enabled.
func newTestSandboxWithLocalBinaryExecution() *Sandbox {
	s := NewSandbox()
	s.updateConfig(&config.Config{
		LocalBinaryExecution: &config.LocalBinaryExecutionConfig{
			Enabled: boolPtr(true),
		},
	}, "")
	return s
}

// updateConfig hands cfg to UpdateConfig the way production does: merged into
// its one paths and commands list first (config.Config.Effective), so a test
// may write a config with profiles or deprecated keys and the sandbox sees what
// it would see from config.LoadForDirectory.
func (s *Sandbox) updateConfig(cfg *config.Config, workDir string) {
	s.UpdateConfig(cfg.Effective(), workDir)
}

// newTestSandboxWithProfiles returns a Sandbox with the named profiles enabled.
func newTestSandboxWithProfiles(names ...string) *Sandbox {
	cfg := &config.Config{}
	for _, n := range names {
		cfg.Profiles = append(cfg.Profiles, config.ProfileEntry{Name: n})
	}
	s := NewSandbox()
	s.updateConfig(cfg, "")
	return s
}

// newTestSandboxWithConfig returns a Sandbox configured with cfg (merged the
// way production merges it; see updateConfig).
func newTestSandboxWithConfig(cfg *config.Config) *Sandbox {
	s := NewSandbox()
	s.updateConfig(cfg, "")
	return s
}
