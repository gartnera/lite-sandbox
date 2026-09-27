package bash_sandboxed

import (
	"context"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// TestProfiles_WhitelistKeepsHooks: a profile's commands are whitelisted, not
// allowed: they still run the profile's validators, and the subcommands those
// refuse are opened by a commands entry for exactly that text.
func TestProfiles_WhitelistKeepsHooks(t *testing.T) {
	dir := t.TempDir()
	paths := []string{dir}
	validate := func(s *Sandbox, cmd string) error {
		return s.ValidateCommand(cmd, dir, paths, paths)
	}

	off := newTestSandbox()
	if err := validate(off, "cargo build"); err == nil || !strings.Contains(err.Error(), "profiles enable rust") {
		t.Errorf("cargo without the rust profile should name the profile: %v", err)
	}

	on := newTestSandboxWithProfiles("rust")
	if err := validate(on, "cargo build"); err != nil {
		t.Errorf("cargo build with the rust profile: %v", err)
	}
	if err := validate(on, "cargo publish"); err == nil || !strings.Contains(err.Error(), `commands allow "cargo publish"`) {
		t.Errorf("cargo publish should be refused with the commands hint: %v", err)
	}

	yes := true
	publish := newTestSandboxWithConfig(&config.Config{
		Profiles: []config.ProfileEntry{{Name: "rust"}},
		Commands: []config.CommandEntry{{Command: "cargo publish", Allow: &yes}},
	})
	if err := validate(publish, "cargo publish --dry-run"); err != nil {
		t.Errorf("cargo publish with its commands entry: %v", err)
	}
	if err := validate(publish, "echo | xargs cargo publish"); err != nil {
		t.Errorf("wrapped cargo publish with its commands entry: %v", err)
	}
	if err := validate(publish, "cargo login"); err == nil {
		t.Error("the cargo publish allow must not open the rest of cargo's refusals")
	}
}

// TestProfiles_RestrictedAllowKeepsRuntimeValidation: a restricted allow
// admits only the invocations it names at the runtime layer as well, so a
// dynamically named command outside it is still validated there.
func TestProfiles_RestrictedAllowKeepsRuntimeValidation(t *testing.T) {
	yes := true
	s := newTestSandboxWithConfig(&config.Config{
		Profiles: []config.ProfileEntry{{Name: "rust"}},
		Commands: []config.CommandEntry{{Command: "cargo publish", Allow: &yes}},
	})
	dir := t.TempDir()
	// cargo login with no stdin: refused by cargo's validator, and if that ever
	// regressed it would fail fast and offline rather than reach a registry.
	_, err := s.Execute(context.Background(), "C=cargo; $C login </dev/null", dir, []string{dir}, []string{dir})
	if err == nil || !strings.Contains(err.Error(), `cargo subcommand "login" is not allowed`) {
		t.Fatalf("dynamically named cargo login should be refused by cargo's validator at runtime: %v", err)
	}
}

// TestProfiles_MontyPythonOffHoldsInDenylist: turning the default-on
// montypython profile off refuses python in denylist mode too, where the
// whitelist itself is advisory.
func TestProfiles_MontyPythonOffHoldsInDenylist(t *testing.T) {
	no := false
	s := newTestSandboxWithConfig(&config.Config{
		Mode:     string(config.ModeDenylist),
		Profiles: []config.ProfileEntry{{Name: "montypython", Enabled: &no}},
	})
	dir := t.TempDir()
	if err := s.ValidateCommand(`python3 -c "print(1)"`, dir, []string{dir}, []string{dir}); err == nil {
		t.Error("python3 should be refused with the montypython profile off")
	}
	if err := newTestSandbox().ValidateCommand(`python3 -c "print(1)"`, dir, []string{dir}, []string{dir}); err != nil {
		t.Errorf("python3 is on by default: %v", err)
	}
}

// TestProfiles_EntriesMeanWhatTheyMeanInConfig: a profile's entries carry the
// config's fields. A bare allow whitelists (validated), and no_sandbox on it
// routes the command to the host; an allow with arguments is the config's
// restricted allow.
func TestProfiles_EntriesMeanWhatTheyMeanInConfig(t *testing.T) {
	yes := true
	s := NewSandbox()
	// The shape Config.Effective hands the sandbox for a profile "tools".
	s.UpdateConfig(&config.Config{Commands: []config.CommandEntry{
		{Command: "cargo", Allow: &yes, Profile: "tools", NoSandbox: true},
		{Command: "pnpx prettier", Allow: &yes, Profile: "tools"},
	}}, "")
	dir := t.TempDir()
	paths := []string{dir}
	if err := s.ValidateCommand("cargo build", dir, paths, paths); err != nil {
		t.Errorf("whitelisted cargo: %v", err)
	}
	if err := s.ValidateCommand("cargo login", dir, paths, paths); err == nil {
		t.Error("a whitelisting entry must keep cargo's validator")
	}
	if !s.execIsUnsandboxed(context.Background(), []string{"cargo", "build"}) {
		t.Error("no_sandbox on a profile's entry should route the command to the host")
	}
	if s.isExtraCommandInvocation("cargo build") {
		t.Error("a whitelisting entry must never take the raw-bash path")
	}
	if err := s.ValidateCommand("pnpx prettier --check .", dir, paths, paths); err != nil {
		t.Errorf("restricted allow from a profile: %v", err)
	}
	if err := s.ValidateCommand("pnpx cowsay", dir, paths, paths); err == nil {
		t.Error("the restricted allow must admit only the invocations it names")
	}
}
