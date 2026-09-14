package bash_sandboxed

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// newDenySandbox returns a sandbox in mode with auditing on and the given
// config applied, returning the audit log path.
func newDenySandbox(t *testing.T, mode config.Mode, workDir string, cfg config.Config) (*Sandbox, string) {
	t.Helper()
	s, logPath := newModeSandbox(t, mode, workDir)
	on := true
	cfg.Mode = string(mode)
	cfg.Audit = &on
	s.UpdateConfig(&cfg, workDir)
	return s, logPath
}

// TestDeniedCommands_SelfProtection covers the reason the built-in deny list
// exists: in denylist mode every program may run, so without it `lite-sandbox
// config mode set open` turns enforcement off for the next command.
func TestDeniedCommands_SelfProtection(t *testing.T) {
	workDir := t.TempDir()
	s, logPath := newDenySandbox(t, config.ModeDenylist, workDir, config.Config{})
	paths := []string{workDir}

	err := s.ValidateCommand("lite-sandbox config mode set open", workDir, paths, paths)
	if err == nil {
		t.Fatal("lite-sandbox config must be denied in denylist mode")
	}
	if !strings.Contains(err.Error(), "denied_commands") {
		t.Errorf("error should name the deny list: %v", err)
	}

	// Read-only subcommands are untouched: the entries are subcommand-scoped.
	if err := s.ValidateCommand("lite-sandbox version", workDir, paths, paths); err != nil {
		t.Errorf("lite-sandbox version should still validate: %v", err)
	}

	var found bool
	for _, r := range readAudit(t, logPath) {
		if r.Rule != string(ruleCommandDenylist) {
			continue
		}
		found = true
		if !r.Blocked {
			t.Errorf("deny finding should be blocked in denylist mode: %+v", r)
		}
		if r.Subject != "lite-sandbox" {
			t.Errorf("subject = %q", r.Subject)
		}
		if strings.Join(r.WouldBlockIn, ",") != "denylist,allowlist" {
			t.Errorf("would_block_in = %v", r.WouldBlockIn)
		}
	}
	if !found {
		t.Error("no command_denylist audit record")
	}
}

// TestDeniedCommands_Modes pins the rule to the mode model: enforced in
// denylist and allowlist, recorded but not blocked in open.
func TestDeniedCommands_Modes(t *testing.T) {
	const cmd = "lite-sandbox config mode set open"
	for _, c := range []struct {
		mode    config.Mode
		blocked bool
	}{
		{config.ModeOpen, false},
		{config.ModeDenylist, true},
		{config.ModeAllowlist, true},
	} {
		t.Run(string(c.mode), func(t *testing.T) {
			workDir := t.TempDir()
			s, logPath := newDenySandbox(t, c.mode, workDir, config.Config{})
			err := s.ValidateCommand(cmd, workDir, []string{workDir}, []string{workDir})
			if c.blocked {
				if err == nil || !strings.Contains(err.Error(), "denied_commands") {
					t.Fatalf("want deny error in %s mode, got %v", c.mode, err)
				}
			} else if err != nil {
				t.Fatalf("open mode must not block: %v", err)
			}
			var recorded bool
			for _, r := range readAudit(t, logPath) {
				if r.Rule == string(ruleCommandDenylist) {
					recorded = true
					if r.Blocked != c.blocked {
						t.Errorf("record blocked = %v, want %v", r.Blocked, c.blocked)
					}
				}
			}
			if !recorded {
				t.Errorf("no command_denylist record in %s mode", c.mode)
			}
		})
	}
}

// TestDeniedCommands_OutranksEscapeHatches: extra_commands and
// unsandboxed_commands allow a command and skip validation, which for a bare
// entry also skips AST parsing entirely. The deny list is the one gate they
// must not lift.
func TestDeniedCommands_OutranksEscapeHatches(t *testing.T) {
	workDir := t.TempDir()
	for _, c := range []struct {
		name string
		cfg  config.Config
	}{
		{"extra_commands", config.Config{ExtraCommands: []string{"lite-sandbox"}}},
		{"unsandboxed_commands", config.Config{UnsandboxedCommands: []string{"lite-sandbox"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newDenySandbox(t, config.ModeDenylist, workDir, c.cfg)
			// The raw-bash bypass must be declined, or the command would never
			// reach validation at all.
			if s.isExtraCommandInvocation("lite-sandbox config mode set open") {
				t.Error("a denied command must not take the unparsed raw-bash path")
			}
			err := s.ValidateCommand("lite-sandbox config mode set open", workDir, []string{workDir}, []string{workDir})
			if err == nil || !strings.Contains(err.Error(), "denied_commands") {
				t.Fatalf("deny must outrank %s: %v", c.name, err)
			}
			// A non-denied invocation of the same command still runs.
			if err := s.ValidateCommand("lite-sandbox version", workDir, []string{workDir}, []string{workDir}); err != nil {
				t.Errorf("lite-sandbox version should still validate: %v", err)
			}
		})
	}
}

// TestDeniedCommands_InvocationForms checks the spellings an agent could reach
// for once the plain one is denied.
func TestDeniedCommands_InvocationForms(t *testing.T) {
	workDir := t.TempDir()
	s, _ := newDenySandbox(t, config.ModeDenylist, workDir, config.Config{})
	paths := []string{workDir}

	denied := []struct{ name, cmd string }{
		{"plain", "lite-sandbox config mode set open"},
		{"absolute path", "/usr/local/bin/lite-sandbox config mode set open"},
		{"relative path", "./lite-sandbox config mode set open"},
		{"env wrapper", "env lite-sandbox config mode set open"},
		{"timeout wrapper", "timeout 5 lite-sandbox config mode set open"},
		{"xargs wrapper", "echo open | xargs lite-sandbox config mode set"},
		{"global flag before the subcommand", "lite-sandbox --log-level debug config mode set open"},
		{"inside a pipeline", "echo x | lite-sandbox config mode set open"},
		{"after a redirection", "lite-sandbox config mode set open > out.txt"},
	}
	for _, c := range denied {
		t.Run(c.name, func(t *testing.T) {
			err := s.ValidateCommand(c.cmd, workDir, paths, paths)
			if err == nil || !strings.Contains(err.Error(), "denied_commands") {
				t.Fatalf("%s should be denied: %v", c.cmd, err)
			}
		})
	}
}

// TestDeniedCommands_RuntimeExpansion covers the layer static analysis cannot:
// a command whose name or subcommand is only known after expansion.
func TestDeniedCommands_RuntimeExpansion(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not installed")
	}
	workDir := t.TempDir()
	s, _ := newDenySandbox(t, config.ModeDenylist, workDir, config.Config{DeniedCommands: []string{"perl"}})
	paths := []string{workDir}

	for _, c := range []struct{ name, cmd string }{
		{"direct", `perl -e 'print "ran\n"'`},
		{"dynamic name", `CMD=perl; $CMD -e 'print "ran\n"'`},
		{"via bash -c", `bash -c 'perl -e "print 1"'`},
	} {
		t.Run(c.name, func(t *testing.T) {
			out, err := s.Execute(context.Background(), c.cmd, workDir, paths, paths)
			if err == nil {
				t.Fatalf("denied command ran: out=%q", out)
			}
			if !strings.Contains(err.Error(), "denied_commands") {
				t.Errorf("error should name the deny list: %v", err)
			}
			if strings.Contains(out, "ran") {
				t.Errorf("denied command produced output: %q", out)
			}
		})
	}

	// The same sandbox still runs everything else, denial being per-command.
	if out, err := s.Execute(context.Background(), "echo ok", workDir, paths, paths); err != nil || !strings.Contains(out, "ok") {
		t.Errorf("unrelated command should run: out=%q err=%v", out, err)
	}
}

// TestDeniedCommands_PrefixScope pins how far a subcommand-restricted entry
// reaches: only invocations that actually start with those tokens.
func TestDeniedCommands_PrefixScope(t *testing.T) {
	workDir := t.TempDir()
	s, _ := newDenySandbox(t, config.ModeDenylist, workDir, config.Config{
		DeniedCommands: []string{"git remote"},
	})
	paths := []string{workDir}

	if err := s.ValidateCommand("git remote add origin /tmp/x", workDir, paths, paths); err == nil ||
		!strings.Contains(err.Error(), "denied_commands") {
		t.Errorf("git remote should be denied: %v", err)
	}
	for _, cmd := range []string{"git status", "git log --oneline"} {
		if err := s.ValidateCommand(cmd, workDir, paths, paths); err != nil {
			t.Errorf("%q should not be denied: %v", cmd, err)
		}
	}
	// A bare invocation (which just prints help) is not the denied subcommand.
	if err := s.ValidateCommand("git", workDir, paths, paths); err != nil {
		t.Errorf("bare git should not be denied: %v", err)
	}
}

func TestDeniedCommands_Matching(t *testing.T) {
	s := NewSandbox()
	s.UpdateConfig(&config.Config{DeniedCommands: []string{"curl", "gh  auth  login"}}, t.TempDir())

	cases := []struct {
		name  string
		cmd   string
		args  []string
		want  bool
		entry string
	}{
		{"bare entry, no args", "curl", nil, true, "curl"},
		{"bare entry by path", "/usr/bin/curl", []string{"https://x"}, true, "curl"},
		{"prefix entry matches", "gh", []string{"auth", "login"}, true, "gh auth login"},
		{"prefix entry behind a value-taking flag", "gh", []string{"--repo", "x", "auth", "login"}, true, "gh auth login"},
		{"prefix entry behind a valueless flag", "gh", []string{"--verbose", "auth", "login"}, true, "gh auth login"},
		{"denied tokens appearing later as data", "gh", []string{"pr", "list", "--search", "auth", "login"}, false, ""},
		{"prefix entry, shorter invocation", "gh", []string{"auth"}, false, ""},
		{"prefix entry, different subcommand", "gh", []string{"pr", "list"}, false, ""},
		{"prefix entry, bare command", "gh", nil, false, ""},
		{"unrelated command", "wget", []string{"https://x"}, false, ""},
		{"empty name", "", []string{"auth"}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entry, got := s.deniedCommand(c.cmd, c.args)
			if got != c.want || entry != c.entry {
				t.Errorf("deniedCommand(%q, %v) = (%q, %v), want (%q, %v)", c.cmd, c.args, entry, got, c.entry, c.want)
			}
		})
	}
}

// TestDeniedCommands_LiftedDefault covers the escape hatch: a user who wants
// the agent to run `lite-sandbox config` can drop the built-in entry.
func TestDeniedCommands_LiftedDefault(t *testing.T) {
	workDir := t.TempDir()
	s, _ := newDenySandbox(t, config.ModeDenylist, workDir, config.Config{
		DeniedCommands: []string{"-lite-sandbox config"},
	})
	if err := s.ValidateCommand("lite-sandbox config mode show", workDir, []string{workDir}, []string{workDir}); err != nil {
		t.Errorf("lifted default should allow the command: %v", err)
	}
	// The other built-ins are unaffected.
	if err := s.ValidateCommand("lite-sandbox install claude", workDir, []string{workDir}, []string{workDir}); err == nil {
		t.Error("lifting one entry must not lift the rest")
	}
}
