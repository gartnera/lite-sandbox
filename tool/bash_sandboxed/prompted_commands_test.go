package bash_sandboxed

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
)

const promptErrText = "needs the user's approval"

// newPromptSandbox returns a sandbox in mode with the given commands entries.
func newPromptSandbox(t *testing.T, mode config.Mode, workDir string, entries ...config.CommandEntry) *Sandbox {
	t.Helper()
	s, _ := newDenySandbox(t, mode, workDir, config.Config{Commands: entries})
	return s
}

func promptEntry(cmd string) config.CommandEntry {
	return config.CommandEntry{Command: cmd, Prompt: true}
}

func promptedAllow(cmd string) config.CommandEntry {
	yes := true
	return config.CommandEntry{Command: cmd, Allow: &yes, Prompt: true}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// TestPrompt_WhitelistedCommand: a prompt entry for a whitelisted command
// refuses it in an unapproved call and runs it, validated, in an approved one.
func TestPrompt_WhitelistedCommand(t *testing.T) {
	workDir := t.TempDir()
	s := newPromptSandbox(t, config.ModeAllowlist, workDir, promptEntry("rm"))
	paths := []string{workDir}
	f := filepath.Join(workDir, "f")
	touch(t, f)

	for _, cmd := range []string{"rm f", "echo a && rm f", "C=rm; $C f", "echo $(rm f)"} {
		if _, err := s.Execute(context.Background(), cmd, workDir, paths, paths); err == nil || !strings.Contains(err.Error(), promptErrText) {
			t.Errorf("%q unapproved: err = %v, want the approval error", cmd, err)
		}
		if !exists(f) {
			t.Fatalf("%q unapproved removed the file", cmd)
		}
	}
	// Other commands are untouched.
	if out, err := s.Execute(context.Background(), "echo ok", workDir, paths, paths); err != nil || !strings.Contains(out, "ok") {
		t.Errorf("echo: out=%q err=%v", out, err)
	}

	approved := WithApproval(context.Background())
	if _, err := s.Execute(approved, "C=rm; $C f", workDir, paths, paths); err != nil {
		t.Fatalf("approved: %v", err)
	}
	if exists(f) {
		t.Error("approved rm did not run")
	}
	// Approval does not lift the command's own validation.
	if _, err := s.Execute(approved, "rm /etc/hostname", workDir, paths, paths); err == nil || strings.Contains(err.Error(), promptErrText) {
		t.Errorf("approved rm outside the boundary: err = %v, want a path boundary error", err)
	}
}

// TestPrompt_ApprovalWhitelists: an approved prompt-only invocation of a
// command off the whitelist runs; unapproved it is refused for the prompt.
func TestPrompt_ApprovalWhitelists(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not installed")
	}
	workDir := t.TempDir()
	s := newPromptSandbox(t, config.ModeAllowlist, workDir, promptEntry("perl"))
	paths := []string{workDir}
	const cmd = `perl -e 'print "ran\n"'`
	if _, err := s.Execute(context.Background(), cmd, workDir, paths, paths); err == nil || !strings.Contains(err.Error(), promptErrText) {
		t.Errorf("unapproved: err = %v", err)
	}
	if out, err := s.Execute(WithApproval(context.Background()), cmd, workDir, paths, paths); err != nil || !strings.Contains(out, "ran") {
		t.Errorf("approved: out=%q err=%v", out, err)
	}
}

// TestPrompt_RawPath: a bare allow runs its command string via real bash, so
// the prompt is checked on the whole string before it is handed over.
func TestPrompt_RawPath(t *testing.T) {
	if _, err := exec.LookPath("perl"); err != nil {
		t.Skip("perl not installed")
	}
	yes := true
	workDir := t.TempDir()
	s := newPromptSandbox(t, config.ModeAllowlist, workDir,
		promptedAllow("perl"),
		config.CommandEntry{Command: "date", Allow: &yes},
		promptEntry("rm"))
	paths := []string{workDir}
	f := filepath.Join(workDir, "f")
	touch(t, f)

	for _, cmd := range []string{`perl -e 'print "ran\n"'`, "date; rm f"} {
		if out, err := s.Execute(context.Background(), cmd, workDir, paths, paths); err == nil || !strings.Contains(err.Error(), promptErrText) {
			t.Errorf("%q unapproved: out=%q err=%v", cmd, out, err)
		}
		if err := s.ValidateCommand(cmd, workDir, paths, paths); err == nil {
			t.Errorf("ValidateCommand(%q) unapproved should fail", cmd)
		}
	}
	if !exists(f) {
		t.Fatal("unapproved raw command removed the file")
	}
	approved := WithApproval(context.Background())
	if out, err := s.Execute(approved, `perl -e 'print "ran\n"'`, workDir, paths, paths); err != nil || !strings.Contains(out, "ran") {
		t.Errorf("approved: out=%q err=%v", out, err)
	}
	if err := s.ValidateCommandContext(approved, "date; rm f", workDir, paths, paths); err != nil {
		t.Errorf("ValidateCommandContext approved: %v", err)
	}
}

// TestPrompt_Wrapped: a wrapper spawns its command itself, out of the
// approval's reach, so a prompted command under one is refused either way.
func TestPrompt_Wrapped(t *testing.T) {
	workDir := t.TempDir()
	s := newPromptSandbox(t, config.ModeAllowlist, workDir, promptEntry("rm"))
	paths := []string{workDir}
	touch(t, filepath.Join(workDir, "f"))
	for _, cmd := range []string{"timeout 5 rm f", "echo f | xargs rm", "find . -name f -exec rm {} ;"} {
		_, err := s.Execute(WithApproval(context.Background()), cmd, workDir, paths, paths)
		if err == nil || !strings.Contains(err.Error(), "run it directly") {
			t.Errorf("%q: err = %v, want the wrapped-prompt error", cmd, err)
		}
	}
}

// TestPrompt_ScriptContents: the approval covers the command line, not the
// commands of a script file it runs.
func TestPrompt_ScriptContents(t *testing.T) {
	workDir := t.TempDir()
	s := newPromptSandbox(t, config.ModeAllowlist, workDir, promptEntry("rm"))
	paths := []string{workDir}
	f := filepath.Join(workDir, "f")
	touch(t, f)
	if err := os.WriteFile(filepath.Join(workDir, "s.sh"), []byte("rm f\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := s.Execute(WithApproval(context.Background()), "bash s.sh", workDir, paths, paths)
	if err == nil || !strings.Contains(err.Error(), promptErrText) {
		t.Errorf("err = %v, want the approval error from inside the script", err)
	}
	if !exists(f) {
		t.Error("the script's rm ran on the command line's approval")
	}
	// A bash -c string is part of the command line the user approved.
	if _, err := s.Execute(WithApproval(context.Background()), "bash -c 'rm f'", workDir, paths, paths); err != nil {
		t.Errorf("bash -c approved: %v", err)
	}
}

// TestPrompt_Modes: prompts are enforced where the deny list is — denylist
// and allowlist — and only audited in open mode.
func TestPrompt_Modes(t *testing.T) {
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
			s, logPath := newDenySandbox(t, c.mode, workDir, config.Config{Commands: []config.CommandEntry{promptEntry("rm")}})
			paths := []string{workDir}
			touch(t, filepath.Join(workDir, "f"))
			_, err := s.Execute(context.Background(), "rm f", workDir, paths, paths)
			if (err != nil) != c.blocked {
				t.Errorf("err = %v, blocked want %v", err, c.blocked)
			}
			if got := s.PromptedCommands("rm f"); (len(got) > 0) != c.blocked {
				t.Errorf("PromptedCommands = %v", got)
			}
			var found bool
			for _, r := range readAudit(t, logPath) {
				if r.Rule == string(ruleCommandPrompt) {
					found = true
					if r.Blocked != c.blocked {
						t.Errorf("audit blocked = %v", r.Blocked)
					}
				}
			}
			if !found {
				t.Error("no command_prompt audit record")
			}
		})
	}
}

func TestPromptedCommands(t *testing.T) {
	workDir := t.TempDir()
	s := newPromptSandbox(t, config.ModeAllowlist, workDir, promptEntry("rm"), promptedAllow("git push"))
	for _, c := range []struct {
		cmd  string
		want []string
	}{
		{"ls", nil},
		{"echo a && rm f", []string{"rm"}},
		{"/bin/rm f; rm g", []string{"rm"}},
		{"git status", nil},
		{"git push origin main | cat; rm x", []string{"git push", "rm"}},
		{"$C f", nil},
		{"rm (", nil},
	} {
		if got := s.PromptedCommands(c.cmd); !slices.Equal(got, c.want) {
			t.Errorf("PromptedCommands(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
}

// TestPrompt_Background: the approval reaches a background command through
// ExecuteBackgroundContext.
func TestPrompt_Background(t *testing.T) {
	workDir := t.TempDir()
	s := newPromptSandbox(t, config.ModeAllowlist, workDir, promptEntry("rm"))
	paths := []string{workDir}
	f := filepath.Join(workDir, "f")
	touch(t, f)
	if _, err := s.ExecuteBackground("rm f", workDir, paths, paths); err == nil || !strings.Contains(err.Error(), promptErrText) {
		t.Errorf("unapproved: err = %v", err)
	}
	proc, err := s.ExecuteBackgroundContext(WithApproval(context.Background()), "C=rm; $C f", workDir, paths, paths)
	if err != nil {
		t.Fatal(err)
	}
	if st := waitForStatus(t, proc, 10*time.Second, "completed", "failed"); st != "completed" {
		t.Fatalf("status = %s: %s", st, readOutput(t, proc))
	}
	if exists(f) {
		t.Error("approved background rm did not run")
	}
}
