package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/internal/hook"
)

// isolateConfig points config.Load() at a non-existent file so tests run
// against an empty config (cwd-only boundaries) regardless of the host's real
// lite-sandbox config.
func isolateConfig(t *testing.T) {
	t.Helper()
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "nonexistent.yaml"))
}

func TestEvaluatePathPolicy(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	outside := t.TempDir()

	tests := []struct {
		name      string
		event     *hook.Event
		wantDeny  bool
		wantInMsg string
	}{
		{
			name: "read inside cwd defers",
			event: &hook.Event{
				ToolName:  hook.ToolRead,
				CWD:       cwd,
				ToolInput: &hook.ReadInput{FilePath: filepath.Join(cwd, "a.txt")},
			},
		},
		{
			name: "read outside is denied",
			event: &hook.Event{
				ToolName:  hook.ToolRead,
				CWD:       cwd,
				ToolInput: &hook.ReadInput{FilePath: filepath.Join(outside, "secret.txt")},
			},
			wantDeny:  true,
			wantInMsg: "readable",
		},
		{
			name: "relative read inside cwd defers",
			event: &hook.Event{
				ToolName:  hook.ToolRead,
				CWD:       cwd,
				ToolInput: &hook.ReadInput{FilePath: "nested/a.txt"},
			},
		},
		{
			name: "relative traversal outside is denied",
			event: &hook.Event{
				ToolName:  hook.ToolRead,
				CWD:       cwd,
				ToolInput: &hook.ReadInput{FilePath: "../../etc/passwd"},
			},
			wantDeny:  true,
			wantInMsg: "readable",
		},
		{
			name: "write inside cwd defers",
			event: &hook.Event{
				ToolName:  hook.ToolWrite,
				CWD:       cwd,
				ToolInput: &hook.WriteInput{FilePath: filepath.Join(cwd, "out.txt"), Content: "hi"},
			},
		},
		{
			name: "write outside is denied",
			event: &hook.Event{
				ToolName:  hook.ToolWrite,
				CWD:       cwd,
				ToolInput: &hook.WriteInput{FilePath: filepath.Join(outside, "out.txt")},
			},
			wantDeny:  true,
			wantInMsg: "writable",
		},
		{
			name: "edit outside is denied",
			event: &hook.Event{
				ToolName:  hook.ToolEdit,
				CWD:       cwd,
				ToolInput: &hook.EditInput{FilePath: filepath.Join(outside, "f.go")},
			},
			wantDeny:  true,
			wantInMsg: "writable",
		},
		{
			name: "notebook edit outside is denied",
			event: &hook.Event{
				ToolName:  hook.ToolNotebook,
				CWD:       cwd,
				ToolInput: &hook.NotebookEditInput{NotebookPath: filepath.Join(outside, "n.ipynb")},
			},
			wantDeny:  true,
			wantInMsg: "writable",
		},
		{
			name: "glob without path defers",
			event: &hook.Event{
				ToolName:  hook.ToolGlob,
				CWD:       cwd,
				ToolInput: &hook.GlobInput{Pattern: "**/*.go"},
			},
		},
		{
			name: "grep with outside path is denied",
			event: &hook.Event{
				ToolName:  hook.ToolGrep,
				CWD:       cwd,
				ToolInput: &hook.GrepInput{Pattern: "secret", Path: outside},
			},
			wantDeny:  true,
			wantInMsg: "readable",
		},
		{
			name: "apply_patch inside cwd defers",
			event: &hook.Event{
				ToolName: hook.ToolApplyPatch,
				CWD:      cwd,
				ToolInput: &hook.ApplyPatchInput{
					Command: "*** Begin Patch\n*** Update File: nested/a.txt\n@@\n-old\n+new\n*** End Patch",
				},
			},
		},
		{
			name: "apply_patch adding file outside is denied",
			event: &hook.Event{
				ToolName: hook.ToolApplyPatch,
				CWD:      cwd,
				ToolInput: &hook.ApplyPatchInput{
					Command: "*** Begin Patch\n*** Add File: " + filepath.Join(outside, "evil.txt") + "\n+pwned\n*** End Patch",
				},
			},
			wantDeny:  true,
			wantInMsg: "writable",
		},
		{
			name: "apply_patch mixed in/out is denied",
			event: &hook.Event{
				ToolName: hook.ToolApplyPatch,
				CWD:      cwd,
				ToolInput: &hook.ApplyPatchInput{
					Command: "*** Begin Patch\n*** Update File: ok.txt\n*** Delete File: " + filepath.Join(outside, "gone.txt") + "\n*** End Patch",
				},
			},
			wantDeny:  true,
			wantInMsg: "writable",
		},
		{
			name: "apply_patch with no visible targets defers",
			event: &hook.Event{
				ToolName:  hook.ToolApplyPatch,
				CWD:       cwd,
				ToolInput: &hook.ApplyPatchInput{Command: "not a real patch"},
			},
		},
		{
			name: "apply_patch writing into .git is denied",
			event: &hook.Event{
				ToolName: hook.ToolApplyPatch,
				CWD:      cwd,
				ToolInput: &hook.ApplyPatchInput{
					Command: "*** Begin Patch\n*** Add File: .git/hooks/pre-commit\n+#!/bin/sh\n*** End Patch",
				},
			},
			wantDeny:  true,
			wantInMsg: ".git",
		},
		{
			name: "edit into .git is denied",
			event: &hook.Event{
				ToolName:  hook.ToolEdit,
				CWD:       cwd,
				ToolInput: &hook.EditInput{FilePath: filepath.Join(cwd, ".git", "config")},
			},
			wantDeny:  true,
			wantInMsg: ".git",
		},
		{
			name: "unmodeled tool defers",
			event: &hook.Event{
				ToolName: "WebFetch",
				CWD:      cwd,
				ToolInput: &hook.WebFetchInput{
					URL: "https://example.com",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluatePathPolicy(tt.event)
			if tt.wantDeny {
				if got == nil {
					t.Fatalf("expected deny decision, got nil (defer)")
				}
				if got.HookSpecificOutput.PermissionDecision != hook.DecisionDeny {
					t.Fatalf("expected deny, got %q", got.HookSpecificOutput.PermissionDecision)
				}
				if !strings.Contains(got.HookSpecificOutput.PermissionDecisionReason, tt.wantInMsg) {
					t.Errorf("reason %q does not contain %q", got.HookSpecificOutput.PermissionDecisionReason, tt.wantInMsg)
				}
			} else if got != nil {
				t.Fatalf("expected defer (nil), got deny: %s", got.HookSpecificOutput.PermissionDecisionReason)
			}
		})
	}
}

// TestRunHookDenyOutput verifies the end-to-end stdin→stdout contract: a
// boundary-violating event yields a deny decision document, and an in-bounds
// event yields no output (defer).
func TestRunHookDenyOutput(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	outside := t.TempDir()

	run := func(event map[string]any) string {
		t.Helper()
		payload, err := json.Marshal(event)
		if err != nil {
			t.Fatalf("marshal event: %v", err)
		}
		var out bytes.Buffer
		c := &cobra.Command{}
		c.SetIn(bytes.NewReader(payload))
		c.SetOut(&out)
		c.SetErr(&bytes.Buffer{})
		if err := runHook(c, false); err != nil {
			t.Fatalf("runHook returned error: %v", err)
		}
		return out.String()
	}

	denyOut := run(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Read",
		"cwd":             cwd,
		"tool_input":      map[string]any{"file_path": filepath.Join(outside, "secret.txt")},
	})
	if denyOut == "" {
		t.Fatal("expected deny JSON for out-of-bounds read, got empty output")
	}
	var dec hook.Decision
	if err := json.Unmarshal([]byte(denyOut), &dec); err != nil {
		t.Fatalf("decision is not valid JSON: %v\n%s", err, denyOut)
	}
	if dec.HookSpecificOutput.PermissionDecision != hook.DecisionDeny {
		t.Errorf("expected deny, got %q", dec.HookSpecificOutput.PermissionDecision)
	}

	allowOut := run(map[string]any{
		"hook_event_name": "PreToolUse",
		"tool_name":       "Read",
		"cwd":             cwd,
		"tool_input":      map[string]any{"file_path": filepath.Join(cwd, "in.txt")},
	})
	if allowOut != "" {
		t.Errorf("expected no output (defer) for in-bounds read, got: %s", allowOut)
	}
}

// TestRunHookFailOpen verifies malformed input defers rather than blocking.
func TestRunHookFailOpen(t *testing.T) {
	isolateConfig(t)
	var out bytes.Buffer
	c := &cobra.Command{}
	c.SetIn(strings.NewReader("not json"))
	c.SetOut(&out)
	c.SetErr(&bytes.Buffer{})
	if err := runHook(c, false); err != nil {
		t.Fatalf("runHook should fail-open, got error: %v", err)
	}
	if out.String() != "" {
		t.Errorf("expected no decision on parse failure, got: %s", out.String())
	}
}

func TestDenyBuiltinBash(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()

	event := &hook.Event{
		ToolName:  hook.ToolBash,
		CWD:       cwd,
		ToolInput: &hook.BashInput{Command: "ls -la"},
	}
	got := evaluate(event, false)
	if got == nil {
		t.Fatal("expected Bash to be denied, got nil (defer)")
	}
	if got.HookSpecificOutput.PermissionDecision != hook.DecisionDeny {
		t.Fatalf("expected deny, got %q", got.HookSpecificOutput.PermissionDecision)
	}
	if !strings.Contains(got.HookSpecificOutput.PermissionDecisionReason, "mcp__lite-sandbox__bash") {
		t.Errorf("deny reason should redirect to the MCP tool, got: %s", got.HookSpecificOutput.PermissionDecisionReason)
	}

	// Bash is denied even when tool_input failed to parse (ToolInput nil).
	bare := &hook.Event{ToolName: hook.ToolBash, CWD: cwd}
	if evaluate(bare, false) == nil {
		t.Error("expected Bash to be denied even without parsed tool input")
	}
}

func TestValidateBuiltinBash(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	outside := t.TempDir()

	// The hook validates statically (no execution), and static path validation
	// only flags absolute read paths that exist locally — so the secret must
	// exist on disk to be caught at validation time.
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("top secret"), 0644); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	tests := []struct {
		name      string
		command   string
		wantAllow bool
		wantInMsg string // substring expected in a deny reason
	}{
		{
			name:      "whitelisted read-only command is allowed",
			command:   "ls -la",
			wantAllow: true,
		},
		{
			name:      "pipeline of read-only commands is allowed",
			command:   "cat foo.txt | grep bar | head -n 5",
			wantAllow: true,
		},
		{
			name:      "non-whitelisted command is denied",
			command:   "curl https://example.com",
			wantInMsg: "did not pass sandbox validation",
		},
		{
			name:      "read of an existing file outside the sandbox is denied",
			command:   "cat " + secret,
			wantInMsg: "did not pass sandbox validation",
		},
		{
			name:      "relative traversal outside the sandbox is denied",
			command:   "cat ../../etc/passwd",
			wantInMsg: "did not pass sandbox validation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := &hook.Event{
				ToolName:  hook.ToolBash,
				CWD:       cwd,
				ToolInput: &hook.BashInput{Command: tt.command},
			}
			got := evaluate(event, true)
			if got == nil {
				t.Fatal("expected a decision in validate-bash mode, got nil (defer)")
			}
			if tt.wantAllow {
				if got.HookSpecificOutput.PermissionDecision != hook.DecisionAllow {
					t.Fatalf("expected allow, got %q: %s", got.HookSpecificOutput.PermissionDecision, got.HookSpecificOutput.PermissionDecisionReason)
				}
				return
			}
			if got.HookSpecificOutput.PermissionDecision != hook.DecisionDeny {
				t.Fatalf("expected deny, got %q", got.HookSpecificOutput.PermissionDecision)
			}
			if !strings.Contains(got.HookSpecificOutput.PermissionDecisionReason, tt.wantInMsg) {
				t.Errorf("reason %q does not contain %q", got.HookSpecificOutput.PermissionDecisionReason, tt.wantInMsg)
			}
		})
	}

	// Without a parseable command, defer rather than guess.
	bare := &hook.Event{ToolName: hook.ToolBash, CWD: cwd}
	if got := evaluate(bare, true); got != nil {
		t.Errorf("expected defer (nil) without a command, got: %s", got.HookSpecificOutput.PermissionDecisionReason)
	}
}

func TestConfigurePermissionsToolHook(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")

	// A prior default install left Bash in the deny list.
	prior := `{"permissions":{"allow":["mcp__lite-sandbox__bash"],"deny":["Bash","WebFetch"]}}`
	if err := os.WriteFile(settingsPath, []byte(prior), 0644); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	if err := configurePermissions(tmpDir, true, false); err != nil {
		t.Fatalf("configurePermissions(allowMCP=true, denyBash=false) failed: %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse settings.json: %v", err)
	}
	var perms permissionsConfig
	if err := json.Unmarshal(raw["permissions"], &perms); err != nil {
		t.Fatalf("parse permissions: %v", err)
	}
	for _, d := range perms.Deny {
		if d == "Bash" {
			t.Error("Bash deny should be removed when the tool hook governs Bash")
		}
	}
	if !contains(strings.Join(perms.Deny, ","), "WebFetch") {
		t.Error("unrelated deny entries should be preserved")
	}
	if !contains(strings.Join(perms.Allow, ","), "mcp__lite-sandbox__bash") {
		t.Error("mcp tool should remain allowed")
	}
}

func TestConfigurePreToolUseHook(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")
	command := "/usr/local/bin/lite-sandbox hook"

	if err := configurePreToolUseHook(tmpDir, command, hookToolMatcher); err != nil {
		t.Fatalf("configurePreToolUseHook failed: %v", err)
	}

	readPre := func() []any {
		t.Helper()
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatalf("read settings.json: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("parse settings.json: %v", err)
		}
		return asSlice(asMap(raw["hooks"])["PreToolUse"])
	}

	pre := readPre()
	if len(pre) != 1 {
		t.Fatalf("expected 1 PreToolUse group, got %d", len(pre))
	}
	group := asMap(pre[0])
	if asString(group["matcher"]) != hookToolMatcher {
		t.Errorf("expected matcher %q, got %q", hookToolMatcher, asString(group["matcher"]))
	}
	cmds := asSlice(group["hooks"])
	if len(cmds) != 1 || asString(asMap(cmds[0])["command"]) != command {
		t.Fatalf("expected single command %q, got %v", command, cmds)
	}

	// Idempotent: re-running with same command/matcher does not duplicate.
	if err := configurePreToolUseHook(tmpDir, command, hookToolMatcher); err != nil {
		t.Fatalf("second configurePreToolUseHook failed: %v", err)
	}
	pre = readPre()
	if len(pre) != 1 {
		t.Fatalf("expected 1 group after re-run, got %d", len(pre))
	}
	if cmds := asSlice(asMap(pre[0])["hooks"]); len(cmds) != 1 {
		t.Fatalf("expected command not duplicated, got %d", len(cmds))
	}
}

// TestReconcilePreToolUseHook verifies that switching install modes replaces the
// lite-sandbox hook entry rather than leaving a stale, conflicting one behind,
// and that unrelated hooks survive.
func TestReconcilePreToolUseHook(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")
	binPath := "/usr/local/bin/lite-sandbox"

	// An unrelated hook from another tool must always survive.
	existing := `{"hooks":{"PreToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"/other/tool guard"}]}]}}`
	if err := os.WriteFile(settingsPath, []byte(existing), 0644); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	// lite-sandbox commands registered across the modes.
	liteCmds := func() []string {
		t.Helper()
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatalf("read settings.json: %v", err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatalf("parse settings.json: %v", err)
		}
		var got []string
		otherSurvived := false
		for _, g := range asSlice(asMap(raw["hooks"])["PreToolUse"]) {
			for _, c := range asSlice(asMap(g)["hooks"]) {
				cmd := asString(asMap(c)["command"])
				if strings.HasPrefix(cmd, binPath) {
					got = append(got, cmd)
				}
				if cmd == "/other/tool guard" {
					otherSurvived = true
				}
			}
		}
		if !otherSurvived {
			t.Error("unrelated PreToolUse hook from another tool was lost")
		}
		return got
	}

	// Install --with-tool-hook.
	if err := reconcilePreToolUseHook(tmpDir, binPath, binPath+" hook", hookToolMatcher); err != nil {
		t.Fatalf("reconcile (tool hook) failed: %v", err)
	}
	if got := liteCmds(); len(got) != 1 || got[0] != binPath+" hook" {
		t.Fatalf("expected exactly the tool hook command, got %v", got)
	}

	// Switch to --bash-ast-hook-mode: the old command must be replaced, not added to.
	if err := reconcilePreToolUseHook(tmpDir, binPath, binPath+" hook --validate-bash", bashValidateMatcher); err != nil {
		t.Fatalf("reconcile (bash hook) failed: %v", err)
	}
	if got := liteCmds(); len(got) != 1 || got[0] != binPath+" hook --validate-bash" {
		t.Fatalf("expected exactly the validate-bash command after switch, got %v", got)
	}

	// Switch to default (no hook): the lite-sandbox entry must be removed.
	if err := reconcilePreToolUseHook(tmpDir, binPath, "", hookToolMatcher); err != nil {
		t.Fatalf("reconcile (no hook) failed: %v", err)
	}
	if got := liteCmds(); len(got) != 0 {
		t.Fatalf("expected no lite-sandbox hook commands after switching to default, got %v", got)
	}
}

func TestConfigurePreToolUseHookPreservesExisting(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")

	// Existing settings: a PostToolUse hook, an unrelated PreToolUse matcher,
	// and a top-level key — all must survive.
	existing := `{
  "someOther": true,
  "hooks": {
    "PostToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo post"}]}],
    "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo pre"}]}]
  }
}`
	if err := os.WriteFile(settingsPath, []byte(existing), 0644); err != nil {
		t.Fatalf("write settings.json: %v", err)
	}

	if err := configurePreToolUseHook(tmpDir, "/bin/ls hook", hookToolMatcher); err != nil {
		t.Fatalf("configurePreToolUseHook failed: %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("read settings.json: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("parse settings.json: %v", err)
	}
	if _, ok := raw["someOther"]; !ok {
		t.Error("top-level key 'someOther' was lost")
	}
	hooks := asMap(raw["hooks"])
	if len(asSlice(hooks["PostToolUse"])) != 1 {
		t.Error("PostToolUse hook was lost")
	}
	pre := asSlice(hooks["PreToolUse"])
	if len(pre) != 2 {
		t.Fatalf("expected existing + new PreToolUse group (2), got %d", len(pre))
	}
}
