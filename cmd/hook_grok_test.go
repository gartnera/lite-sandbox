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

// runGrokHook feeds runHook a PreToolUse event shaped the way Grok Build sends
// it (camelCase keys plus the snake_case aliases) and returns the decision, or
// nil when the hook deferred.
func runGrokHook(t *testing.T, cwd, tool string, input map[string]any, validateBash bool) *hook.Decision {
	t.Helper()
	return runGrokHookRaw(t, cwd, tool, input, false, validateBash)
}

// runGrokHookRaw is runGrokHook with any tool_input value and Grok's
// toolInputTruncated flag.
func runGrokHookRaw(t *testing.T, cwd, tool string, input any, truncated, validateBash bool) *hook.Decision {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"hookEventName":      "pre_tool_use",
		"hook_event_name":    "PreToolUse",
		"sessionId":          "s-1",
		"cwd":                cwd,
		"workspaceRoot":      cwd,
		"permissionMode":     "default",
		"toolName":           tool,
		"tool_name":          tool,
		"toolUseId":          "call-1",
		"toolInput":          input,
		"tool_input":         input,
		"toolInputTruncated": truncated,
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &cobra.Command{}
	c.SetIn(bytes.NewReader(payload))
	c.SetOut(&out)
	c.SetErr(&bytes.Buffer{})
	if err := runHook(c, validateBash); err != nil {
		t.Fatalf("runHook: %v", err)
	}
	if out.Len() == 0 {
		return nil
	}
	var d hook.Decision
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatalf("decision is not JSON: %v\n%s", err, out.String())
	}
	return &d
}

func TestGrokHookFileTools(t *testing.T) {
	isolateConfig(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	cwd := t.TempDir()
	outside := t.TempDir()

	tests := []struct {
		name     string
		tool     string
		input    map[string]any
		wantDeny bool
	}{
		{"read_file inside", hook.GrokToolReadFile, map[string]any{"target_file": "src/main.rs"}, false},
		{"read_file outside", hook.GrokToolReadFile, map[string]any{"target_file": filepath.Join(outside, "secret")}, true},
		{"read_file home via tilde", hook.GrokToolReadFile, map[string]any{"target_file": "~/bin/launch.sh"}, true},
		{"read_file quoted outside", hook.GrokToolReadFile, map[string]any{"target_file": ` "` + filepath.Join(outside, "secret") + `" `}, true},
		{"read_file traversal", hook.GrokToolReadFile, map[string]any{"target_file": "../../etc/passwd"}, true},
		{"grep workspace default", hook.GrokToolGrep, map[string]any{"pattern": "TODO"}, false},
		{"grep outside", hook.GrokToolGrep, map[string]any{"pattern": "TODO", "path": home}, true},
		{"list_dir outside", hook.GrokToolListDir, map[string]any{"target_directory": outside}, true},
		{"search_replace inside", hook.GrokToolSearchReplace, map[string]any{"file_path": "a.go", "old_string": "a", "new_string": "b"}, false},
		{"search_replace outside", hook.GrokToolSearchReplace, map[string]any{"file_path": filepath.Join(outside, "a.go"), "old_string": "a", "new_string": "b"}, true},
		{"search_replace into .git", hook.GrokToolSearchReplace, map[string]any{"file_path": ".git/hooks/pre-commit", "old_string": "", "new_string": "x"}, true},
		{"write outside", hook.GrokToolWrite, map[string]any{"file_path": filepath.Join(outside, "x"), "content": "x"}, true},
		{"image_edit outside", hook.GrokToolImageEdit, map[string]any{"prompt": "x", "image": []string{"[Image #1]", filepath.Join(outside, "a.png")}}, true},
		{"image_edit attachment only", hook.GrokToolImageEdit, map[string]any{"prompt": "x", "image": []string{"[Image #1]"}}, false},
		{"reference_to_video outside frame", hook.GrokToolReferenceToVideo, map[string]any{"prompt": "x", "last_frame": filepath.Join(outside, "a.png")}, true},
		{"second spelling outside", hook.GrokToolRead, map[string]any{"target_file": "src/ok.go", "filePath": filepath.Join(outside, "secret")}, true},
		{"write second spelling outside", hook.GrokToolWrite, map[string]any{"filePath": "ok.txt", "file_path": filepath.Join(outside, "x"), "content": "x"}, true},
		{"case-variant key does not hide the real one", hook.GrokToolSearchReplace, map[string]any{"file_path": filepath.Join(outside, "x"), "FILE_PATH": "a.go", "old_string": "a", "new_string": "b"}, true},
		{"apply_patch outside", hook.ToolApplyPatch, map[string]any{"patch": "*** Begin Patch\n*** Add File: " + filepath.Join(outside, "x") + "\n+x\n*** End Patch\n"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runGrokHook(t, cwd, tt.tool, tt.input, false)
			if !tt.wantDeny {
				if got != nil {
					t.Errorf("expected defer, got %q: %s", got.HookSpecificOutput.PermissionDecision, got.HookSpecificOutput.PermissionDecisionReason)
				}
				return
			}
			if got == nil || got.HookSpecificOutput.PermissionDecision != hook.DecisionDeny {
				t.Fatalf("expected deny, got %+v", got)
			}
		})
	}
}

func TestGrokHookShellRedirect(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()

	for _, tool := range []string{hook.GrokToolRunTerminalCommand, hook.GrokToolMonitor, hook.GrokToolBash} {
		// timeout as a string is what a model may send; it must not stop the
		// hook from seeing the call.
		got := runGrokHook(t, cwd, tool, map[string]any{"command": "ls", "timeout": "120000", "description": "list"}, false)
		if got == nil || got.HookSpecificOutput.PermissionDecision != hook.DecisionDeny {
			t.Fatalf("%s: expected deny, got %+v", tool, got)
		}
		reason := got.HookSpecificOutput.PermissionDecisionReason
		if !strings.Contains(reason, "lite-sandbox__bash") || !strings.Contains(reason, "use_tool") {
			t.Errorf("%s: deny reason should point at use_tool + lite-sandbox__bash, got: %s", tool, reason)
		}
		if strings.Contains(reason, "mcp__lite-sandbox__bash") {
			t.Errorf("%s: deny reason uses Claude Code's tool name: %s", tool, reason)
		}
		if n := len([]rune(reason)); n > grokMaxReasonChars {
			t.Errorf("%s: deny reason is %d characters; Grok clips it at %d: %s", tool, n, grokMaxReasonChars, reason)
		}
	}
}

// grokMaxReasonChars is where Grok clips a hook's deny reason
// (MAX_REASON_CHARS in xai-grok-hooks).
const grokMaxReasonChars = 256

// TestGrokHookCompactReasons checks the path-boundary denial puts its verdict
// inside the part of the reason Grok keeps.
func TestGrokHookCompactReasons(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	// Long enough that a path-first message would push the fix past the clip.
	outside := filepath.Join(t.TempDir(), strings.Repeat("deep-directory/", 16), "secret.txt")

	for _, tc := range []struct {
		tool  string
		input map[string]any
		want  string
	}{
		{hook.GrokToolReadFile, map[string]any{"target_file": outside}, "outside the sandbox's readable paths"},
		{hook.GrokToolWrite, map[string]any{"file_path": outside, "content": "x"}, "outside the sandbox's writable paths"},
		{hook.GrokToolSearchReplace, map[string]any{"file_path": ".git/config", "old_string": "a", "new_string": "b"}, "inside a .git directory"},
	} {
		got := runGrokHook(t, cwd, tc.tool, tc.input, false)
		if got == nil {
			t.Fatalf("%s: expected deny", tc.tool)
		}
		kept := []rune(got.HookSpecificOutput.PermissionDecisionReason)
		if len(kept) > grokMaxReasonChars {
			kept = kept[:grokMaxReasonChars]
		}
		if !strings.Contains(string(kept), tc.want) || (tc.tool != hook.GrokToolSearchReplace && !strings.Contains(string(kept), "config paths allow")) {
			t.Errorf("%s: the first %d characters of the reason lack %q: %s", tc.tool, grokMaxReasonChars, tc.want, got.HookSpecificOutput.PermissionDecisionReason)
		}
	}
}

func TestGrokHookValidateBash(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	if got := runGrokHook(t, cwd, hook.GrokToolRunTerminalCommand, map[string]any{"command": "ls -la", "timeout": "5"}, true); got == nil || got.HookSpecificOutput.PermissionDecision != hook.DecisionAllow {
		t.Errorf("whitelisted command: expected allow, got %+v", got)
	}
	if got := runGrokHook(t, cwd, hook.GrokToolRunTerminalCommand, map[string]any{"command": "cat " + secret}, true); got == nil || got.HookSpecificOutput.PermissionDecision != hook.DecisionDeny {
		t.Errorf("out-of-bounds read: expected deny, got %+v", got)
	}
	if got := runGrokHook(t, cwd, hook.GrokToolMonitor, map[string]any{"command": "curl https://example.com", "persistent": "true"}, true); got == nil || got.HookSpecificOutput.PermissionDecision != hook.DecisionDeny {
		t.Errorf("monitor with a non-whitelisted command: expected deny, got %+v", got)
	}
}

func TestGrokHookMCPTools(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()

	for _, tool := range []string{"lite-sandbox__bash", "lite-sandbox__bash_output", "lite-sandbox__kill_shell", "lite-sandbox__list_shells"} {
		if got := runGrokHook(t, cwd, tool, map[string]any{"command": "ls"}, false); got == nil || got.HookSpecificOutput.PermissionDecision != hook.DecisionAllow {
			t.Errorf("%s: expected allow, got %+v", tool, got)
		}
	}
	if got := runGrokHook(t, cwd, "other__bash", map[string]any{"command": "ls"}, false); got != nil {
		t.Errorf("another server's tool: expected defer, got %+v", got)
	}
}

// TestGrokHookTruncatedInput: Grok replaces a tool input over 128 KiB with a
// clipped JSON string, which hides the path (or command) from the hook. The
// hook must deny rather than defer, except in open mode.
func TestGrokHookTruncatedInput(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	clipped := `{"content":"` + strings.Repeat("x", 200) + `... [truncated]`

	for _, tc := range []struct {
		tool         string
		validateBash bool
	}{
		{hook.GrokToolWrite, false},
		{hook.GrokToolSearchReplace, false},
		{hook.GrokToolReadFile, false},
		{hook.GrokToolRunTerminalCommand, true}, // --bash-ast-hook-mode
	} {
		got := runGrokHookRaw(t, cwd, tc.tool, clipped, true, tc.validateBash)
		if got == nil || got.HookSpecificOutput.PermissionDecision != hook.DecisionDeny {
			t.Errorf("%s: expected deny for a truncated input, got %+v", tc.tool, got)
			continue
		}
		if r := got.HookSpecificOutput.PermissionDecisionReason; !strings.Contains(r, "128 KiB") || len([]rune(r)) > grokMaxReasonChars {
			t.Errorf("%s: unexpected reason: %s", tc.tool, r)
		}
	}

	// Not governed: nothing to protect, so no fail-closed deny.
	if got := runGrokHookRaw(t, cwd, "todo_write", clipped, true, false); got != nil {
		t.Errorf("todo_write: expected defer, got %+v", got)
	}

	// Open mode enforces nothing, so a truncated input defers too.
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: open\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITE_SANDBOX_CONFIG", cfgPath)
	if got := runGrokHookRaw(t, cwd, hook.GrokToolWrite, clipped, true, false); got != nil {
		t.Errorf("open mode: expected defer, got %+v", got)
	}
}

// TestGrokHookUndecodableInput: a governed call whose arguments do not decode
// (a path that is not a string) is denied, since Grok may still run it.
func TestGrokHookUndecodableInput(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	for _, tc := range []struct {
		tool  string
		input map[string]any
	}{
		{hook.GrokToolReadFile, map[string]any{"target_file": []string{"/etc/passwd"}}},
		{hook.GrokToolImageEdit, map[string]any{"prompt": "x", "image": []any{map[string]any{"path": "/etc/passwd"}}}},
	} {
		got := runGrokHook(t, cwd, tc.tool, tc.input, false)
		if got == nil || got.HookSpecificOutput.PermissionDecision != hook.DecisionDeny || !strings.Contains(got.HookSpecificOutput.PermissionDecisionReason, "could not be read") {
			t.Errorf("%s: expected an undecodable-input deny, got %+v", tc.tool, got)
		}
	}
}
