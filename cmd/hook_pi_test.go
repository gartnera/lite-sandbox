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

// runPiHook feeds runHook a tool call the way lite-sandbox's pi extension
// forwards it, and returns the decision, or nil when the hook deferred.
func runPiHook(t *testing.T, cwd, tool string, input map[string]any, opts hookOptions) *hook.Decision {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"pi_event":        hook.PiEventToolCall,
		"session_id":      "s-1",
		"cwd":             cwd,
		"tool_name":       tool,
		"tool_input":      input,
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &cobra.Command{}
	c.SetIn(bytes.NewReader(payload))
	c.SetOut(&out)
	c.SetErr(&bytes.Buffer{})
	if err := runHook(c, opts); err != nil {
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

func TestPiHookFileTools(t *testing.T) {
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
		{"read inside", hook.PiToolRead, map[string]any{"path": "src/main.go"}, false},
		{"read outside", hook.PiToolRead, map[string]any{"path": filepath.Join(outside, "secret")}, true},
		{"read home via tilde", hook.PiToolRead, map[string]any{"path": "~/notes.txt"}, true},
		{"read outside via @", hook.PiToolRead, map[string]any{"path": "@" + filepath.Join(outside, "secret")}, true},
		{"read outside via file URL", hook.PiToolRead, map[string]any{"path": "file://" + filepath.Join(outside, "secret")}, true},
		{"read traversal", hook.PiToolRead, map[string]any{"path": "../../etc/passwd"}, true},
		{"read project .pi", hook.PiToolRead, map[string]any{"path": ".pi/settings.json"}, false},
		{"grep workspace default", hook.PiToolGrep, map[string]any{"pattern": "TODO"}, false},
		{"grep outside", hook.PiToolGrep, map[string]any{"pattern": "TODO", "path": home}, true},
		{"find outside", hook.PiToolFind, map[string]any{"pattern": "*.go", "path": outside}, true},
		{"ls default", hook.PiToolLs, map[string]any{}, false},
		{"ls outside", hook.PiToolLs, map[string]any{"path": "/etc"}, true},
		{"write inside", hook.PiToolWrite, map[string]any{"path": "a.go", "content": "x"}, false},
		{"write outside", hook.PiToolWrite, map[string]any{"path": filepath.Join(outside, "x"), "content": "x"}, true},
		{"edit inside", hook.PiToolEdit, map[string]any{"path": "a.go", "edits": []any{map[string]any{"oldText": "a", "newText": "b"}}}, false},
		{"edit into .git", hook.PiToolEdit, map[string]any{"path": ".git/hooks/pre-commit", "edits": []any{}}, true},
		{"write project .pi extension", hook.PiToolWrite, map[string]any{"path": ".pi/extensions/x.ts", "content": "x"}, true},
		{"write project .claude settings", hook.PiToolWrite, map[string]any{"path": ".claude/settings.json", "content": "{}"}, true},
		{"edit project .pi settings", hook.PiToolEdit, map[string]any{"path": "./.pi/settings.json", "edits": []any{}}, true},
		// The same lowercase names mean other tools to Grok; an exact key
		// match keeps a differently cased duplicate from hiding the path.
		{"case-folded duplicate key", hook.PiToolRead, map[string]any{"path": filepath.Join(outside, "secret"), "PATH": "a.go"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := runPiHook(t, cwd, tt.tool, tt.input, hookOptions{})
			if got := decisionOf(d) == hook.DecisionDeny; got != tt.wantDeny {
				t.Fatalf("deny = %v, want %v (decision %+v)", got, tt.wantDeny, d)
			}
		})
	}
}

func TestPiHookAgentConfigWriteReason(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	d := runPiHook(t, cwd, hook.PiToolWrite, map[string]any{"path": ".pi/extensions/x.ts", "content": "x"}, hookOptions{})
	if decisionOf(d) != hook.DecisionDeny {
		t.Fatalf("decision = %+v, want deny", d)
	}
	if reason := d.HookSpecificOutput.PermissionDecisionReason; !strings.Contains(reason, ".pi directory") {
		t.Errorf("reason %q does not name the .pi directory", reason)
	}
}

func TestPiHookShellRedirect(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	for _, tool := range []string{hook.PiToolBash, hook.PiToolPowerShell} {
		d := runPiHook(t, cwd, tool, map[string]any{"command": "ls"}, hookOptions{})
		if decisionOf(d) != hook.DecisionDeny {
			t.Fatalf("%s: decision = %+v, want deny", tool, d)
		}
		if reason := d.HookSpecificOutput.PermissionDecisionReason; !strings.Contains(reason, "mcp__lite_sandbox__bash") {
			t.Errorf("%s: reason %q does not name pi's sandbox tool", tool, reason)
		}
	}
}

func TestPiHookValidateBash(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	opts := hookOptions{validateBash: true}
	if d := runPiHook(t, cwd, hook.PiToolBash, map[string]any{"command": "ls"}, opts); decisionOf(d) != hook.DecisionAllow {
		t.Errorf("ls: decision = %+v, want allow", d)
	}
	if d := runPiHook(t, cwd, hook.PiToolBash, map[string]any{"command": "cat /etc/shadow"}, opts); decisionOf(d) != hook.DecisionDeny {
		t.Errorf("cat /etc/shadow: decision = %+v, want deny", d)
	}
	// PowerShell is not bash: it is redirected even when bash is validated.
	if d := runPiHook(t, cwd, hook.PiToolPowerShell, map[string]any{"command": "ls"}, opts); decisionOf(d) != hook.DecisionDeny {
		t.Errorf("powershell: decision = %+v, want deny", d)
	}
}

func TestPiHookMCPTools(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	for _, tool := range []string{piMCPToolPrefix + "bash", piMCPToolPrefix + "list_shells", piMCPToolPrefix + "kill_shell"} {
		if d := runPiHook(t, cwd, tool, map[string]any{"command": "ls"}, hookOptions{configRequests: true}); decisionOf(d) != hook.DecisionAllow {
			t.Errorf("%s: decision = %+v, want allow", tool, d)
		}
	}
	// Claude Code's spelling is not pi's: from pi it is some other tool.
	if d := runPiHook(t, cwd, mcpToolPrefix+"bash", map[string]any{"command": "ls"}, hookOptions{}); d != nil {
		t.Errorf("%s from pi: decision = %+v, want defer", mcpToolPrefix+"bash", d)
	}
}

// TestPiHookAskCommand checks that a pi call to the sandbox's bash tool that
// runs an ask: true command is answered "ask" (the extension then confirms
// with the user) and records the approval the server consumes.
func TestPiHookAskCommand(t *testing.T) {
	dir, c := setupAskProject(t, askConfig, serveOptions{configRequests: true})
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	const command = "rm f"
	d := runPiHook(t, dir, piMCPToolPrefix+"bash", map[string]any{"command": command}, hookOptions{configRequests: true})
	if decisionOf(d) != hook.DecisionAsk {
		t.Fatalf("hook decision = %+v, want ask", d)
	}
	if text, isErr := runBash(t, c, command); isErr {
		t.Fatalf("approved call failed: %s", text)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("approved rm did not run")
	}
}

// TestPiHookConfigRequest checks that a config request from pi is put to the
// user, as from Claude Code.
func TestPiHookConfigRequest(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := runPiHook(t, cwd, piMCPToolPrefix+"bash", map[string]any{"command": "lite-sandbox config commands allow make"}, hookOptions{configRequests: true})
	if decisionOf(d) != hook.DecisionAsk {
		t.Fatalf("decision = %+v, want ask", d)
	}
}

func TestPiModelPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	for _, tt := range []struct{ in, want string }{
		{"a.go", "a.go"},
		{"@a.go", "a.go"},
		{"@@a.go", "@a.go"},
		{"~", home},
		{"~/x", filepath.Join(home, "x")},
		{"@~/x", filepath.Join(home, "x")},
		{"~user/x", "~user/x"},
		{"file:///etc/passwd", "/etc/passwd"},
		{"a b.go", "a b.go"},
	} {
		if got := hook.PiModelPath(tt.in); got != tt.want {
			t.Errorf("PiModelPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestPiHookValidateBashLooserModesAsk checks that outside allowlist mode a
// pi bash command that passes the check is put to the user: deferring, as for
// Claude Code, would run it unasked, since pi has no permission prompt.
func TestPiHookValidateBashLooserModesAsk(t *testing.T) {
	t.Setenv("TMPDIR", "/tmp")
	cwd := t.TempDir()
	for _, mode := range []string{"denylist", "open"} {
		t.Run(mode, func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "config.yaml")
			t.Setenv("LITE_SANDBOX_CONFIG", cfgPath)
			if err := os.WriteFile(cfgPath, []byte("mode: "+mode+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			d := runPiHook(t, cwd, hook.PiToolBash, map[string]any{"command": "curl http://x -o fetched.sh"}, hookOptions{validateBash: true})
			if decisionOf(d) != hook.DecisionAsk {
				t.Fatalf("decision = %+v, want ask", d)
			}
			if reason := d.HookSpecificOutput.PermissionDecisionReason; !strings.Contains(reason, mode+" mode") {
				t.Errorf("reason %q does not name the mode", reason)
			}
		})
	}
}
