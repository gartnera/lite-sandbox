package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/hook"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

// setupPromptProject runs the test from a fresh project directory under a
// config with the given body, and returns that directory and a client of a
// server configured from it.
func setupPromptProject(t *testing.T, body string, opts serveOptions) (string, *client.Client) {
	t.Helper()
	isolateConfig(t)
	isolateConfigRequests(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", cfgPath)
	if err := os.WriteFile(cfgPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	cfg, err := config.LoadForDirectory(dir)
	if err != nil {
		t.Fatal(err)
	}
	sb := bash_sandboxed.NewSandbox()
	sb.UpdateConfig(cfg, dir)
	t.Cleanup(func() { sb.Close() })
	c, err := client.NewInProcessClient(newMCPServer(sb, opts))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Initialize(context.Background(), mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: "2024-11-05",
			ClientInfo:      mcp.Implementation{Name: "test-client", Version: "0.0.1"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	return dir, c
}

const promptConfig = "commands:\n  - command: rm\n    prompt: true\n"

// TestPromptedCommandRequiresHook is the end-to-end contract of prompt: true:
// the server runs a prompted command only in a call the hook asked the user
// about, exactly that call, and once.
func TestPromptedCommandRequiresHook(t *testing.T) {
	dir, c := setupPromptProject(t, promptConfig, serveOptions{configRequests: true})
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	const command = "rm f"

	// No hook ran: refused.
	if text, isErr := runBash(t, c, command); !isErr || !strings.Contains(text, "needs the user's approval") {
		t.Fatalf("call without the hook = %q (error %v), want the approval refusal", text, isErr)
	}

	d := evaluate(bashEvent(t, command, false), hookOptions{configRequests: true})
	if decisionOf(d) != hook.DecisionAsk {
		t.Fatalf("hook decision = %+v, want ask", d)
	}
	if reason := d.HookSpecificOutput.PermissionDecisionReason; !strings.Contains(reason, "`rm`") {
		t.Errorf("ask reason %q does not name the prompted command", reason)
	}

	// The approval is for that exact command.
	if _, isErr := runBash(t, c, "rm  f"); !isErr {
		t.Fatal("a command the hook did not ask about ran")
	}
	if text, isErr := runBash(t, c, command); isErr {
		t.Fatalf("approved call failed: %s", text)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("approved rm did not run")
	}

	// And it is used up.
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, isErr := runBash(t, c, command); !isErr {
		t.Fatal("one approval ran two calls")
	}

	// Commands that prompt for nothing keep the plain pre-approval, and one
	// the sandbox refuses anyway is denied rather than put to the user.
	if d := evaluate(bashEvent(t, "ls", false), hookOptions{configRequests: true}); decisionOf(d) != hook.DecisionAllow {
		t.Errorf("ls: hook decision = %+v, want allow", d)
	}
	d = evaluate(bashEvent(t, "rm /etc/hostname", false), hookOptions{configRequests: true})
	if decisionOf(d) != hook.DecisionDeny || !strings.Contains(d.HookSpecificOutput.PermissionDecisionReason, "did not pass sandbox validation") {
		t.Errorf("rm outside the boundary: hook decision = %+v, want a validation denial", d)
	}
}

// TestPromptedCommandBackground: the approval reaches a background call.
func TestPromptedCommandBackground(t *testing.T) {
	dir, c := setupPromptProject(t, promptConfig, serveOptions{configRequests: true})
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if d := evaluate(bashEvent(t, "rm f", true), hookOptions{configRequests: true}); decisionOf(d) != hook.DecisionAsk {
		t.Fatalf("hook decision = %+v, want ask", d)
	}
	res, err := c.CallTool(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "bash", Arguments: map[string]any{"command": "rm f", "run_in_background": true}},
	})
	if err != nil || res.IsError {
		t.Fatalf("background call: %v %+v", err, res)
	}
}

// TestPromptedCommandWithoutAsk: an agent that cannot ask (no
// --config-requests) gets the plain pre-approval from the hook, and the
// sandbox refuses the prompted command.
func TestPromptedCommandWithoutAsk(t *testing.T) {
	dir, c := setupPromptProject(t, promptConfig, serveOptions{})
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if d := evaluate(bashEvent(t, "rm f", false), hookOptions{}); decisionOf(d) != hook.DecisionAllow {
		t.Errorf("hook decision = %+v, want allow", d)
	}
	if text, isErr := runBash(t, c, "rm f"); !isErr || !strings.Contains(text, "needs the user's approval") {
		t.Errorf("= %q (error %v), want the approval refusal", text, isErr)
	}
}

// TestValidateBuiltinBashPrompt: in --validate-bash mode a prompted command
// that passes validation is put to the user when the agent asks (--ask), and
// denied when it cannot.
func TestValidateBuiltinBashPrompt(t *testing.T) {
	dir, _ := setupPromptProject(t, promptConfig, serveOptions{})
	ev := &hook.Event{ToolName: hook.ToolBash, CWD: dir, ToolInput: &hook.BashInput{Command: "rm f"}}
	d := validateBuiltinBash(ev, hookOptions{ask: true})
	if decisionOf(d) != hook.DecisionAsk {
		t.Errorf("--ask: decision = %+v, want ask", d)
	}
	if d := validateBuiltinBash(ev, hookOptions{}); decisionOf(d) != hook.DecisionDeny {
		t.Errorf("without --ask: decision = %+v, want deny", d)
	}
	ev.ToolInput = &hook.BashInput{Command: "rm /etc/hostname"}
	if d := validateBuiltinBash(ev, hookOptions{ask: true}); decisionOf(d) != hook.DecisionDeny {
		t.Errorf("rm outside the boundary: decision = %+v, want deny", d)
	}
}
