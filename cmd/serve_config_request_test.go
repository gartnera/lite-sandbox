package cmd

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/gartnera/lite-sandbox/internal/hook"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

// isolateConfigRequests points the config requests' approval tickets at a
// fresh directory (os.UserCacheDir reads XDG_CACHE_HOME on Linux, HOME on
// macOS).
func isolateConfigRequests(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("HOME", dir)
}

// stubConfigCommand replaces the `lite-sandbox config` subprocess and records
// the arguments of each run.
func stubConfigCommand(t *testing.T) *[][]string {
	t.Helper()
	var runs [][]string
	orig := runConfigCommand
	runConfigCommand = func(_ context.Context, _ string, args []string) (string, error) {
		runs = append(runs, args)
		return "Allowed make\n", nil
	}
	t.Cleanup(func() { runConfigCommand = orig })
	return &runs
}

func setupClientWith(t *testing.T, opts serveOptions) *client.Client {
	t.Helper()
	c, err := client.NewInProcessClient(newMCPServer(bash_sandboxed.NewSandbox(), opts))
	if err != nil {
		t.Fatalf("failed to create in-process client: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Initialize(context.Background(), mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: "2024-11-05",
			ClientInfo:      mcp.Implementation{Name: "test-client", Version: "0.0.1"},
		},
	}); err != nil {
		t.Fatalf("failed to initialize: %v", err)
	}
	return c
}

// runBash calls the bash tool and returns its text and whether it is an error.
func runBash(t *testing.T, c *client.Client, command string) (string, bool) {
	t.Helper()
	res, err := c.CallTool(context.Background(), mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "bash", Arguments: map[string]any{"command": command}},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	var b strings.Builder
	for _, content := range res.Content {
		if text, ok := content.(mcp.TextContent); ok {
			b.WriteString(text.Text)
		}
	}
	return b.String(), res.IsError
}

// bashEvent is the PreToolUse event Claude Code sends before running command
// with the sandbox's bash tool.
func bashEvent(t *testing.T, command string, background bool) *hook.Event {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"command": command, "run_in_background": background})
	if err != nil {
		t.Fatal(err)
	}
	return &hook.Event{
		HookEventName: hook.EventPreToolUse,
		ToolName:      mcpToolPrefix + "bash",
		CWD:           t.TempDir(),
		RawToolInput:  raw,
	}
}

func decisionOf(d *hook.Decision) hook.PermissionDecision {
	if d == nil {
		return ""
	}
	return d.HookSpecificOutput.PermissionDecision
}

// TestConfigRequestRequiresHook is the end-to-end contract: the server runs a
// `lite-sandbox config` command only after the hook asked the user about
// exactly that command, and only once.
func TestConfigRequestRequiresHook(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	runs := stubConfigCommand(t)
	c := setupClientWith(t, serveOptions{configRequests: true})
	const command = "lite-sandbox config commands allow make"

	// No hook ran: refused, nothing run.
	text, isErr := runBash(t, c, command)
	if !isErr || !strings.Contains(text, "was not approved") {
		t.Fatalf("call without the hook = %q (error %v), want a refusal", text, isErr)
	}
	if len(*runs) != 0 {
		t.Fatalf("config command ran without approval: %v", *runs)
	}

	// The hook asks the user, naming the command.
	d := evaluate(bashEvent(t, command, false), hookOptions{configRequests: true})
	if decisionOf(d) != hook.DecisionAsk {
		t.Fatalf("hook decision = %+v, want ask", d)
	}
	if reason := d.HookSpecificOutput.PermissionDecisionReason; !strings.Contains(reason, command) {
		t.Errorf("ask reason %q does not name the command", reason)
	}

	// A different request is still refused.
	if _, isErr := runBash(t, c, "lite-sandbox config mode set open"); !isErr {
		t.Fatal("a request the hook did not ask about was run")
	}

	// The approved one runs, however its path is spelled.
	text, isErr = runBash(t, c, "/usr/local/bin/lite-sandbox config commands allow 'make'")
	if isErr {
		t.Fatalf("approved call failed: %s", text)
	}
	if want := []string{"commands", "allow", "make"}; len(*runs) != 1 || !slices.Equal((*runs)[0], want) {
		t.Fatalf("runs = %v, want one run of %v", *runs, want)
	}

	// The approval is used up.
	if _, isErr := runBash(t, c, command); !isErr {
		t.Fatal("one approval ran two requests")
	}
}

// TestConfigRequestNotAlone checks a `lite-sandbox config` command combined
// with anything else is never a config request: the hook pre-approves it like
// any bash call and the sandbox's deny list refuses it, so nothing beyond the
// command the user approves can ride along.
func TestConfigRequestNotAlone(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	runs := stubConfigCommand(t)
	c := setupClientWith(t, serveOptions{configRequests: true})
	for _, command := range []string{
		"lite-sandbox config commands allow make && echo hi",
		"lite-sandbox config commands allow make; echo hi",
		"lite-sandbox config commands allow make | cat",
		"lite-sandbox config commands allow make > out.txt",
		"lite-sandbox config commands allow $CMD",
		"lite-sandbox config commands allow $(echo make)",
		"lite-sandbox config paths allow *",
		"FOO=1 lite-sandbox config commands allow make",
		"lite-sandbox config commands allow make &",
	} {
		if d := evaluate(bashEvent(t, command, false), hookOptions{configRequests: true}); decisionOf(d) != hook.DecisionAllow {
			t.Errorf("%q: hook decision = %+v, want the plain bash pre-approval", command, d)
		}
		text, isErr := runBash(t, c, command)
		if !isErr || !strings.Contains(text, `deny list entry "lite-sandbox config"`) {
			t.Errorf("%q = %q, want the deny list refusal", command, text)
		}
		if !strings.Contains(text, "runs only as a command of its own") {
			t.Errorf("%q: refusal %q lacks the hint to run it alone", command, text)
		}
	}
	if len(*runs) != 0 {
		t.Fatalf("runs = %v, want none", *runs)
	}
}

// TestConfigRequestsOff checks agents installed without --config-requests
// keep the old behavior: the hook pre-approves, the deny list refuses.
func TestConfigRequestsOff(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	runs := stubConfigCommand(t)
	const command = "lite-sandbox config commands allow make"

	grok := bashEvent(t, command, false)
	grok.ToolName = grokMCPToolPrefix + "bash"
	grok.GrokEventName = "pre_tool_use"
	for name, tc := range map[string]struct {
		event *hook.Event
		opts  hookOptions
	}{
		"no flag": {bashEvent(t, command, false), hookOptions{}},
		"grok":    {grok, hookOptions{configRequests: true}},
	} {
		if d := evaluate(tc.event, tc.opts); decisionOf(d) != hook.DecisionAllow {
			t.Errorf("%s: decision = %+v, want allow (no ask, no ticket)", name, d)
		}
	}

	c := setupClientWith(t, serveOptions{})
	text, isErr := runBash(t, c, command)
	if !isErr || !strings.Contains(text, `deny list entry "lite-sandbox config"`) {
		t.Fatalf("got %q, want the deny list refusal", text)
	}
	if strings.Contains(text, "runs only as a command of its own") {
		t.Errorf("hint shown without config requests: %q", text)
	}
	if len(*runs) != 0 {
		t.Fatalf("runs = %v, want none", *runs)
	}
}

func TestConfigRequestHookDenials(t *testing.T) {
	isolateConfigRequests(t)
	for name, ev := range map[string]*hook.Event{
		"interactive edit": bashEvent(t, "lite-sandbox config edit", false),
		"background":       bashEvent(t, "lite-sandbox config commands allow make", true),
	} {
		if d := evaluate(ev, hookOptions{configRequests: true}); decisionOf(d) != hook.DecisionDeny {
			t.Errorf("%s: decision = %+v, want deny", name, d)
		}
	}
}

// TestBashErrorConfigRequestHint checks the bash tool points from a
// `lite-sandbox config` fix to running it only when config requests are on.
func TestBashErrorConfigRequestHint(t *testing.T) {
	isolateConfig(t)
	for _, on := range []bool{false, true} {
		c := setupClientWith(t, serveOptions{configRequests: on})
		text, isErr := runBash(t, c, "notarealcommand123")
		if !isErr || !strings.Contains(text, "lite-sandbox config commands allow") {
			t.Fatalf("bash error = %q, want the whitelist error with its fix", text)
		}
		if got := strings.Contains(text, "make this config change yourself"); got != on {
			t.Errorf("configRequests=%v: hint present = %v in %q", on, got, text)
		}
	}
}

func TestHookDenialConfigRequestHint(t *testing.T) {
	isolateConfig(t)
	event := &hook.Event{
		HookEventName: hook.EventPreToolUse,
		ToolName:      hook.ToolRead,
		CWD:           t.TempDir(),
		ToolInput:     &hook.ReadInput{FilePath: filepath.Join(t.TempDir(), "secret.txt")},
	}
	for _, on := range []bool{false, true} {
		d := evaluate(event, hookOptions{configRequests: on})
		if decisionOf(d) != hook.DecisionDeny {
			t.Fatalf("decision = %+v, want deny", d)
		}
		if got := strings.Contains(d.HookSpecificOutput.PermissionDecisionReason, "make this config change yourself"); got != on {
			t.Errorf("configRequests=%v: hint present = %v", on, got)
		}
	}
}
