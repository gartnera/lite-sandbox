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

// permissionRequest turns a sandbox bash event into the PermissionRequest
// Claude Code sends for the same call in mode.
func permissionRequest(event *hook.Event, mode hook.PermissionMode) *hook.Event {
	event.HookEventName = hook.EventPermissionRequest
	event.PermissionMode = mode
	return event
}

// TestEvaluatePermissionRequest covers which prompts the hook answers: the
// sandbox's MCP tools in plan mode, where Claude Code ignores the PreToolUse
// allow, and nothing else.
func TestEvaluatePermissionRequest(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	t.Chdir(t.TempDir())
	opts := hookOptions{configRequests: true}

	for _, tool := range []string{"bash", "kill_shell", "list_shells"} {
		event := permissionRequest(bashEvent(t, "ls", false), hook.PermissionModePlan)
		event.ToolName = mcpToolPrefix + tool
		if d := evaluatePermissionRequest(event, opts); d == nil || d.HookSpecificOutput.Decision.Behavior != hook.DecisionAllow {
			t.Errorf("%s in plan mode: decision = %+v, want allow", tool, d)
		}
	}

	// Outside plan mode the allow rules settle the sandbox's calls; a prompt
	// there was raised on purpose.
	for _, mode := range []hook.PermissionMode{"", hook.PermissionModeDefault, hook.PermissionModeAcceptEdits, "dontAsk", "auto"} {
		if d := evaluatePermissionRequest(permissionRequest(bashEvent(t, "ls", false), mode), opts); d != nil {
			t.Errorf("mode %q: decision = %+v, want none", mode, d)
		}
	}

	// Only the sandbox's own tools.
	for _, tool := range []string{"Bash", "Write", "mcp__other-server__bash"} {
		event := permissionRequest(bashEvent(t, "ls", false), hook.PermissionModePlan)
		event.ToolName = tool
		if d := evaluatePermissionRequest(event, opts); d != nil {
			t.Errorf("%s: decision = %+v, want none", tool, d)
		}
	}

	// A config request keeps its prompt; asking for help changes nothing, and
	// without --config-requests the request is pre-approved (the sandbox
	// refuses it) like any other command.
	const request = "lite-sandbox config commands allow make"
	if d := evaluatePermissionRequest(permissionRequest(bashEvent(t, request, false), hook.PermissionModePlan), opts); d != nil {
		t.Errorf("config request: decision = %+v, want none (the user is asked)", d)
	}
	if d := evaluatePermissionRequest(permissionRequest(bashEvent(t, "lite-sandbox config --help", false), hook.PermissionModePlan), opts); d == nil {
		t.Error("config help: want allow")
	}
	if d := evaluatePermissionRequest(permissionRequest(bashEvent(t, request, false), hook.PermissionModePlan), hookOptions{}); d == nil {
		t.Error("config request without --config-requests: want allow")
	}
}

// TestPermissionRequestKeepsAskCommandPrompt: a command that asks first keeps
// its prompt in plan mode, and answering the PermissionRequest issues no
// approval of its own: only the PreToolUse ask does.
func TestPermissionRequestKeepsAskCommandPrompt(t *testing.T) {
	dir, c := setupAskProject(t, askConfig, serveOptions{configRequests: true})
	if err := os.WriteFile(filepath.Join(dir, "f"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	opts := hookOptions{configRequests: true}

	if d := evaluatePermissionRequest(permissionRequest(bashEvent(t, "rm f", false), hook.PermissionModePlan), opts); d != nil {
		t.Fatalf("rm in plan mode: decision = %+v, want none (the user is asked)", d)
	}
	if text, isErr := runBash(t, c, "rm f"); !isErr || !strings.Contains(text, "needs the user's approval") {
		t.Fatalf("rm after the PermissionRequest alone = %q (error %v), want the approval refusal", text, isErr)
	}
	if d := evaluatePermissionRequest(permissionRequest(bashEvent(t, "ls", false), hook.PermissionModePlan), opts); d == nil {
		t.Error("ls in plan mode: want allow")
	}
}

// TestPermissionRequestKeepsConfigRequestTicketless: answering the
// PermissionRequest for a config request issues no ticket, so the server
// still refuses it.
func TestPermissionRequestKeepsConfigRequestTicketless(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	runs := stubConfigCommand(t)
	c := setupClientWith(t, serveOptions{configRequests: true})
	const command = "lite-sandbox config commands allow make"

	if d := evaluatePermissionRequest(permissionRequest(bashEvent(t, command, false), hook.PermissionModePlan), hookOptions{configRequests: true}); d != nil {
		t.Fatalf("decision = %+v, want none", d)
	}
	if text, isErr := runBash(t, c, command); !isErr || !strings.Contains(text, "was not approved") {
		t.Fatalf("config request after the PermissionRequest alone = %q (error %v), want a refusal", text, isErr)
	}
	if len(*runs) != 0 {
		t.Fatalf("config command ran without approval: %v", *runs)
	}
}

// TestRunHookPermissionRequestOutput checks the document Claude Code reads
// for a PermissionRequest answer.
func TestRunHookPermissionRequestOutput(t *testing.T) {
	isolateConfig(t)
	run := func(mode string) string {
		t.Helper()
		payload, err := json.Marshal(map[string]any{
			"hook_event_name": "PermissionRequest",
			"permission_mode": mode,
			"tool_name":       "mcp__lite-sandbox__bash",
			"cwd":             t.TempDir(),
			"tool_input":      map[string]any{"command": "ls"},
		})
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		c := &cobra.Command{}
		c.SetIn(bytes.NewReader(payload))
		c.SetOut(&out)
		c.SetErr(&bytes.Buffer{})
		if err := runHook(c, hookOptions{configRequests: true}); err != nil {
			t.Fatalf("runHook returned error: %v", err)
		}
		return out.String()
	}

	var got struct {
		HookSpecificOutput struct {
			HookEventName string `json:"hookEventName"`
			Decision      struct {
				Behavior string `json:"behavior"`
			} `json:"decision"`
		} `json:"hookSpecificOutput"`
	}
	out := run("plan")
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("decision is not valid JSON: %v\n%s", err, out)
	}
	if got.HookSpecificOutput.HookEventName != "PermissionRequest" || got.HookSpecificOutput.Decision.Behavior != "allow" {
		t.Errorf("decision = %s, want a PermissionRequest allow", out)
	}

	if out := run("default"); out != "" {
		t.Errorf("default mode: want no output, got %s", out)
	}
}

// TestClaudePlanPermissionRequestHook: every mode that configures the MCP
// server registers the PermissionRequest hook for its tools, with the
// PreToolUse hook's command; --bash-ast-hook-mode, which has no MCP server,
// registers none.
func TestClaudePlanPermissionRequestHook(t *testing.T) {
	const bin = "/usr/local/bin/lite-sandbox"
	for _, o := range []claudeOptions{{}, {withToolHook: true, redirectBash: true}, {withToolHook: true}} {
		p := o.plan(bin)
		hooks := p.claudeHooks()
		if len(hooks) != 2 || hooks[1].event != hook.EventPermissionRequest {
			t.Fatalf("%+v: hooks = %+v, want PreToolUse then PermissionRequest", o, hooks)
		}
		if hooks[1].matcher != mcpToolMatcher || hooks[1].command != p.hookCommand {
			t.Errorf("%+v: PermissionRequest hook = %+v, want %q on %q", o, hooks[1], p.hookCommand, mcpToolMatcher)
		}
	}
	for _, o := range []claudeOptions{{bashASTHookMode: true}, {bashASTHookMode: true, withToolHook: true}} {
		for _, h := range o.plan(bin).claudeHooks() {
			if h.event == hook.EventPermissionRequest {
				t.Errorf("%+v: registers a PermissionRequest hook without an MCP server", o)
			}
		}
	}
}

// TestReconcileClaudeHooksPermissionRequest: install registers the
// PermissionRequest hook next to the PreToolUse one, and switching to a mode
// without it removes it while another tool's PermissionRequest hook stays.
func TestReconcileClaudeHooksPermissionRequest(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")
	const bin = "/usr/local/bin/lite-sandbox"
	const other = "/other/tool approve"
	existing := `{"hooks":{"PermissionRequest":[{"matcher":"Bash","hooks":[{"type":"command","command":"` + other + `"}]}]}}`
	if err := os.WriteFile(settingsPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}

	commands := func(event string) []string {
		t.Helper()
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, g := range asSlice(asMap(raw["hooks"])[event]) {
			for _, c := range asSlice(asMap(g)["hooks"]) {
				got = append(got, asString(asMap(g)["matcher"])+" "+asString(asMap(c)["command"]))
			}
		}
		return got
	}

	for range 2 { // idempotent
		if err := reconcileClaudeHooks(tmpDir, bin, claudeOptions{}.plan(bin).claudeHooks()); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"Bash " + other, mcpToolMatcher + " " + bin + " hook --config-requests"}
	if got := commands("PermissionRequest"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("PermissionRequest hooks = %q, want %q", got, want)
	}

	if err := reconcileClaudeHooks(tmpDir, bin, claudeOptions{bashASTHookMode: true}.plan(bin).claudeHooks()); err != nil {
		t.Fatal(err)
	}
	if got := commands("PermissionRequest"); len(got) != 1 || got[0] != "Bash "+other {
		t.Errorf("PermissionRequest hooks after switching to --bash-ast-hook-mode = %q, want only the other tool's", got)
	}
}

// TestClaudeLaunchArgsPermissionRequestHook: launch passes the
// PermissionRequest hook too.
func TestClaudeLaunchArgsPermissionRequestHook(t *testing.T) {
	setLaunchFlags(t)
	_, settings := launchSettings(t, nil)
	groups := asSlice(settings.Hooks["PermissionRequest"])
	if len(groups) != 1 {
		t.Fatalf("PermissionRequest groups = %v, want one", settings.Hooks)
	}
	group := asMap(groups[0])
	if matcher := asString(group["matcher"]); matcher != mcpToolMatcher {
		t.Errorf("matcher = %q, want %q", matcher, mcpToolMatcher)
	}
	if command := asString(asMap(asSlice(group["hooks"])[0])["command"]); command != testBin+" hook --config-requests" {
		t.Errorf("command = %q", command)
	}
}
