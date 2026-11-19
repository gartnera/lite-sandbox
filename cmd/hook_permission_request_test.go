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

// permissionRequestEvent turns a PreToolUse event into the PermissionRequest
// event Claude Code sends for the same call when it is about to prompt.
func permissionRequestEvent(ev *hook.Event, mode hook.PermissionMode) *hook.Event {
	ev.HookEventName = hook.EventPermissionRequest
	ev.PermissionMode = mode
	return ev
}

func behaviorOf(d *hook.PermissionRequestDecision) hook.PermissionBehavior {
	if d == nil {
		return ""
	}
	return d.HookSpecificOutput.Decision.Behavior
}

// TestPermissionRequestPlanMode: in plan mode the sandbox's MCP tools are
// allowed; in every other mode, and for any other tool, the hook stays out of
// the prompt.
func TestPermissionRequestPlanMode(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	opts := hookOptions{configRequests: true}

	ev := permissionRequestEvent(bashEvent(t, "git clone https://example.com/r.git", false), hook.PermissionModePlan)
	if d := evaluatePermissionRequest(ev, opts); behaviorOf(d) != hook.BehaviorAllow {
		t.Errorf("plan mode bash: decision = %+v, want allow", d)
	}
	for _, tool := range []string{"kill_shell", "list_shells"} {
		ev := &hook.Event{
			HookEventName:  hook.EventPermissionRequest,
			PermissionMode: hook.PermissionModePlan,
			ToolName:       mcpToolPrefix + tool,
			RawToolInput:   json.RawMessage(`{}`),
		}
		if d := evaluatePermissionRequest(ev, opts); behaviorOf(d) != hook.BehaviorAllow {
			t.Errorf("plan mode %s: decision = %+v, want allow", tool, d)
		}
	}

	for _, mode := range []hook.PermissionMode{"", hook.PermissionModeDefault, hook.PermissionModeAcceptEdits, hook.PermissionModeBypassPermissions} {
		ev := permissionRequestEvent(bashEvent(t, "ls", false), mode)
		if d := evaluatePermissionRequest(ev, opts); d != nil {
			t.Errorf("mode %q: decision = %+v, want none", mode, d)
		}
	}

	for _, tool := range []string{"Bash", "Write", "mcp__other__bash"} {
		ev := permissionRequestEvent(bashEvent(t, "ls", false), hook.PermissionModePlan)
		ev.ToolName = tool
		if d := evaluatePermissionRequest(ev, opts); d != nil {
			t.Errorf("plan mode %s: decision = %+v, want none", tool, d)
		}
	}

	// Other agents speak PreToolUse only; never answer as if from Claude Code.
	codex := permissionRequestEvent(bashEvent(t, "ls", false), hook.PermissionModePlan)
	codex.TurnID = "t1"
	if d := evaluatePermissionRequest(codex, opts); d != nil {
		t.Errorf("codex event: decision = %+v, want none", d)
	}
}

// TestPermissionRequestConfigRequest: a config request that changes the config
// is left to the user, since PreToolUse put it to them on purpose; one that
// only reads is allowed, as PreToolUse allows it.
func TestPermissionRequestConfigRequest(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	opts := hookOptions{configRequests: true}

	change := permissionRequestEvent(bashEvent(t, "lite-sandbox config commands allow make", false), hook.PermissionModePlan)
	if d := evaluatePermissionRequest(change, opts); d != nil {
		t.Errorf("config change: decision = %+v, want none (the user decides)", d)
	}
	malformed := permissionRequestEvent(bashEvent(t, "lite-sandbox config paths allow", false), hook.PermissionModePlan)
	if d := evaluatePermissionRequest(malformed, opts); d != nil {
		t.Errorf("malformed config request: decision = %+v, want none", d)
	}
	read := permissionRequestEvent(bashEvent(t, "lite-sandbox config show", false), hook.PermissionModePlan)
	if d := evaluatePermissionRequest(read, opts); behaviorOf(d) != hook.BehaviorAllow {
		t.Errorf("config read: decision = %+v, want allow", d)
	}

	// Without --config-requests the server refuses config requests outright,
	// so there is no prompt to protect.
	if d := evaluatePermissionRequest(change, hookOptions{}); behaviorOf(d) != hook.BehaviorAllow {
		t.Errorf("config change without --config-requests: decision = %+v, want allow", d)
	}

	// Arguments the hook can't read are left to the user.
	unreadable := permissionRequestEvent(bashEvent(t, "ls", false), hook.PermissionModePlan)
	unreadable.RawToolInput = json.RawMessage(`{"command": 7}`)
	if d := evaluatePermissionRequest(unreadable, opts); d != nil {
		t.Errorf("unreadable input: decision = %+v, want none", d)
	}
}

// TestPermissionRequestAskCommand: a command whose commands entry has
// ask: true is left to the user, and answering the event issues no approval,
// so the server still refuses the command until PreToolUse asks.
func TestPermissionRequestAskCommand(t *testing.T) {
	dir, c := setupAskProject(t, askConfig, serveOptions{configRequests: true})
	opts := hookOptions{configRequests: true}
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	ev := permissionRequestEvent(bashEvent(t, "rm f", false), hook.PermissionModePlan)
	if d := evaluatePermissionRequest(ev, opts); d != nil {
		t.Fatalf("ask command: decision = %+v, want none (the user decides)", d)
	}
	if text, isErr := runBash(t, c, "rm f"); !isErr || !strings.Contains(text, "needs the user's approval") {
		t.Fatalf("after the PermissionRequest event: %q (error %v), want the approval refusal", text, isErr)
	}

	// The real sequence: PreToolUse asks and records the approval, then the
	// PermissionRequest for the same prompt defers, and the approval is intact.
	if d := evaluate(bashEvent(t, "rm f", false), opts); decisionOf(d) != hook.DecisionAsk {
		t.Fatalf("PreToolUse decision = %+v, want ask", d)
	}
	if d := evaluatePermissionRequest(ev, opts); d != nil {
		t.Fatalf("ask command after PreToolUse: decision = %+v, want none", d)
	}
	if text, isErr := runBash(t, c, "rm f"); isErr {
		t.Fatalf("approved call failed: %s", text)
	}

	other := permissionRequestEvent(bashEvent(t, "ls", false), hook.PermissionModePlan)
	if d := evaluatePermissionRequest(other, opts); behaviorOf(d) != hook.BehaviorAllow {
		t.Errorf("ls: decision = %+v, want allow", d)
	}
}

// TestRunHookPermissionRequestOutput checks the wire format Claude Code
// expects from a PermissionRequest hook.
func TestRunHookPermissionRequestOutput(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	run := func(event map[string]any) string {
		t.Helper()
		payload, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		c := &cobra.Command{}
		c.SetIn(bytes.NewReader(payload))
		c.SetOut(&out)
		c.SetErr(&bytes.Buffer{})
		if err := runHook(c, hookOptions{configRequests: true}); err != nil {
			t.Fatalf("runHook: %v", err)
		}
		return out.String()
	}
	event := map[string]any{
		"hook_event_name": "PermissionRequest",
		"permission_mode": "plan",
		"tool_name":       "mcp__lite-sandbox__bash",
		"cwd":             t.TempDir(),
		"tool_input":      map[string]any{"command": "ls"},
		"permission_suggestions": []any{
			map[string]any{"type": "addRules", "behavior": "allow", "destination": "localSettings"},
		},
	}

	var got map[string]any
	if err := json.Unmarshal([]byte(run(event)), &got); err != nil {
		t.Fatalf("output is not JSON: %v", err)
	}
	out := asMap(got["hookSpecificOutput"])
	if asString(out["hookEventName"]) != "PermissionRequest" || asString(asMap(out["decision"])["behavior"]) != "allow" {
		t.Errorf("output = %v, want a PermissionRequest allow", got)
	}

	event["permission_mode"] = "default"
	if out := run(event); out != "" {
		t.Errorf("default mode: output = %q, want none", out)
	}
}

// TestReconcileClaudeHooksPermissionRequest: install registers the
// PermissionRequest hook for the MCP tools alongside PreToolUse, and drops it
// when the plan has none, leaving other tools' hooks alone.
func TestReconcileClaudeHooksPermissionRequest(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")
	binPath := "/usr/local/bin/lite-sandbox"
	existing := `{"hooks":{"PermissionRequest":[{"matcher":"Bash","hooks":[{"type":"command","command":"/other/tool approve"}]}]}}`
	if err := os.WriteFile(settingsPath, []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	groups := func(event string) []any {
		t.Helper()
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]any
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		return asSlice(asMap(raw["hooks"])[event])
	}

	plan := claudeOptions{}.plan(binPath)
	if plan.permissionHookCommand != binPath+" hook --config-requests" {
		t.Fatalf("permissionHookCommand = %q", plan.permissionHookCommand)
	}
	for range 2 { // idempotent
		if err := reconcileClaudeHooks(tmpDir, binPath, plan); err != nil {
			t.Fatal(err)
		}
	}
	pr := groups("PermissionRequest")
	if len(pr) != 2 {
		t.Fatalf("PermissionRequest groups = %v, want the other tool's and lite-sandbox's", pr)
	}
	ours := asMap(pr[1])
	if asString(ours["matcher"]) != mcpToolMatcher || asString(asMap(asSlice(ours["hooks"])[0])["command"]) != plan.permissionHookCommand {
		t.Errorf("lite-sandbox PermissionRequest group = %v", ours)
	}
	if len(groups("PreToolUse")) != 1 {
		t.Errorf("PreToolUse groups = %v, want lite-sandbox's", groups("PreToolUse"))
	}

	// --bash-ast-hook-mode configures no MCP server, so no PermissionRequest hook.
	astPlan := claudeOptions{bashASTHookMode: true}.plan(binPath)
	if astPlan.permissionHookCommand != "" {
		t.Fatalf("bash-ast-hook-mode permissionHookCommand = %q, want none", astPlan.permissionHookCommand)
	}
	if err := reconcileClaudeHooks(tmpDir, binPath, astPlan); err != nil {
		t.Fatal(err)
	}
	pr = groups("PermissionRequest")
	if len(pr) != 1 || asString(asMap(asSlice(asMap(pr[0])["hooks"])[0])["command"]) != "/other/tool approve" {
		t.Errorf("PermissionRequest groups after switching modes = %v, want only the other tool's", pr)
	}
}
