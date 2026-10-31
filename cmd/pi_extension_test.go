package cmd

import (
	"bufio"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// requireNodeTypeStripping skips the test unless a node that runs TypeScript
// directly (type stripping, on by default since Node 22.18 and 23.6) is on
// PATH, and returns its path.
func requireNodeTypeStripping(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not on PATH")
	}
	out, err := exec.Command(node, "--version").Output()
	if err != nil {
		t.Skipf("node --version: %v", err)
	}
	m := regexp.MustCompile(`v(\d+)\.(\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		t.Skipf("unparseable node version %q", out)
	}
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	if major < 22 || (major == 22 && minor < 18) || (major == 23 && minor < 6) {
		t.Skipf("node %s cannot run TypeScript without flags", strings.TrimSpace(string(out)))
	}
	return node
}

// fakePiHook is a stand-in for `lite-sandbox hook`: it records each event it
// is given and answers by tool name.
const fakePiHook = `#!/bin/sh
input=$(cat)
printf '%s\n' "$input" >> "$(dirname "$0")/events.jsonl"
case "$input" in
*'"tool_name":"read"'*) ;;
*'"tool_name":"write"'*) printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"outside the sandbox"}}' ;;
*'"tool_name":"mcp__lite_sandbox__bash"'*) printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"ask","permissionDecisionReason":"change the config?"}}' ;;
*'"tool_name":"grep"'*) printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"allow","permissionDecisionReason":"ok"}}' ;;
*'"tool_name":"find"'*) echo 'not json' ;;
*'"tool_name":"ls"'*) echo 'boom' >&2; exit 3 ;;
esac
`

type piDriverOutput struct {
	Servers  map[string]map[string]any `json:"servers"`
	Results  []map[string]any          `json:"results"`
	Confirms []map[string]string       `json:"confirms"`
	Sections map[string]string         `json:"sections"`
	Events   []string                  `json:"events"`
}

type piDriverCall struct {
	ToolName string         `json:"toolName"`
	Input    map[string]any `json:"input"`
	HasUI    bool           `json:"hasUI"`
	Confirm  bool           `json:"confirm"`
}

// runPiExtension renders the extension for the plan with the fake hook as the
// lite-sandbox binary, drives it through the calls, and returns what it did
// and the events the hook received.
func runPiExtension(t *testing.T, node string, plan piPlan, bin string, calls []piDriverCall) (piDriverOutput, []map[string]any) {
	t.Helper()
	dir := t.TempDir()
	src, err := renderPiExtension(bin, plan)
	if err != nil {
		t.Fatal(err)
	}
	// .mts: an ES module whatever the nearest package.json says.
	ext := filepath.Join(dir, "lite-sandbox.mts")
	if err := os.WriteFile(ext, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	driver, err := filepath.Abs(filepath.Join("testdata", "pi_extension_driver.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	callsJSON, err := json.Marshal(calls)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(node, "--no-warnings", driver, ext, string(callsJSON))
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok {
			stderr = string(ee.Stderr)
		}
		t.Fatalf("driver failed: %v\n%s", err, stderr)
	}
	var res piDriverOutput
	if err := json.Unmarshal(out, &res); err != nil {
		t.Fatalf("driver output is not JSON: %v\n%s", err, out)
	}
	var events []map[string]any
	if f, err := os.Open(filepath.Join(filepath.Dir(bin), "events.jsonl")); err == nil {
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var e map[string]any
			if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
				t.Fatalf("hook got invalid JSON %q: %v", sc.Text(), err)
			}
			events = append(events, e)
		}
	}
	return res, events
}

func TestPiExtension(t *testing.T) {
	node := requireNodeTypeStripping(t)
	hookDir := t.TempDir()
	bin := filepath.Join(hookDir, "lite-sandbox")
	if err := os.WriteFile(bin, []byte(fakePiHook), 0o755); err != nil {
		t.Fatal(err)
	}

	calls := []piDriverCall{
		{ToolName: "read", Input: map[string]any{"path": "a.go"}},                                                 // 0: hook defers
		{ToolName: "write", Input: map[string]any{"path": "/etc/x", "content": "x"}},                              // 1: deny
		{ToolName: "mcp__lite_sandbox__bash", Input: map[string]any{"command": "c"}, HasUI: true, Confirm: true},  // 2: ask, approved
		{ToolName: "mcp__lite_sandbox__bash", Input: map[string]any{"command": "c"}, HasUI: true, Confirm: false}, // 3: ask, declined
		{ToolName: "mcp__lite_sandbox__bash", Input: map[string]any{"command": "c"}, HasUI: false},                // 4: ask, no UI
		{ToolName: "grep", Input: map[string]any{"pattern": "x"}},                                                 // 5: allow
		{ToolName: "find", Input: map[string]any{"pattern": "x"}},                                                 // 6: unreadable output
		{ToolName: "ls", Input: map[string]any{}},                                                                 // 7: hook fails
		{ToolName: "mcp__other__tool", Input: map[string]any{}},                                                   // 8: not governed
	}
	res, events := runPiExtension(t, node, newPiPlan(false), bin, calls)

	if srv := res.Servers["lite-sandbox"]; srv == nil || srv["command"] != bin || srv["exposure"] != "direct" {
		t.Errorf("MCP server = %v, want %s with direct exposure", srv, bin)
	}
	if !strings.Contains(res.Sections["lite-sandbox"], "mcp__lite_sandbox__bash") {
		t.Errorf("system prompt sections = %v", res.Sections)
	}

	blocked := func(i int) (bool, string) {
		r := res.Results[i]
		if r == nil {
			return false, ""
		}
		if e, ok := r["error"].(string); ok {
			return true, e
		}
		reason, _ := r["reason"].(string)
		return r["block"] == true, reason
	}
	for _, tt := range []struct {
		i       int
		block   bool
		contain string
	}{
		{0, false, ""},
		{1, true, "outside the sandbox"},
		{2, false, ""},
		{3, true, "declined"},
		{4, true, "without a UI"},
		{5, false, ""},
		{6, true, "unreadable decision"},
		{7, true, "exited with status 3"},
		{8, false, ""},
	} {
		got, reason := blocked(tt.i)
		if got != tt.block || !strings.Contains(reason, tt.contain) {
			t.Errorf("call %d (%s): blocked = %v (%q), want %v containing %q", tt.i, calls[tt.i].ToolName, got, reason, tt.block, tt.contain)
		}
	}
	if len(res.Confirms) != 2 || res.Confirms[0]["message"] != "change the config?" {
		t.Errorf("confirm dialogs = %v, want two asking %q", res.Confirms, "change the config?")
	}

	// The hook saw every governed call, in the protocol's shape, and not the
	// ungoverned one.
	if len(events) != 8 {
		t.Fatalf("hook got %d events, want 8: %v", len(events), events)
	}
	e := events[0]
	if e["hook_event_name"] != "PreToolUse" || e["pi_event"] != "tool_call" || e["tool_name"] != "read" || e["cwd"] == "" {
		t.Errorf("event = %v", e)
	}
	if in, _ := e["tool_input"].(map[string]any); in["path"] != "a.go" {
		t.Errorf("tool_input = %v", e["tool_input"])
	}
}

func TestPiExtensionBashASTMode(t *testing.T) {
	node := requireNodeTypeStripping(t)
	hookDir := t.TempDir()
	bin := filepath.Join(hookDir, "lite-sandbox")
	if err := os.WriteFile(bin, []byte(fakePiHook), 0o755); err != nil {
		t.Fatal(err)
	}
	res, events := runPiExtension(t, node, newPiPlan(true), bin, []piDriverCall{
		{ToolName: "mcp__lite_sandbox__bash", Input: map[string]any{"command": "c"}, HasUI: true},
	})
	if len(res.Servers) != 0 {
		t.Errorf("MCP server registered in --bash-ast-hook-mode: %v", res.Servers)
	}
	if len(res.Sections) != 0 {
		t.Errorf("directive added in --bash-ast-hook-mode: %v", res.Sections)
	}
	if len(events) != 0 {
		t.Errorf("hook ran for a tool it does not govern in this mode: %v", events)
	}
}

func TestPiExtensionMissingBinary(t *testing.T) {
	node := requireNodeTypeStripping(t)
	res, _ := runPiExtension(t, node, newPiPlan(false), filepath.Join(t.TempDir(), "missing"), []piDriverCall{
		{ToolName: "read", Input: map[string]any{"path": "a.go"}},
	})
	if e, _ := res.Results[0]["error"].(string); !strings.Contains(e, "could not run lite-sandbox hook") {
		t.Errorf("result = %v, want the call blocked", res.Results[0])
	}
}
