package mockedserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
)

// claudeSandboxTool is the sandbox bash tool under Claude Code's
// mcp__<server>__<tool> naming.
const claudeSandboxTool = "mcp__lite-sandbox__bash"

// TestClaudeCode drives Claude Code through `lite-sandbox install claude` and
// a non-interactive `claude -p`, pointed at the mock via ANTHROPIC_BASE_URL,
// in each install mode:
//
//   - default: the MCP server is loaded from the generated user config, the
//     sandbox tools are offered, the built-in Bash tool is gone (permission
//     deny), and the CLAUDE.md directive reached the model;
//   - --with-tool-hook: Bash stays offered but the PreToolUse hook blocks it
//     with a redirect, and a Write outside the writable paths is denied;
//   - --bash-ast-hook-mode: no MCP server; the hook validates Bash commands in
//     place, rejecting curl and letting echo run.
func TestClaudeCode(t *testing.T) {
	requireE2E(t)
	bash := func(command string) mockmodel.ToolCall {
		return mockmodel.ToolCall{Name: "Bash", Arguments: map[string]string{"command": command}}
	}
	t.Run("default", func(t *testing.T) {
		calls := sandboxCalls(claudeSandboxTool)
		model := runClaude(t, calls)
		tools := assertConversation(t, model.output, model.Server, calls, claudeSandboxTool, true)
		if tools["Bash"] {
			t.Errorf("built-in Bash tool still offered to the model despite the permission deny")
		}
		if !tools["Read"] {
			t.Errorf("unrelated built-in tools were hidden too")
		}
		assertDirective(t, model.Server, claudeSandboxTool)
	})
	t.Run("with-tool-hook", func(t *testing.T) {
		write := mockmodel.ToolCall{Name: "Write", Arguments: map[string]string{"file_path": outsidePath, "content": "denied"}}
		calls := append([]mockmodel.ToolCall{bash("echo built-in-shell"), write}, sandboxCalls(claudeSandboxTool)...)
		model := runClaude(t, calls, "--with-tool-hook")
		tools := assertConversation(t, model.output, model.Server, calls, claudeSandboxTool, true)
		if !tools["Bash"] {
			t.Errorf("built-in Bash tool should stay offered (the hook governs it) but was not")
		}
		results := lastResults(t, model.Server)
		assertResult(t, results, 0, hookBlockedShell)
		assertResult(t, results, 1, hookOutsideWritable)
	})
	t.Run("bash-ast-hook-mode", func(t *testing.T) {
		calls := []mockmodel.ToolCall{bash(blockedCommand), bash(allowedCommand)}
		model := runClaude(t, calls, "--bash-ast-hook-mode")
		assertConversation(t, model.output, model.Server, calls, claudeSandboxTool, false)
		assertResult(t, lastResults(t, model.Server), 0, hookRejectedCommand)
	})
}

// TestClaudeCodeLaunch drives `lite-sandbox launch claude`, the temporary
// alternative to `install`: the MCP server, permissions, hook, and usage
// directive reach Claude Code through its command line for this one run. The
// session must behave like the default install, and Claude Code's config must
// come back untouched.
func TestClaudeCodeLaunch(t *testing.T) {
	requireE2E(t)
	calls := sandboxCalls(claudeSandboxTool)
	model := startModel(t, calls)
	configDir, environ := claudeEnv(t, model)

	// No installSandbox: `launch` is the whole configuration.
	output := runAgent(t, newProject(t), environ, bins.sandbox,
		append([]string{"launch", "claude"}, "-p", "--output-format", "json", prompt)...)

	tools := assertConversation(t, output, model, calls, claudeSandboxTool, true)
	if tools["Bash"] {
		t.Errorf("built-in Bash tool still offered to the model despite the permission deny")
	}
	assertDirective(t, model, claudeSandboxTool)
	assertClaudeConfigUntouched(t, configDir)
}

// assertClaudeConfigUntouched checks that launch wrote none of the three
// things `install claude` writes: the usage directive in CLAUDE.md, the
// permissions and hook in settings.json, and the MCP server in .claude.json.
// (Claude Code writes .claude.json itself, so that one is checked for our
// server rather than for existence.)
func assertClaudeConfigUntouched(t *testing.T, configDir string) {
	t.Helper()
	for _, name := range []string{"CLAUDE.md", "settings.json"} {
		if data, err := os.ReadFile(filepath.Join(configDir, name)); err == nil {
			t.Errorf("launch wrote %s: %s", name, data)
		}
	}
	data, err := os.ReadFile(filepath.Join(configDir, ".claude.json"))
	if err != nil {
		return
	}
	var cfg struct {
		MCPServers map[string]any `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse .claude.json: %v", err)
	}
	if _, ok := cfg.MCPServers["lite-sandbox"]; ok {
		t.Errorf("launch persisted the MCP server into .claude.json: %s", data)
	}
}

// agentRun is one completed agent invocation: the mock that served it and the
// agent's output.
type agentRun struct {
	*mockmodel.Server
	output string
}

// runClaude installs lite-sandbox for Claude Code with installFlags into an
// isolated CLAUDE_CONFIG_DIR and runs `claude -p` once against a mock scripted
// with calls.
func runClaude(t *testing.T, calls []mockmodel.ToolCall, installFlags ...string) agentRun {
	t.Helper()
	model := startModel(t, calls)
	_, environ := claudeEnv(t, model)

	installSandbox(t, "claude", environ, installFlags...)

	output := runAgent(t, newProject(t), environ, bins.claude, "-p", "--output-format", "json", prompt)
	return agentRun{model, output}
}

// claudeEnv builds the environment for one Claude Code run against model, and
// returns the isolated config directory along with it.
//
// CLAUDE_CONFIG_DIR isolates everything Claude Code reads and writes
// (settings.json, CLAUDE.md, and .claude.json, which moves there too). The
// API key and base URL point it at the mock; the remaining variables keep
// it from calling home for updates, telemetry, or error reports.
func claudeEnv(t *testing.T, model *mockmodel.Server) (configDir string, environ []string) {
	t.Helper()
	configDir = t.TempDir()
	home := t.TempDir()
	return configDir, env(home,
		"CLAUDE_CONFIG_DIR="+configDir,
		"ANTHROPIC_BASE_URL="+model.URL,
		"ANTHROPIC_API_KEY=dummy",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"DISABLE_AUTOUPDATER=1",
		"DISABLE_TELEMETRY=1",
		"DISABLE_ERROR_REPORTING=1",
	)
}
