package e2e

import (
	"testing"
)

// claudeSandboxTool is the sandbox bash tool under Claude Code's
// mcp__<server>__<tool> naming.
const claudeSandboxTool = "mcp__lite-sandbox__bash"

// TestClaudeCode drives Claude Code through `lite-sandbox install claude` and
// a non-interactive `claude -p`, pointed at the mock via ANTHROPIC_BASE_URL.
// It proves Claude Code loads the MCP server from the generated user config,
// offers the sandbox tools, no longer offers the denied built-in Bash tool,
// and feeds the sandbox's results back.
func TestClaudeCode(t *testing.T) {
	requireE2E(t)

	calls := sandboxCalls(claudeSandboxTool)
	model := startModel(t, calls)

	// CLAUDE_CONFIG_DIR isolates everything Claude Code reads and writes
	// (settings.json, CLAUDE.md, and .claude.json, which moves there too). The
	// API key and base URL point it at the mock; the remaining variables keep
	// it from calling home for updates, telemetry, or error reports.
	configDir := t.TempDir()
	home := t.TempDir()
	project := newProject(t)
	environ := env(home,
		"CLAUDE_CONFIG_DIR="+configDir,
		"ANTHROPIC_BASE_URL="+model.URL,
		"ANTHROPIC_API_KEY=dummy",
		"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1",
		"DISABLE_AUTOUPDATER=1",
		"DISABLE_TELEMETRY=1",
		"DISABLE_ERROR_REPORTING=1",
	)

	installSandbox(t, "claude", environ)

	output := runAgent(t, project, environ, bins.claude, "-p", "--output-format", "json", prompt)

	tools := assertConversation(t, output, model, calls, claudeSandboxTool)
	if tools["Bash"] {
		t.Errorf("built-in Bash tool still offered to the model despite the permission deny")
	}
	if !tools["Read"] {
		t.Errorf("unrelated built-in tools were hidden too")
	}
}
