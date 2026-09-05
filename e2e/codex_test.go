package e2e

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/e2e/mockmodel"
)

// codexSandboxTool is the sandbox bash tool under Codex's MCP tool naming.
const codexSandboxTool = "mcp__lite_sandbox__bash"

// TestCodex drives Codex through `lite-sandbox install codex` and a
// non-interactive `codex exec`. Codex keeps its built-in shell tool, so the
// installer's PreToolUse hook is what redirects it: the mock first asks for a
// built-in shell command and the test checks the hook's denial came back, then
// the usual sandbox scenario runs through the MCP tool.
func TestCodex(t *testing.T) {
	requireE2E(t)

	hookCall := mockmodel.ToolCall{Name: "exec_command", Arguments: map[string]any{"cmd": "echo built-in-shell"}}
	calls := append([]mockmodel.ToolCall{hookCall}, sandboxCalls(codexSandboxTool)...)
	model := startModel(t, calls)

	// CODEX_HOME isolates Codex's config, auth, sessions, and logs. The
	// provider half of config.toml is what a user would already have; the
	// installer appends its MCP server table and hook block to the same file.
	codexHome := t.TempDir()
	home := t.TempDir()
	project := newProject(t)
	environ := env(home,
		"CODEX_HOME="+codexHome,
		"MOCK_API_KEY=dummy",
	)
	writeFile(t, filepath.Join(codexHome, "config.toml"), strings.Join([]string{
		`model = "` + model.ModelID + `"`,
		`model_provider = "mock"`,
		`check_for_update_on_startup = false`,
		``,
		`[analytics]`,
		`enabled = false`,
		``,
		`[model_providers.mock]`,
		`name = "Mock"`,
		`base_url = "` + model.BaseURL + `"`,
		`env_key = "MOCK_API_KEY"`,
		`wire_api = "responses"`,
		``,
	}, "\n"))

	installSandbox(t, "codex", environ)

	// Codex skips hooks it has not been told to trust (normally done in the TUI
	// via /hooks, which records the hook's hash); the bypass flag runs the
	// configured hooks for this invocation without that step.
	output := runAgent(t, project, environ, bins.codex, "exec",
		"--skip-git-repo-check", "--dangerously-bypass-hook-trust", "--json", "-C", project, prompt)

	assertConversation(t, output, model, calls, codexSandboxTool)
	results := model.AgentTurns()[len(model.AgentTurns())-1].ToolResults
	if !strings.Contains(results[0], "Blocked by lite-sandbox") {
		t.Errorf("hook did not block the built-in shell: %q", results[0])
	}
}
