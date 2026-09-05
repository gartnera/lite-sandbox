package e2e

import (
	"path/filepath"
	"testing"

	"github.com/gartnera/lite-sandbox/e2e/mockmodel"
	"github.com/pelletier/go-toml/v2"
)

// codexSandboxTool is the sandbox bash tool under Codex's MCP tool naming.
const codexSandboxTool = "mcp__lite_sandbox__bash"

// TestCodex drives Codex through `lite-sandbox install codex` and a
// non-interactive `codex exec`, in each install mode:
//
//   - default: Codex keeps its built-in shell tool, so the installer's
//     PreToolUse hook is what redirects it. The mock first asks for a built-in
//     shell command and the test checks the hook's denial came back; then the
//     usual sandbox scenario runs through the MCP tool, and the AGENTS.md
//     directive must have reached the model;
//   - --bash-ast-hook-mode: no MCP server; the hook validates shell commands in
//     place, rejecting curl and letting echo run.
func TestCodex(t *testing.T) {
	requireE2E(t)
	shell := func(command string) mockmodel.ToolCall {
		return mockmodel.ToolCall{Name: "exec_command", Arguments: map[string]any{"cmd": command}}
	}
	t.Run("default", func(t *testing.T) {
		calls := append([]mockmodel.ToolCall{shell("echo built-in-shell")}, sandboxCalls(codexSandboxTool)...)
		model := runCodex(t, calls)
		assertConversation(t, model.output, model.Server, calls, codexSandboxTool, true)
		assertResult(t, lastResults(t, model.Server), 0, hookBlockedShell)
		assertDirective(t, model.Server, "`lite-sandbox` MCP server")
	})
	t.Run("bash-ast-hook-mode", func(t *testing.T) {
		calls := []mockmodel.ToolCall{shell(blockedCommand), shell(allowedCommand)}
		model := runCodex(t, calls, "--bash-ast-hook-mode")
		assertConversation(t, model.output, model.Server, calls, codexSandboxTool, false)
		assertResult(t, lastResults(t, model.Server), 0, hookRejectedCommand)
	})
}

// runCodex installs lite-sandbox for Codex with installFlags into an isolated
// CODEX_HOME and runs `codex exec` once against a mock scripted with calls.
func runCodex(t *testing.T, calls []mockmodel.ToolCall, installFlags ...string) agentRun {
	t.Helper()
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
	cfg := map[string]any{
		"model":                       model.ModelID,
		"model_provider":              "mock",
		"check_for_update_on_startup": false,
		"analytics":                   map[string]any{"enabled": false},
		"model_providers": map[string]any{
			"mock": map[string]any{"name": "Mock", "base_url": model.BaseURL, "env_key": "MOCK_API_KEY", "wire_api": "responses"},
		},
	}
	b, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(codexHome, "config.toml"), string(b))

	installSandbox(t, "codex", environ, installFlags...)

	// Codex skips hooks it has not been told to trust (normally done in the TUI
	// via /hooks, which records the hook's hash); the bypass flag runs the
	// configured hooks for this invocation without that step. Codex's own
	// sandbox for the built-in shell is turned off: lite-sandbox's hook is what
	// is under test here, and Codex's Linux sandbox (bubblewrap) needs
	// unprivileged user namespaces that CI runners may not grant.
	output := runAgent(t, project, environ, bins.codex, "exec",
		"--skip-git-repo-check", "--dangerously-bypass-hook-trust", "--sandbox", "danger-full-access",
		"--json", "-C", project, prompt)
	return agentRun{model, output}
}
