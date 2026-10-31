package mockedserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
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
	_, project, environ := codexEnv(t, model)

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

// codexEnv isolates Codex for one run against model: a CODEX_HOME whose
// config.toml holds the provider half a user would already have, a project
// directory, and the environment to run in.
func codexEnv(t *testing.T, model *mockmodel.Server) (codexHome, project string, environ []string) {
	t.Helper()
	// CODEX_HOME isolates Codex's config, auth, sessions, and logs.
	codexHome = t.TempDir()
	project = newProject(t)
	environ = env(t.TempDir(),
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
	return codexHome, project, environ
}

// TestCodexLaunch drives `lite-sandbox launch codex exec ...`: the MCP server,
// directive, and (in the hook modes) the PreToolUse hook reach Codex as
// command-line overrides, with nothing written to its config.toml.
//
//   - default: the built-in shell is removed outright (--disable shell_tool),
//     so the model is not even offered exec_command, and the sandbox scenario
//     runs through the MCP tool. The default --with-tool-hook only matches
//     apply_patch and the file tools here, which the mock model isn't offered;
//   - --bash-ast-hook-mode: no MCP server, and the hook validates the shell in
//     place. This proves a hook passed with -c runs: launch adds the trust
//     bypass Codex needs for it (the test passes none of its own).
func TestCodexLaunch(t *testing.T) {
	requireE2E(t)
	shell := func(command string) mockmodel.ToolCall {
		return mockmodel.ToolCall{Name: "exec_command", Arguments: map[string]any{"cmd": command}}
	}
	launch := func(t *testing.T, calls []mockmodel.ToolCall, launchFlags ...string) (agentRun, string) {
		model := startModel(t, calls)
		codexHome, project, environ := codexEnv(t, model)
		before := readFile(t, filepath.Join(codexHome, "config.toml"))
		args := append([]string{"launch"}, launchFlags...)
		args = append(args, "codex", "exec", "--skip-git-repo-check", "--sandbox", "danger-full-access", "--json", "-C", project, prompt)
		output := runAgent(t, project, environ, bins.sandbox, args...)
		// Codex itself records the project's trust in config.toml; what must not
		// appear is anything of lite-sandbox's.
		after := readFile(t, filepath.Join(codexHome, "config.toml"))
		if !strings.HasPrefix(after, strings.TrimRight(before, "\n")) || strings.Contains(after, "lite-sandbox") {
			t.Errorf("launch changed config.toml:\n%s", after)
		}
		if _, err := os.Stat(filepath.Join(codexHome, "AGENTS.md")); err == nil {
			t.Error("launch wrote AGENTS.md")
		}
		return agentRun{model, output}, codexHome
	}

	t.Run("default", func(t *testing.T) {
		calls := sandboxCalls(codexSandboxTool)
		run, _ := launch(t, calls)
		tools := assertConversation(t, run.output, run.Server, calls, codexSandboxTool, true)
		if tools["exec_command"] {
			t.Error("built-in shell still offered despite --disable shell_tool")
		}
		assertDirective(t, run.Server, "built-in shell tool is disabled for this session")
	})
	t.Run("bash-ast-hook-mode", func(t *testing.T) {
		calls := []mockmodel.ToolCall{shell(blockedCommand), shell(allowedCommand)}
		run, _ := launch(t, calls, "--bash-ast-hook-mode")
		assertConversation(t, run.output, run.Server, calls, codexSandboxTool, false)
		assertResult(t, lastResults(t, run.Server), 0, hookRejectedCommand)
	})
}
