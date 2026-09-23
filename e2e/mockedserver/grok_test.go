package mockedserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
	"github.com/pelletier/go-toml/v2"
)

// grokSandboxTool is the sandbox bash tool under Grok's MCP tool naming. Grok
// does not offer MCP tools to the model directly: it calls them through the
// use_tool dispatcher with this qualified name.
const (
	grokSandboxTool = "lite-sandbox__bash"
	grokUseTool     = "use_tool"
)

// grokSandboxCalls scripts the sandbox scenario as use_tool calls.
func grokSandboxCalls() []mockmodel.ToolCall {
	var calls []mockmodel.ToolCall
	for _, c := range sandboxCalls(grokSandboxTool) {
		calls = append(calls, mockmodel.ToolCall{Name: grokUseTool, Arguments: map[string]any{"tool_name": c.Name, "tool_input": c.Arguments}})
	}
	return calls
}

func grokShell(command string) mockmodel.ToolCall {
	return mockmodel.ToolCall{Name: "run_terminal_command", Arguments: map[string]any{"command": command, "description": "run it"}}
}

// TestGrok drives Grok Build through `lite-sandbox install grok` and a
// headless `grok -p`, in each install mode:
//
//   - default: the mock first asks for the built-in shell and for a file read
//     outside the project, and the test checks the hook denied both; then the
//     sandbox scenario runs through use_tool (which the installer's permission
//     rule must approve, since headless Grok cannot prompt), and the rules-file
//     directive must have reached the model;
//   - --bash-ast-hook-mode: no MCP server; the hook validates shell commands in
//     place, rejecting curl and letting echo run, and still confines file reads.
func TestGrok(t *testing.T) {
	requireE2E(t)
	t.Run("default", func(t *testing.T) {
		secret := secretOutsideProject(t)
		calls := append([]mockmodel.ToolCall{
			grokShell("echo built-in-shell"),
			{Name: "read_file", Arguments: map[string]any{"target_file": secret}},
			// Over Grok's 128 KiB hook payload limit, so the hook gets a
			// clipped string instead of the path and must deny.
			{Name: "write", Arguments: map[string]any{"file_path": outsidePath, "content": strings.Repeat("x", 140*1024)}},
		}, grokSandboxCalls()...)
		model := runGrok(t, calls)
		assertConversation(t, model.output, model.Server, calls, grokUseTool, true)
		results := lastResults(t, model.Server)
		assertResult(t, results, 0, grokHookBlockedShell)
		assertResult(t, results, 1, hookOutsideReadable)
		assertResult(t, results, 2, grokHookTruncated)
		if _, err := os.Stat(outsidePath); err == nil {
			t.Errorf("%s was written despite the hook", outsidePath)
		}
		assertDirective(t, model.Server, "lite-sandbox__bash")
	})
	t.Run("bash-ast-hook-mode", func(t *testing.T) {
		secret := secretOutsideProject(t)
		calls := []mockmodel.ToolCall{
			{Name: "read_file", Arguments: map[string]any{"target_file": secret}},
			grokShell(blockedCommand),
			grokShell(allowedCommand),
		}
		model := runGrok(t, calls, "--bash-ast-hook-mode")
		results := lastResults(t, model.Server)
		t.Logf("tool results fed back: %q", results)
		if len(results) != len(calls) {
			t.Fatalf("expected %d tool results, got %d", len(calls), len(results))
		}
		assertResult(t, results, 0, hookOutsideReadable)
		assertResult(t, results, 1, hookRejectedCommand)
		assertResult(t, results, 2, allowedOutput)
	})
}

// Grok-specific fragments of the hook's deny reasons (see cmd/hook.go).
const (
	grokHookBlockedShell = "the built-in run_terminal_command tool is disabled"
	hookOutsideReadable  = "outside the sandbox's readable paths"
	grokHookTruncated    = "over Grok's 128 KiB hook limit"
)

// secretOutsideProject writes a file outside any directory the sandbox grants
// and returns its path.
func secretOutsideProject(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret.txt")
	writeFile(t, p, "do-not-read")
	return p
}

// runGrok installs lite-sandbox for Grok with installFlags into an isolated
// GROK_HOME and runs `grok -p` once against a mock scripted with calls.
func runGrok(t *testing.T, calls []mockmodel.ToolCall, installFlags ...string) agentRun {
	t.Helper()
	model := startModel(t, calls)

	// GROK_HOME isolates Grok's config, hooks, rules, sessions, and logs. The
	// model half of config.toml is what a user would already have; the
	// installer adds its MCP server and permission rules to the same file.
	grokHome := t.TempDir()
	home := t.TempDir()
	project := newProject(t)
	environ := env(home,
		"GROK_HOME="+grokHome,
		"MOCK_API_KEY=dummy",
	)
	cfg := map[string]any{
		"models": map[string]any{"default": "mock"},
		"model": map[string]any{
			"mock": map[string]any{
				"model":       model.ModelID,
				"base_url":    model.BaseURL,
				"env_key":     "MOCK_API_KEY",
				"api_backend": "chat_completions",
			},
		},
	}
	b, err := toml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(grokHome, "config.toml"), string(b))

	installSandbox(t, "grok", environ, installFlags...)
	for _, f := range []string{"config.toml", "hooks/lite-sandbox.json"} {
		if data, err := os.ReadFile(filepath.Join(grokHome, f)); err == nil {
			t.Logf("%s:\n%s", f, data)
		}
	}

	output := runAgent(t, project, environ, bins.grok, "-p", prompt, "--cwd", project)
	return agentRun{model, output}
}
