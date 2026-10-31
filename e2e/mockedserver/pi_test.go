package mockedserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
)

// piSandboxTool is the sandbox bash tool under pi's MCP tool naming
// (mcp__<server>__<tool>, with the server name's - replaced by _).
const piSandboxTool = "mcp__lite_sandbox__bash"

// Fragments of the hook's pi-specific deny reasons (see cmd/hook.go).
const piHookAgentConfig = "inside a .pi directory"

// TestPi drives pi through `lite-sandbox install pi` and a non-interactive
// `pi -p`, in each install mode:
//
//   - default: the extension registers the MCP server and blocks pi's file
//     tools outside the sandbox. The mock first reads a file outside the
//     project and writes an extension into the project's .pi directory, and
//     the test checks the hook (run by the extension) denied both; then the
//     sandbox scenario runs through mcp__lite_sandbox__bash. The built-in bash
//     tool must not be offered, and the extension's system prompt section must
//     have reached the model.
//   - --bash-ast-hook-mode: no MCP server; the hook validates pi's own bash in
//     place, rejecting curl and letting echo run, and still confines reads.
func TestPi(t *testing.T) {
	requireE2E(t)
	t.Run("default", func(t *testing.T) {
		calls := append([]mockmodel.ToolCall{
			{Name: "read", Arguments: map[string]any{"path": outsideReadable}},
			{Name: "write", Arguments: map[string]any{"path": ".pi/extensions/evil.ts", "content": "export default function () {}\n"}},
		}, sandboxCalls(piSandboxTool)...)
		run := runPi(t, calls)
		tools := assertConversation(t, run.output, run.Server, calls, piSandboxTool, true)
		if tools["bash"] {
			t.Errorf("built-in bash tool still offered to the model")
		}
		if !tools["read"] {
			t.Errorf("unrelated built-in tools were hidden too")
		}
		results := lastResults(t, run.Server)
		assertResult(t, results, 0, hookOutsideReadable)
		assertResult(t, results, 1, piHookAgentConfig)
		if _, err := os.Stat(filepath.Join(run.project, ".pi", "extensions", "evil.ts")); err == nil {
			t.Errorf("the write into .pi went through despite the hook")
		}
		assertDirective(t, run.Server, piSandboxTool)
	})
	t.Run("bash-ast-hook-mode", func(t *testing.T) {
		calls := []mockmodel.ToolCall{
			{Name: "read", Arguments: map[string]any{"path": outsideReadable}},
			{Name: "bash", Arguments: map[string]any{"command": blockedCommand}},
			{Name: "bash", Arguments: map[string]any{"command": allowedCommand}},
		}
		run := runPi(t, calls, "--bash-ast-hook-mode")
		results := lastResults(t, run.Server)
		t.Logf("tool results fed back: %q", results)
		if len(results) != len(calls) {
			t.Fatalf("expected %d tool results, got %d", len(calls), len(results))
		}
		assertResult(t, results, 0, hookOutsideReadable)
		assertResult(t, results, 1, hookRejectedCommand)
		assertResult(t, results, 2, allowedOutput)
		if turns := run.Server.AgentTurns(); len(turns) > 0 && turns[0].Tools[piSandboxTool] {
			t.Errorf("sandbox MCP tool offered in --bash-ast-hook-mode")
		}
	})
}

type piRun struct {
	*mockmodel.Server
	output, project string
}

// runPi installs lite-sandbox for pi with installFlags into an isolated agent
// directory and runs `pi -p` once against a mock scripted with calls.
func runPi(t *testing.T, calls []mockmodel.ToolCall, installFlags ...string) piRun {
	t.Helper()
	model := startModel(t, calls)
	agentDir, project, environ := piEnv(t, model)

	installSandbox(t, "pi", environ, installFlags...)
	if data, err := os.ReadFile(filepath.Join(agentDir, "settings.json")); err == nil {
		t.Logf("settings.json:\n%s", data)
	}

	output := runAgent(t, project, environ, bins.pi, "-p", "--model", "mock/"+model.ModelID, prompt)
	return piRun{model, output, project}
}

// piEnv isolates pi for one run against model: PI_CODING_AGENT_DIR holds its
// settings, extensions, models, sessions and trust store, and models.json is
// what a user would already have, the mock as an OpenAI-compatible provider.
// It returns the agent directory, the project to run in, and the environment.
func piEnv(t *testing.T, model *mockmodel.Server) (agentDir, project string, environ []string) {
	t.Helper()
	agentDir = t.TempDir()
	home := t.TempDir()
	project = newProject(t)
	environ = env(home,
		"PI_CODING_AGENT_DIR="+agentDir,
		"XDG_CACHE_HOME="+t.TempDir(),
		"PI_OFFLINE=1",
		"PI_SKIP_VERSION_CHECK=1",
		"PI_TELEMETRY=0",
	)
	models := map[string]any{
		"providers": map[string]any{
			"mock": map[string]any{
				"baseUrl": model.BaseURL,
				"api":     "openai-completions",
				"apiKey":  "dummy",
				"models":  []any{map[string]any{"id": model.ModelID}},
			},
		},
	}
	b, err := json.MarshalIndent(models, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(agentDir, "models.json"), string(b))
	return agentDir, project, environ
}

// TestPiLaunch drives `lite-sandbox launch pi -p ...`: the extension, loaded
// with -e from lite-sandbox's cache, registers the MCP server, confines the
// file tools and adds the directive, --exclude-tools hides the built-in bash,
// and pi's agent directory is left as it was.
func TestPiLaunch(t *testing.T) {
	requireE2E(t)
	calls := append([]mockmodel.ToolCall{
		{Name: "read", Arguments: map[string]any{"path": outsideReadable}},
	}, sandboxCalls(piSandboxTool)...)
	model := startModel(t, calls)
	agentDir, project, environ := piEnv(t, model)

	output := runAgent(t, project, environ, bins.sandbox,
		"launch", "pi", "-p", "--model", "mock/"+model.ModelID, prompt)

	tools := assertConversation(t, output, model, calls, piSandboxTool, true)
	if tools["bash"] {
		t.Errorf("built-in bash tool still offered to the model")
	}
	if !tools["read"] {
		t.Errorf("unrelated built-in tools were hidden too")
	}
	assertResult(t, lastResults(t, model), 0, hookOutsideReadable)
	assertDirective(t, model, piSandboxTool)
	for _, name := range []string{"settings.json", "extensions"} {
		if _, err := os.Stat(filepath.Join(agentDir, name)); err == nil {
			t.Errorf("launch wrote %s into pi's agent directory", name)
		}
	}
}
