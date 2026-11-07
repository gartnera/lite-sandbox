package mockedserver

import (
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
)

// bgMarker is what the background command prints; list_shells shows it in the
// command column.
const bgMarker = "bg-e2e-marker"

// backgroundAgent is one agent the background scenario runs against: tool is
// its name for the sandbox bash tool, and run drives it once against a mock
// scripted with calls.
type backgroundAgent struct {
	name string
	tool string
	run  func(t *testing.T, calls []mockmodel.ToolCall) (output string, model *mockmodel.Server)
}

var backgroundAgents = []backgroundAgent{
	{"claude", claudeSandboxTool, func(t *testing.T, calls []mockmodel.ToolCall) (string, *mockmodel.Server) {
		r := runClaude(t, calls)
		return r.output, r.Server
	}},
	{"codex", codexSandboxTool, func(t *testing.T, calls []mockmodel.ToolCall) (string, *mockmodel.Server) {
		r := runCodex(t, calls)
		return r.output, r.Server
	}},
	{"crush", crushSandboxTool, func(t *testing.T, calls []mockmodel.ToolCall) (string, *mockmodel.Server) {
		model := startModel(t, calls)
		_, project, environ := crushEnv(t, model, "crushrc")
		installSandbox(t, "crush", environ)
		return runAgent(t, project, environ, bins.crush, "run", "--quiet", "--verbose", "--cwd", project, prompt), model
	}},
	{"grok", grokSandboxTool, func(t *testing.T, calls []mockmodel.ToolCall) (string, *mockmodel.Server) {
		r := runGrok(t, calls)
		return r.output, r.Server
	}},
	{"opencode", opencodeSandboxTool, func(t *testing.T, calls []mockmodel.ToolCall) (string, *mockmodel.Server) {
		model := startModel(t, calls)
		_, project, environ := opencodeEnv(t, model, nil)
		installSandbox(t, "opencode", environ)
		return runAgent(t, project, environ, bins.opencode, "run", "--format", "json", "-m", "mock/"+model.ModelID, prompt), model
	}},
	{"pi", piSandboxTool, func(t *testing.T, calls []mockmodel.ToolCall) (string, *mockmodel.Server) {
		r := runPi(t, calls)
		return r.output, r.Server
	}},
}

// TestBackgroundCommands runs a background command through each agent and
// follows it with list_shells. None of these non-interactive runs gets MCP
// tasks (Claude Code only runs background commands as tasks in sessions that
// fetch feature flags, and `claude -p` never does), so each must get the
// shell id reply and be offered the control tools, which a client running
// background commands as tasks is not.
func TestBackgroundCommands(t *testing.T) {
	requireE2E(t)
	for _, agent := range backgroundAgents {
		t.Run(agent.name, func(t *testing.T) {
			prefix := strings.TrimSuffix(agent.tool, "bash")
			listShells, killShell := prefix+"list_shells", prefix+"kill_shell"
			calls := []mockmodel.ToolCall{
				{Name: agent.tool, Arguments: map[string]any{"command": "echo " + bgMarker, "run_in_background": true}},
				{Name: listShells, Arguments: map[string]any{}},
			}
			output, model := agent.run(t, calls)

			turns := model.AgentTurns()
			if len(turns) == 0 {
				t.Fatalf("no agent turns (protocols: %v)", protocols(model))
			}
			// Grok reaches MCP tools through its use_tool dispatcher, so only
			// agents that offer the sandbox tools directly are checked here; for
			// every agent the list_shells result below proves it was callable.
			if turns[0].Tools[agent.tool] {
				for _, tool := range []string{listShells, killShell} {
					if !turns[0].Tools[tool] {
						t.Errorf("%s not offered: the client should get the shell id path", tool)
					}
				}
			}
			results := lastResults(t, model)
			t.Logf("tool results fed back: %q", results)
			if len(results) != len(calls) {
				t.Fatalf("expected %d tool results, got %d", len(calls), len(results))
			}
			assertResult(t, results, 0, `shell id "bash_1"`)
			// The echo usually finishes before the next turn, but nothing
			// orders the two, so the listing may still show it running.
			assertResult(t, results, 1, "bash_1\t")
			assertResult(t, results, 1, "echo "+bgMarker)
			if !strings.Contains(results[1], "completed (exit 0)") && !strings.Contains(results[1], "running") {
				t.Errorf("list_shells shows neither running nor a clean exit: %q", results[1])
			}
			if !strings.Contains(output, finalPrefix) {
				t.Errorf("final answer missing from the agent's output")
			}
		})
	}
}
