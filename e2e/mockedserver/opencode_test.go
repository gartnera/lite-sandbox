package mockedserver

import (
	"encoding/json"
	"maps"
	"path/filepath"
	"testing"

	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
)

// opencodeSandboxTool is the sandbox bash tool under opencode's <server>_<tool>
// naming.
const opencodeSandboxTool = "lite-sandbox_bash"

// TestOpencode drives opencode through `lite-sandbox install opencode` and a
// non-interactive `opencode run`. It proves opencode loads the generated
// global config, launches `lite-sandbox serve-mcp` and offers its tools, no
// longer runs the built-in bash tool (permission deny), executes the sandboxed
// commands and feeds the results back, and saw the AGENTS.md directive.
// opencode has no hook protocol, so there is a single install mode.
func TestOpencode(t *testing.T) {
	requireE2E(t)

	calls := sandboxCalls(opencodeSandboxTool)
	model := startModel(t, calls)
	_, project, environ := opencodeEnv(t, model, nil)

	installSandbox(t, "opencode", environ)

	output := runAgent(t, project, environ, bins.opencode, "run", "--format", "json", "-m", "mock/"+model.ModelID, prompt)

	tools := assertConversation(t, output, model, calls, opencodeSandboxTool, true)
	if tools["bash"] {
		t.Errorf("built-in bash tool still offered to the model despite the permission deny")
	}
	if !tools["read"] {
		t.Errorf("unrelated built-in tools were hidden too")
	}
	assertDirective(t, model, "`bash` tool from the `lite-sandbox` MCP server")
}

// opencodeEnv isolates opencode for one run against model and writes the
// global opencode.json a user would already have, plus extra keys. It returns
// opencode's config directory, a project directory, and the environment.
func opencodeEnv(t *testing.T, model *mockmodel.Server, extra map[string]any) (configDir, project string, environ []string) {
	t.Helper()
	// opencode follows the XDG layout for config, data, cache, and state; each
	// points at a temp directory so nothing of the real user's is read or
	// written. The provider half of opencode.json is what a user would already
	// have: the mock as an OpenAI-compatible provider (that provider package is
	// bundled, so no runtime install), with auto-update and sharing off.
	xdgConfig := t.TempDir()
	project = newProject(t)
	environ = env(t.TempDir(),
		"XDG_CONFIG_HOME="+xdgConfig,
		"XDG_DATA_HOME="+t.TempDir(),
		"XDG_CACHE_HOME="+t.TempDir(),
		"XDG_STATE_HOME="+t.TempDir(),
	)
	cfg := map[string]any{
		"$schema":     "https://opencode.ai/config.json",
		"autoupdate":  false,
		"share":       "disabled",
		"model":       "mock/" + model.ModelID,
		"small_model": "mock/" + model.ModelID,
		"provider": map[string]any{
			"mock": map[string]any{
				"npm":     "@ai-sdk/openai-compatible",
				"name":    "Mock",
				"options": map[string]any{"baseURL": model.BaseURL, "apiKey": "dummy"},
				"models":  map[string]any{model.ModelID: map[string]any{"name": "Mock"}},
			},
		},
	}
	maps.Copy(cfg, extra)
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	configDir = filepath.Join(xdgConfig, "opencode")
	writeFile(t, filepath.Join(configDir, "opencode.json"), string(b))
	return configDir, project, environ
}

// TestOpencodeLaunch drives `lite-sandbox launch opencode run ...`: the MCP
// server, the bash deny, and the directive reach opencode through
// OPENCODE_CONFIG_CONTENT, and its config directory is left as it was. The
// user's own instructions and AGENTS.md must still reach the model alongside
// the directive (the inline config's instructions are merged, not replacing
// theirs).
func TestOpencodeLaunch(t *testing.T) {
	requireE2E(t)
	calls := sandboxCalls(opencodeSandboxTool)
	model := startModel(t, calls)
	const instructionsMarker, agentsMarker = "USER-INSTRUCTIONS-MARKER", "USER-AGENTS-MARKER"
	userInstructions := filepath.Join(t.TempDir(), "rules.md")
	writeFile(t, userInstructions, instructionsMarker)
	configDir, project, environ := opencodeEnv(t, model, map[string]any{"instructions": []string{userInstructions}})
	writeFile(t, filepath.Join(configDir, "AGENTS.md"), agentsMarker)
	before := readFile(t, filepath.Join(configDir, "opencode.json"))

	output := runAgent(t, project, environ, bins.sandbox,
		"launch", "opencode", "run", "--format", "json", "-m", "mock/"+model.ModelID, prompt)

	tools := assertConversation(t, output, model, calls, opencodeSandboxTool, true)
	if tools["bash"] {
		t.Errorf("built-in bash tool still offered to the model despite the permission deny")
	}
	if !tools["read"] {
		t.Errorf("unrelated built-in tools were hidden too")
	}
	assertDirective(t, model, "`bash` tool from the `lite-sandbox` MCP server")
	assertDirective(t, model, instructionsMarker)
	assertDirective(t, model, agentsMarker)
	if after := readFile(t, filepath.Join(configDir, "opencode.json")); after != before {
		t.Errorf("launch changed opencode.json:\n%s", after)
	}
	if got := readFile(t, filepath.Join(configDir, "AGENTS.md")); got != agentsMarker {
		t.Errorf("launch changed AGENTS.md: %q", got)
	}
}
