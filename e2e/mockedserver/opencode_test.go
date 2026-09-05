package mockedserver

import (
	"encoding/json"
	"path/filepath"
	"testing"
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

	// opencode follows the XDG layout for config, data, cache, and state; each
	// points at a temp directory so nothing of the real user's is read or
	// written. The provider half of opencode.json is what a user would already
	// have: the mock as an OpenAI-compatible provider (that provider package is
	// bundled, so no runtime install), with auto-update and sharing off.
	configDir := t.TempDir()
	home := t.TempDir()
	project := newProject(t)
	environ := env(home,
		"XDG_CONFIG_HOME="+configDir,
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
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(configDir, "opencode", "opencode.json"), string(b))

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
