package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// crushSandboxTool is the sandbox bash tool under Crush's mcp_<server>_<tool>
// naming.
const crushSandboxTool = "mcp_lite-sandbox_bash"

// TestCrush drives Crush through `lite-sandbox install crush` and a
// non-interactive `crush run`. It proves Crush (1) loads the generated config,
// (2) launches `lite-sandbox serve-mcp` and exposes its tools, (3) no longer
// offers the built-in bash tool, and (4) executes the sandboxed commands and
// feeds the results back. Both config formats the installer can edit are
// covered: the current crushrc and the legacy crush.json.
func TestCrush(t *testing.T) {
	requireE2E(t)
	for _, format := range []string{"crushrc", "crush.json"} {
		t.Run(format, func(t *testing.T) { runCrush(t, format) })
	}
}

func runCrush(t *testing.T, format string) {
	calls := sandboxCalls(crushSandboxTool)
	model := startModel(t, calls)

	// Isolate Crush completely: config dir, data dir, and HOME all point at
	// temp directories, so the real user's config is never read or written.
	configDir := t.TempDir()
	dataDir := t.TempDir()
	home := t.TempDir()
	project := newProject(t)
	environ := env(home,
		"CRUSH_GLOBAL_CONFIG="+configDir,
		"CRUSH_GLOBAL_DATA="+dataDir,
		"XDG_DATA_HOME="+dataDir,
	)

	// The provider/model half of the config is what a user would already have.
	// Provider auto-update and metrics are off so the run makes no network
	// calls beyond the mock.
	switch format {
	case "crushrc":
		writeFile(t, filepath.Join(configDir, "crushrc"), strings.Join([]string{
			"# user config",
			"provider add mock --type openai-compat --base-url " + model.BaseURL + " --api-key dummy",
			"model add mock/" + model.ModelID + " --name Mock --context-window 128000 --default-max-tokens 4096",
			"model large mock/" + model.ModelID,
			"model small mock/" + model.ModelID,
			"option provider-auto-update false",
			"option metrics false",
			"option notifications disabled",
			"",
		}, "\n"))
	case "crush.json":
		cfg := map[string]any{
			"providers": map[string]any{
				"mock": map[string]any{
					"type": "openai-compat", "base_url": model.BaseURL, "api_key": "dummy",
					"models": []any{map[string]any{"id": model.ModelID, "name": "Mock", "context_window": 128000, "default_max_tokens": 4096}},
				},
			},
			"models": map[string]any{
				"large": map[string]any{"provider": "mock", "model": model.ModelID},
				"small": map[string]any{"provider": "mock", "model": model.ModelID},
			},
			"options": map[string]any{"disable_provider_auto_update": true, "disable_metrics": true, "notifications": "disabled"},
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		writeFile(t, filepath.Join(configDir, "crush.json"), string(b))
	}

	installSandbox(t, "crush", environ)
	if _, err := os.Stat(filepath.Join(configDir, "crushrc")); (err == nil) != (format == "crushrc") {
		t.Fatalf("install edited the wrong config file for %s", format)
	}

	output := runAgent(t, project, environ, bins.crush, "run", "--quiet", "--verbose", "--cwd", project, prompt)

	tools := assertConversation(t, output, model, calls, crushSandboxTool, true)
	if tools["bash"] {
		t.Errorf("built-in bash tool still offered to the model")
	}
	if !tools["view"] {
		t.Errorf("unrelated built-in tools were hidden too")
	}
	assertDirective(t, model, crushSandboxTool)
}
