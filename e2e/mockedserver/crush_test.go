package mockedserver

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/e2e/mockedserver/mockmodel"
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

	configDir, project, environ := crushEnv(t, model, format)

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

// crushEnv isolates Crush for one run against model and writes the user's own
// global config in format (crushrc or crush.json). It returns the global
// config directory, a project directory, and the environment.
func crushEnv(t *testing.T, model *mockmodel.Server, format string) (configDir, project string, environ []string) {
	t.Helper()
	// Isolate Crush completely: config dir, data dir, and HOME all point at
	// temp directories, so the real user's config is never read or written.
	configDir = t.TempDir()
	dataDir := t.TempDir()
	project = newProject(t)
	environ = env(t.TempDir(),
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
	return configDir, project, environ
}

// TestCrushLaunch drives `lite-sandbox launch crush run ...`. Crush is pointed
// at a stand-in global config directory that loads the user's own (their
// crushrc sourced, their crush.json linked) and adds the sandbox's rules, so:
// the user's provider — which lives only in their config — must still work,
// the sandbox tools replace the built-in bash, the directive and the user's
// own CRUSH.md both reach the model, and the user's directory is unchanged.
func TestCrushLaunch(t *testing.T) {
	requireE2E(t)
	for _, format := range []string{"crushrc", "crush.json"} {
		t.Run(format, func(t *testing.T) {
			calls := sandboxCalls(crushSandboxTool)
			model := startModel(t, calls)
			configDir, project, environ := crushEnv(t, model, format)
			const memoryMarker = "USER-CRUSH-MD-MARKER"
			writeFile(t, filepath.Join(configDir, "CRUSH.md"), memoryMarker)
			before := snapshotDir(t, configDir)

			output := runAgent(t, project, environ, bins.sandbox,
				"launch", "crush", "run", "--quiet", "--verbose", "--cwd", project, prompt)

			tools := assertConversation(t, output, model, calls, crushSandboxTool, true)
			if tools["bash"] {
				t.Errorf("built-in bash tool still offered to the model")
			}
			if !tools["view"] {
				t.Errorf("unrelated built-in tools were hidden too")
			}
			assertDirective(t, model, crushSandboxTool)
			assertDirective(t, model, memoryMarker)
			if after := snapshotDir(t, configDir); !maps.Equal(before, after) {
				t.Errorf("launch changed the user's config directory: %v -> %v", slices.Sorted(maps.Keys(before)), slices.Sorted(maps.Keys(after)))
			}
		})
	}
}

// snapshotDir maps each regular file directly in dir to its content.
func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.Type().IsRegular() {
			out[e.Name()] = readFile(t, filepath.Join(dir, e.Name()))
		}
	}
	return out
}
