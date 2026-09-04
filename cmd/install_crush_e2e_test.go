package cmd

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/internal/mockopenai"
)

// TestCrushEndToEnd drives a real crush binary through `lite-sandbox install
// crush` and a non-interactive `crush run`, with the mockopenai server
// standing in for the LLM. The mock asks Crush to call mcp_lite-sandbox_bash,
// so the run proves that Crush (1) loads the generated config, (2) launches
// `lite-sandbox serve-mcp` and exposes its tools under Crush's
// mcp_<server>_<tool> names, (3) no longer offers the built-in bash tool, and
// (4) executes the sandboxed commands and feeds the results back.
//
// It always compiles but only runs when CRUSH_E2E_TESTS is set and both a
// `crush` binary (on PATH, or at $CRUSH_BIN) and the built `lite-sandbox`
// binary at the repo root are present.
func TestCrushEndToEnd(t *testing.T) {
	if os.Getenv("CRUSH_E2E_TESTS") == "" {
		t.Skip("requires a crush binary; set CRUSH_E2E_TESTS=1 (and optionally CRUSH_BIN) to run")
	}
	crushBin := os.Getenv("CRUSH_BIN")
	if crushBin == "" {
		var err error
		if crushBin, err = exec.LookPath("crush"); err != nil {
			t.Skip("crush not on PATH and CRUSH_BIN unset")
		}
	}
	sandboxBin, err := filepath.Abs(filepath.Join("..", "lite-sandbox"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(sandboxBin); err != nil {
		t.Skipf("lite-sandbox binary not built at %s (run `go build -o lite-sandbox` first)", sandboxBin)
	}

	for _, format := range []string{"crushrc", "crush.json"} {
		t.Run(format, func(t *testing.T) {
			runCrushEndToEnd(t, crushBin, sandboxBin, format)
		})
	}
}

// mockCommands is the scripted sequence of sandbox commands the mock model
// asks for, one per agent turn: first a command the sandbox must reject (curl
// is not whitelisted), then one it must run.
var mockCommands = []string{"curl http://example.com", "echo hello-from-sandbox"}

func runCrushEndToEnd(t *testing.T, crushBin, sandboxBin, format string) {
	var calls []mockopenai.ToolCall
	for _, command := range mockCommands {
		calls = append(calls, mockopenai.ToolCall{Name: "mcp_lite-sandbox_bash", Arguments: map[string]string{"command": command}})
	}
	model := mockopenai.Start(mockopenai.Script{
		ToolCalls: calls,
		FinalText: func(results []string) string {
			return "The sandbox printed: " + strings.TrimSpace(results[len(results)-1])
		},
	})
	defer model.Close()

	// Isolate Crush completely: its config dir, data dir, and HOME all point at
	// temp directories, so the real user's config is never read or written.
	configDir := t.TempDir()
	dataDir := t.TempDir()
	home := t.TempDir()
	project := t.TempDir()
	t.Setenv("CRUSH_GLOBAL_CONFIG", configDir)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	// The provider/model half of the config is what a user would already have.
	// Crush will only use the mock; provider auto-update and metrics are off so
	// the run makes no network calls beyond our server.
	baseURL := model.BaseURL
	switch format {
	case "crushrc":
		rc := strings.Join([]string{
			"# user config",
			"provider add mock --type openai-compat --base-url " + baseURL + " --api-key dummy",
			"model add mock/mock-model --name Mock --context-window 128000 --default-max-tokens 4096",
			"model large mock/mock-model",
			"model small mock/mock-model",
			"option provider-auto-update false",
			"option metrics false",
			"option notifications disabled",
			"",
		}, "\n")
		if err := os.WriteFile(filepath.Join(configDir, "crushrc"), []byte(rc), 0644); err != nil {
			t.Fatal(err)
		}
	case "crush.json":
		cfg := map[string]any{
			"providers": map[string]any{
				"mock": map[string]any{
					"type": "openai-compat", "base_url": baseURL, "api_key": "dummy",
					"models": []any{map[string]any{"id": "mock-model", "name": "Mock", "context_window": 128000, "default_max_tokens": 4096}},
				},
			},
			"models": map[string]any{
				"large": map[string]any{"provider": "mock", "model": "mock-model"},
				"small": map[string]any{"provider": "mock", "model": "mock-model"},
			},
			"options": map[string]any{"disable_provider_auto_update": true, "disable_metrics": true, "notifications": "disabled"},
		}
		b, _ := json.MarshalIndent(cfg, "", "  ")
		if err := os.WriteFile(filepath.Join(configDir, "crush.json"), b, 0644); err != nil {
			t.Fatal(err)
		}
	}

	// The install under test.
	if err := runInstallCrush(sandboxBin); err != nil {
		t.Fatalf("runInstallCrush failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "crushrc")); (err == nil) != (format == "crushrc") {
		t.Fatalf("install edited the wrong config file for %s", format)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, crushBin, "run", "--quiet", "--verbose", "--cwd", project,
		"Run the command echo hello-from-sandbox and tell me what it printed.")
	cmd.Env = append(os.Environ(),
		"HOME="+home,
		"CRUSH_GLOBAL_CONFIG="+configDir,
		"CRUSH_GLOBAL_DATA="+dataDir,
		"XDG_DATA_HOME="+dataDir,
		"XDG_CONFIG_HOME=",
		"NO_COLOR=1",
	)
	out, err := cmd.CombinedOutput()
	output := string(out)
	if err != nil {
		t.Fatalf("crush run failed: %v\n%s", err, output)
	}
	t.Logf("crush output:\n%s", output)

	if !strings.Contains(output, "The sandbox printed: hello-from-sandbox") {
		t.Errorf("final answer missing the sandboxed command's output:\n%s", output)
	}

	turns := model.AgentRequests()
	if want := len(mockCommands) + 1; len(turns) < want {
		t.Fatalf("expected at least %d agent turns (%d tool calls + answer), got %d", want, len(mockCommands), len(turns))
	}
	tools := turns[0].ToolNames()
	t.Logf("tools offered on the first agent turn: %v", slices.Sorted(maps.Keys(tools)))
	for _, want := range crushToolPermissions {
		if !tools[want] {
			t.Errorf("sandbox tool %s not offered to the model; tools: %v", want, slices.Sorted(maps.Keys(tools)))
		}
	}
	if tools["bash"] {
		t.Errorf("built-in bash tool still offered to the model; tools: %v", slices.Sorted(maps.Keys(tools)))
	}
	if !tools["view"] {
		t.Errorf("unrelated built-in tools were hidden too; tools: %v", slices.Sorted(maps.Keys(tools)))
	}

	// The tool results Crush fed back must show the sandbox enforcing its
	// whitelist (curl rejected) and running the allowed command.
	results := turns[len(turns)-1].ToolResults()
	t.Logf("tool results fed back: %q", results)
	if len(results) != len(mockCommands) {
		t.Fatalf("expected %d tool results, got %d", len(mockCommands), len(results))
	}
	if !strings.Contains(results[0], `command "curl" is not allowed`) {
		t.Errorf("sandbox did not reject curl: %q", results[0])
	}
	if got := results[1]; strings.TrimSpace(got) != "hello-from-sandbox" {
		t.Errorf("tool result is not the sandbox's output: %q", got)
	}
}
