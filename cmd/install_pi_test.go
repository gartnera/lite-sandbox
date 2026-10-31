package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestPiVersionSupported(t *testing.T) {
	for _, tt := range []struct {
		out  string
		want bool
	}{
		{"1.4.0\n", true},
		{"1.0.0", true},
		{"2.0.0", true},
		{"0.99.2", false},
		{"0.73.1", false},
		{"dev", true},
	} {
		if got := piVersionSupported(tt.out); got != tt.want {
			t.Errorf("piVersionSupported(%q) = %v, want %v", tt.out, got, tt.want)
		}
	}
}

// renderedPiConfig renders the extension for the plan and returns the
// configuration it embeds.
func renderedPiConfig(t *testing.T, p piPlan) (string, piExtensionConfig) {
	t.Helper()
	src, err := renderPiExtension("/opt/bin/lite-sandbox", p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(src, piExtensionPlaceholder) {
		t.Fatal("placeholder left in the rendered extension")
	}
	const prefix = "const CONFIG: LiteSandboxConfig = "
	i := strings.Index(src, prefix)
	if i < 0 {
		t.Fatalf("no CONFIG in rendered extension:\n%s", src)
	}
	var cfg piExtensionConfig
	if err := json.NewDecoder(strings.NewReader(src[i+len(prefix):])).Decode(&cfg); err != nil {
		t.Fatalf("CONFIG is not JSON: %v", err)
	}
	return src, cfg
}

func TestRenderPiExtension(t *testing.T) {
	_, cfg := renderedPiConfig(t, newPiPlan(false))
	if cfg.Bin != "/opt/bin/lite-sandbox" || !cfg.MCP {
		t.Errorf("config = %+v", cfg)
	}
	if !slices.Equal(cfg.ServeArgs, []string{"serve-mcp", "--config-requests"}) {
		t.Errorf("serveArgs = %v", cfg.ServeArgs)
	}
	if !slices.Equal(cfg.HookArgs, []string{"hook", "--config-requests"}) {
		t.Errorf("hookArgs = %v", cfg.HookArgs)
	}
	for _, tool := range []string{"bash", "powershell", "read", "write", "edit", "grep", "find", "ls", "mcp__lite_sandbox__bash"} {
		if !slices.Contains(cfg.Tools, tool) {
			t.Errorf("tools %v missing %s", cfg.Tools, tool)
		}
	}
	if !strings.Contains(cfg.Directive, "mcp__lite_sandbox__bash") {
		t.Errorf("directive %q does not name the sandbox tool", cfg.Directive)
	}

	_, cfg = renderedPiConfig(t, newPiPlan(true))
	if cfg.MCP || cfg.Directive != "" || len(cfg.ServeArgs) != 0 {
		t.Errorf("--bash-ast-hook-mode config = %+v, want no MCP server or directive", cfg)
	}
	if !slices.Equal(cfg.HookArgs, []string{"hook", "--validate-bash"}) {
		t.Errorf("--bash-ast-hook-mode hookArgs = %v", cfg.HookArgs)
	}
	if slices.Contains(cfg.Tools, "mcp__lite_sandbox__bash") || !slices.Contains(cfg.Tools, "bash") {
		t.Errorf("--bash-ast-hook-mode tools = %v", cfg.Tools)
	}
}

func readPiSettings(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("settings.json is not JSON: %v\n%s", err, data)
	}
	return cfg
}

func TestConfigurePiSettings(t *testing.T) {
	mcp, ast := newPiPlan(false), newPiPlan(true)
	tests := []struct {
		name    string
		initial string // "" for no file
		plan    piPlan
		want    any // defaultTools after; nil for absent
	}{
		{"no file", "", mcp, []any{"-bash"}},
		{"no defaultTools", `{"theme":"dark"}`, mcp, []any{"-bash"}},
		{"modifiers", `{"defaultTools":["+grep","+bash"]}`, mcp, []any{"+grep", "-bash"}},
		{"plain names", `{"defaultTools":["read","bash","edit"]}`, mcp, []any{"read", "edit", "-bash"}},
		{"already", `{"defaultTools":["-bash"]}`, mcp, []any{"-bash"}},
		{"empty list left alone", `{"defaultTools":[]}`, mcp, []any{}},
		{"ast removes ours", `{"defaultTools":["-bash"]}`, ast, nil},
		{"ast keeps others", `{"defaultTools":["+grep","-bash"]}`, ast, []any{"+grep"}},
		{"ast no file", "", ast, nil},
		{"null", "null", mcp, []any{"-bash"}},
		{"bom", "\ufeff{\"defaultTools\":[\"+grep\"]}", mcp, []any{"+grep", "-bash"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "settings.json")
			if tt.initial != "" {
				if err := os.WriteFile(path, []byte(tt.initial), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := configurePiSettings(path, tt.plan); err != nil {
				t.Fatalf("configurePiSettings: %v", err)
			}
			if _, err := os.Stat(path); os.IsNotExist(err) {
				if tt.want != nil {
					t.Fatalf("settings.json not written, want defaultTools %v", tt.want)
				}
				return
			}
			cfg := readPiSettings(t, path)
			got, ok := cfg["defaultTools"]
			if tt.want == nil {
				if ok {
					t.Fatalf("defaultTools = %v, want absent", got)
				}
				return
			}
			gb, _ := json.Marshal(got)
			wb, _ := json.Marshal(tt.want)
			if string(gb) != string(wb) {
				t.Fatalf("defaultTools = %s, want %s", gb, wb)
			}
			if strings.Contains(tt.initial, "theme") && cfg["theme"] != "dark" {
				t.Errorf("other settings lost: %v", cfg)
			}
		})
	}
}

func TestConfigurePiSettingsReportsDisabledMCP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{"extensions":["-builtin:mcp"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	disabled, err := configurePiSettings(path, newPiPlan(false))
	if err != nil {
		t.Fatal(err)
	}
	if !disabled {
		t.Error("-builtin:mcp not reported")
	}
}

func TestRunInstallPi(t *testing.T) {
	home := t.TempDir()
	agentDir := filepath.Join(t.TempDir(), "pi-agent")
	t.Setenv("HOME", home)
	t.Setenv("PI_CODING_AGENT_DIR", agentDir)
	t.Setenv("PATH", t.TempDir()) // no pi on PATH: no version check

	if err := runInstallPi("/opt/bin/lite-sandbox"); err != nil {
		t.Fatalf("runInstallPi: %v", err)
	}
	ext := filepath.Join(agentDir, "extensions", piExtensionFile)
	src, err := os.ReadFile(ext)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `"bin": "/opt/bin/lite-sandbox"`) {
		t.Errorf("extension does not name the binary:\n%s", src)
	}
	if tools := readPiSettings(t, filepath.Join(agentDir, "settings.json"))["defaultTools"]; tools == nil {
		t.Error("built-in bash not disabled")
	}
	entries, err := os.ReadDir(home)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("installer wrote into HOME despite PI_CODING_AGENT_DIR: %v", entries)
	}
	if !detectPi() {
		t.Error("detectPi should see the PI_CODING_AGENT_DIR directory")
	}

	// Idempotent: a second run leaves the same files.
	settings, _ := os.ReadFile(filepath.Join(agentDir, "settings.json"))
	if err := runInstallPi("/opt/bin/lite-sandbox"); err != nil {
		t.Fatal(err)
	}
	settings2, _ := os.ReadFile(filepath.Join(agentDir, "settings.json"))
	src2, _ := os.ReadFile(ext)
	if string(settings) != string(settings2) || string(src) != string(src2) {
		t.Error("reinstalling changed the files")
	}

	// Switching to --bash-ast-hook-mode re-enables the built-in bash.
	installBashASTHookMode = true
	t.Cleanup(func() { installBashASTHookMode = false })
	if err := runInstallPi("/opt/bin/lite-sandbox"); err != nil {
		t.Fatal(err)
	}
	if tools, ok := readPiSettings(t, filepath.Join(agentDir, "settings.json"))["defaultTools"]; ok {
		t.Errorf("defaultTools = %v after --bash-ast-hook-mode, want absent", tools)
	}
	if src3, _ := os.ReadFile(ext); !strings.Contains(string(src3), "--validate-bash") {
		t.Error("extension not rewritten for --bash-ast-hook-mode")
	}
}

func TestRunInstallPiRefusesOldPi(t *testing.T) {
	pathDir := t.TempDir()
	t.Setenv("PATH", pathDir)
	t.Setenv("PI_CODING_AGENT_DIR", filepath.Join(t.TempDir(), "agent"))
	if err := os.WriteFile(filepath.Join(pathDir, "pi"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	orig := piVersionOutput
	piVersionOutput = func() (string, error) { return "0.73.1\n", nil }
	t.Cleanup(func() { piVersionOutput = orig })

	err := runInstallPi("/opt/bin/lite-sandbox")
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("err = %v, want too old", err)
	}
}
