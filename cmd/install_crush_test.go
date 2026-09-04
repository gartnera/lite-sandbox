package cmd

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureCrushRCNewFile(t *testing.T) {
	rcPath := filepath.Join(t.TempDir(), "crushrc")

	if err := configureCrushRC(rcPath, "/usr/local/bin/lite-sandbox"); err != nil {
		t.Fatalf("configureCrushRC failed: %v", err)
	}

	content := readFile(t, rcPath)
	for _, want := range []string{
		crushBlockStart,
		"mcp add lite-sandbox --type stdio --command /usr/local/bin/lite-sandbox --args serve-mcp\n",
		"permissions deny bash\n",
		"permissions allow mcp_lite-sandbox_bash mcp_lite-sandbox_bash_output mcp_lite-sandbox_kill_shell mcp_lite-sandbox_list_shells\n",
		crushBlockEnd,
	} {
		if !strings.Contains(content, want) {
			t.Errorf("missing %q in:\n%s", want, content)
		}
	}
}

// TestConfigureCrushRCQuotesPath verifies a binary path with shell-special
// characters is quoted so the crushrc (which Crush runs as Bash) sees it as a
// single word.
func TestConfigureCrushRCQuotesPath(t *testing.T) {
	rcPath := filepath.Join(t.TempDir(), "crushrc")

	if err := configureCrushRC(rcPath, "/opt/my tools/$weird/lite-sandbox"); err != nil {
		t.Fatalf("configureCrushRC failed: %v", err)
	}
	content := readFile(t, rcPath)
	if !strings.Contains(content, "--command '/opt/my tools/$weird/lite-sandbox' --args") {
		t.Errorf("path not shell-quoted:\n%s", content)
	}
}

func TestConfigureCrushRCPreservesExistingAndIsIdempotent(t *testing.T) {
	rcPath := filepath.Join(t.TempDir(), "crushrc")

	existing := "# my crush config\nprovider add ollama --type ollama --base-url http://localhost:11434/v1\npermissions allow view\n"
	if err := os.WriteFile(rcPath, []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing crushrc: %v", err)
	}

	if err := configureCrushRC(rcPath, "/first/lite-sandbox"); err != nil {
		t.Fatalf("first configureCrushRC failed: %v", err)
	}
	// Simulate the user appending content below our block, then re-run with a
	// new binary path.
	if err := os.WriteFile(rcPath, []byte(readFile(t, rcPath)+"\n# trailing user note\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := configureCrushRC(rcPath, "/second/lite-sandbox"); err != nil {
		t.Fatalf("second configureCrushRC failed: %v", err)
	}

	content := readFile(t, rcPath)
	if !strings.HasPrefix(content, existing) {
		t.Errorf("existing content not preserved at top:\n%s", content)
	}
	if !strings.Contains(content, "# trailing user note") {
		t.Errorf("user content after the block lost:\n%s", content)
	}
	if strings.Contains(content, "/first/lite-sandbox") {
		t.Errorf("stale command not replaced:\n%s", content)
	}
	if got := strings.Count(content, crushBlockStart); got != 1 {
		t.Errorf("expected exactly one managed block, got %d:\n%s", got, content)
	}
	if got := strings.Count(content, "permissions deny bash"); got != 1 {
		t.Errorf("expected one deny line, got %d:\n%s", got, content)
	}
	// The block must come last so `mcp add` overrides any earlier definition.
	if !strings.HasSuffix(strings.TrimSpace(content), crushBlockEnd) {
		t.Errorf("managed block is not at the end of the file:\n%s", content)
	}
}

func parseCrushJSON(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, path)), &cfg); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}
	return cfg
}

func rawStrings(t *testing.T, cfg map[string]json.RawMessage, section, key string) []string {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(cfg[section], &obj); err != nil {
		t.Fatalf("failed to parse %s: %v", section, err)
	}
	var list []string
	if raw, ok := obj[key]; ok {
		if err := json.Unmarshal(raw, &list); err != nil {
			t.Fatalf("failed to parse %s.%s: %v", section, key, err)
		}
	}
	return list
}

func TestConfigureCrushJSONNewFile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "crush.json")

	if err := configureCrushJSON(configPath, "/usr/local/bin/lite-sandbox"); err != nil {
		t.Fatalf("configureCrushJSON failed: %v", err)
	}

	cfg := parseCrushJSON(t, configPath)
	var schema string
	if err := json.Unmarshal(cfg["$schema"], &schema); err != nil || schema != crushSchemaURL {
		t.Errorf("$schema not written, got %s", cfg["$schema"])
	}

	var mcp map[string]crushMCPStdio
	if err := json.Unmarshal(cfg["mcp"], &mcp); err != nil {
		t.Fatalf("failed to parse mcp: %v", err)
	}
	server, ok := mcp["lite-sandbox"]
	if !ok {
		t.Fatal("lite-sandbox server not found")
	}
	if server.Type != "stdio" || server.Command != "/usr/local/bin/lite-sandbox" || len(server.Args) != 1 || server.Args[0] != "serve-mcp" {
		t.Errorf("unexpected server config: %+v", server)
	}

	if got := rawStrings(t, cfg, "options", "disabled_tools"); len(got) != 1 || got[0] != "bash" {
		t.Errorf("built-in bash not disabled, got %v", got)
	}
	if got := rawStrings(t, cfg, "permissions", "allowed_tools"); strings.Join(got, ",") != strings.Join(crushToolPermissions, ",") {
		t.Errorf("sandbox tools not auto-allowed, got %v", got)
	}
}

func TestConfigureCrushJSONPreservesExistingAndIsIdempotent(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "crush.json")

	existing := `{
  "$schema": "https://charm.land/crush.json",
  "models": {"large": {"model": "claude-sonnet-4-5", "provider": "anthropic"}},
  "mcp": {
    "other": {"type": "http", "url": "https://example.com/mcp"}
  },
  "options": {"debug": true, "disabled_tools": ["sourcegraph"]},
  "permissions": {"allowed_tools": ["view", "mcp_lite-sandbox_bash"]}
}`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureCrushJSON(configPath, "/first/lite-sandbox"); err != nil {
		t.Fatalf("first configureCrushJSON failed: %v", err)
	}
	if err := configureCrushJSON(configPath, "/second/lite-sandbox"); err != nil {
		t.Fatalf("second configureCrushJSON failed: %v", err)
	}

	cfg := parseCrushJSON(t, configPath)
	if !strings.Contains(string(cfg["models"]), "claude-sonnet-4-5") {
		t.Errorf("unrelated key lost, got %s", cfg["models"])
	}

	var mcp map[string]json.RawMessage
	if err := json.Unmarshal(cfg["mcp"], &mcp); err != nil {
		t.Fatalf("failed to parse mcp: %v", err)
	}
	if _, ok := mcp["other"]; !ok {
		t.Error("existing MCP server lost")
	}
	if !strings.Contains(string(mcp["lite-sandbox"]), "/second/lite-sandbox") || strings.Contains(string(mcp["lite-sandbox"]), "/first/") {
		t.Errorf("server command not updated: %s", mcp["lite-sandbox"])
	}

	var opts map[string]json.RawMessage
	if err := json.Unmarshal(cfg["options"], &opts); err != nil {
		t.Fatalf("failed to parse options: %v", err)
	}
	if string(opts["debug"]) != "true" {
		t.Errorf("existing option lost, got %s", opts["debug"])
	}
	if got := rawStrings(t, cfg, "options", "disabled_tools"); strings.Join(got, ",") != "sourcegraph,bash" {
		t.Errorf("disabled_tools not extended exactly once, got %v", got)
	}
	want := "view,mcp_lite-sandbox_bash,mcp_lite-sandbox_bash_output,mcp_lite-sandbox_kill_shell,mcp_lite-sandbox_list_shells"
	if got := rawStrings(t, cfg, "permissions", "allowed_tools"); strings.Join(got, ",") != want {
		t.Errorf("allowed_tools not extended without duplicates, got %v", got)
	}
}

func TestConfigureCrushJSONRejectsInvalidJSON(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "crush.json")

	bad := "{\n  // crush.json must be strict JSON\n  \"options\": {}\n}\n"
	if err := os.WriteFile(configPath, []byte(bad), 0644); err != nil {
		t.Fatal(err)
	}
	if err := configureCrushJSON(configPath, "/bin/lite-sandbox"); err == nil {
		t.Fatal("expected error on invalid JSON, got nil")
	}
	if readFile(t, configPath) != bad {
		t.Error("unparseable config was modified")
	}
}

func TestConfigureCrushCRUSHMD(t *testing.T) {
	tmpDir := t.TempDir()

	if err := configureCrushCRUSHMD(tmpDir); err != nil {
		t.Fatalf("configureCrushCRUSHMD failed: %v", err)
	}
	if err := configureCrushCRUSHMD(tmpDir); err != nil {
		t.Fatalf("configureCrushCRUSHMD failed on second run: %v", err)
	}
	content := readFile(t, filepath.Join(tmpDir, "CRUSH.md"))
	if got := strings.Count(content, crushDirective); got != 1 {
		t.Errorf("expected directive once, got %d:\n%s", got, content)
	}
}

func TestCrushConfigDir(t *testing.T) {
	t.Setenv("CRUSH_GLOBAL_CONFIG", "/crush-global")
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	if dir, err := crushConfigDir(); err != nil || dir != "/crush-global" {
		t.Errorf("CRUSH_GLOBAL_CONFIG not honored, got %s (%v)", dir, err)
	}

	t.Setenv("CRUSH_GLOBAL_CONFIG", "")
	if dir, err := crushConfigDir(); err != nil || dir != filepath.Join("/xdg", "crush") {
		t.Errorf("XDG_CONFIG_HOME not honored, got %s (%v)", dir, err)
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/someone")
	if dir, err := crushConfigDir(); err != nil || dir != filepath.Join("/home/someone", ".config", "crush") {
		t.Errorf("unexpected default dir: %s (%v)", dir, err)
	}
}

func TestCrushVersionSupportsRC(t *testing.T) {
	tests := []struct {
		out  string
		want bool
	}{
		{"crush version v0.92.0\n", true},
		{"crush version v0.88.0", true},
		{"crush version v1.0.0", true},
		{"crush version v0.87.3", false},
		{"v0.9.1", false},
		{"crush version devel", true}, // unparseable: assume current
		{"", true},
	}
	for _, tt := range tests {
		if got := crushVersionSupportsRC(tt.out); got != tt.want {
			t.Errorf("crushVersionSupportsRC(%q) = %v, want %v", tt.out, got, tt.want)
		}
	}
}

// TestRunInstallCrushChoosesConfigFile verifies which global config file the
// install edits: an existing crushrc (preferred), else an existing crush.json,
// else a new crushrc — or a new crush.json when the installed crush predates
// the crushrc format.
func TestRunInstallCrushChoosesConfigFile(t *testing.T) {
	orig := crushVersionOutput
	t.Cleanup(func() { crushVersionOutput = orig })

	tests := []struct {
		name     string
		existing []string // files to pre-create in the config dir
		version  string   // stubbed `crush --version` output ("" = not on PATH)
		wantRC   bool
	}{
		{"neither, current crush", nil, "crush version v0.92.0", true},
		{"neither, old crush", nil, "crush version v0.85.0", false},
		{"neither, crush not on PATH", nil, "", true},
		{"crushrc exists, old crush", []string{"crushrc"}, "crush version v0.85.0", true},
		{"crush.json exists, current crush", []string{"crush.json"}, "crush version v0.92.0", false},
		{"both exist", []string{"crushrc", "crush.json"}, "crush version v0.92.0", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("CRUSH_GLOBAL_CONFIG", dir)
			for _, f := range tt.existing {
				content := "# keep me\n"
				if f == "crush.json" {
					content = "{}"
				}
				if err := os.WriteFile(filepath.Join(dir, f), []byte(content), 0644); err != nil {
					t.Fatal(err)
				}
			}
			crushVersionOutput = func() (string, error) {
				if tt.version == "" {
					return "", errors.New("not found")
				}
				return tt.version, nil
			}

			if err := runInstallCrush("/bin/lite-sandbox"); err != nil {
				t.Fatalf("runInstallCrush failed: %v", err)
			}

			rc := readFileIfExists(t, filepath.Join(dir, "crushrc"))
			js := readFileIfExists(t, filepath.Join(dir, "crush.json"))
			if tt.wantRC {
				if !strings.Contains(rc, crushBlockStart) {
					t.Errorf("expected crushrc to be configured, got:\n%s", rc)
				}
				if strings.Contains(js, "lite-sandbox") {
					t.Errorf("crush.json unexpectedly modified:\n%s", js)
				}
			} else {
				if !strings.Contains(js, `"lite-sandbox"`) {
					t.Errorf("expected crush.json to be configured, got:\n%s", js)
				}
				if rc != "" {
					t.Errorf("crushrc unexpectedly written:\n%s", rc)
				}
			}
			for _, f := range tt.existing {
				if f == "crushrc" && !strings.Contains(rc, "# keep me") {
					t.Error("existing crushrc content lost")
				}
			}
			if !strings.Contains(readFileIfExists(t, filepath.Join(dir, "CRUSH.md")), crushDirective) {
				t.Error("CRUSH.md directive not written")
			}
		})
	}
}

// TestRunInstallCrushSkipsInBashASTHookMode verifies --bash-ast-hook-mode
// leaves Crush's config untouched (there is no hook over its built-in shell).
func TestRunInstallCrushSkipsInBashASTHookMode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CRUSH_GLOBAL_CONFIG", dir)
	installBashASTHookMode = true
	defer func() { installBashASTHookMode = false }()

	if err := runInstallCrush("/bin/lite-sandbox"); err != nil {
		t.Fatalf("runInstallCrush failed: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no files written, got %d", len(entries))
	}
}

func readFileIfExists(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return string(data)
}
