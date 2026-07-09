package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func parseOpencodeConfig(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, path)), &cfg); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}
	return cfg
}

func TestConfigureOpencodeConfigNewFile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	if err := configureOpencodeConfig(configPath, "/usr/local/bin/lite-sandbox"); err != nil {
		t.Fatalf("configureOpencodeConfig failed: %v", err)
	}

	cfg := parseOpencodeConfig(t, configPath)

	var schema string
	if err := json.Unmarshal(cfg["$schema"], &schema); err != nil || schema != "https://opencode.ai/config.json" {
		t.Errorf("$schema not written, got %s", cfg["$schema"])
	}

	var mcp map[string]opencodeMCPLocal
	if err := json.Unmarshal(cfg["mcp"], &mcp); err != nil {
		t.Fatalf("failed to parse mcp: %v", err)
	}
	server, ok := mcp["lite-sandbox"]
	if !ok {
		t.Fatal("lite-sandbox server not found")
	}
	if server.Type != "local" || !server.Enabled {
		t.Errorf("unexpected server config: %+v", server)
	}
	if len(server.Command) != 2 || server.Command[0] != "/usr/local/bin/lite-sandbox" || server.Command[1] != "serve-mcp" {
		t.Errorf("unexpected command: %v", server.Command)
	}

	var perm map[string]json.RawMessage
	if err := json.Unmarshal(cfg["permission"], &perm); err != nil {
		t.Fatalf("failed to parse permission: %v", err)
	}
	if string(perm["bash"]) != `"deny"` {
		t.Errorf("built-in bash not denied, got %s", perm["bash"])
	}
	if string(perm["lite-sandbox*"]) != `"allow"` {
		t.Errorf("sandbox tools not auto-allowed, got %s", perm["lite-sandbox*"])
	}
}

func TestConfigureOpencodeConfigPreservesExisting(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	existing := `{
  "$schema": "https://opencode.ai/config.json",
  "model": "anthropic/claude-sonnet-4-5",
  "mcp": {
    "other": {"type": "remote", "url": "https://example.com/mcp"}
  },
  "permission": {
    "edit": "ask",
    "webfetch": {"https://example.com/*": "allow"}
  }
}`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureOpencodeConfig(configPath, "/opt/lite-sandbox"); err != nil {
		t.Fatalf("configureOpencodeConfig failed: %v", err)
	}

	cfg := parseOpencodeConfig(t, configPath)
	if string(cfg["model"]) != `"anthropic/claude-sonnet-4-5"` {
		t.Errorf("unrelated key lost, got %s", cfg["model"])
	}

	var mcp map[string]json.RawMessage
	if err := json.Unmarshal(cfg["mcp"], &mcp); err != nil {
		t.Fatalf("failed to parse mcp: %v", err)
	}
	if _, ok := mcp["other"]; !ok {
		t.Error("existing MCP server lost")
	}
	if _, ok := mcp["lite-sandbox"]; !ok {
		t.Error("lite-sandbox server not added")
	}

	var perm map[string]json.RawMessage
	if err := json.Unmarshal(cfg["permission"], &perm); err != nil {
		t.Fatalf("failed to parse permission: %v", err)
	}
	if string(perm["edit"]) != `"ask"` {
		t.Errorf("existing edit permission lost, got %s", perm["edit"])
	}
	if !strings.Contains(string(perm["webfetch"]), "https://example.com/*") {
		t.Errorf("existing granular permission lost, got %s", perm["webfetch"])
	}
	if string(perm["bash"]) != `"deny"` {
		t.Errorf("built-in bash not denied, got %s", perm["bash"])
	}
}

func TestConfigureOpencodeConfigIsIdempotent(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	if err := configureOpencodeConfig(configPath, "/first/lite-sandbox"); err != nil {
		t.Fatalf("first configureOpencodeConfig failed: %v", err)
	}
	if err := configureOpencodeConfig(configPath, "/second/lite-sandbox"); err != nil {
		t.Fatalf("second configureOpencodeConfig failed: %v", err)
	}

	content := readFile(t, configPath)
	if strings.Contains(content, "/first/lite-sandbox") {
		t.Errorf("stale command not replaced:\n%s", content)
	}
	if got := strings.Count(content, `"lite-sandbox":`); got != 1 {
		t.Errorf("expected one lite-sandbox server entry, got %d:\n%s", got, content)
	}

	cfg := parseOpencodeConfig(t, configPath)
	var mcp map[string]opencodeMCPLocal
	if err := json.Unmarshal(cfg["mcp"], &mcp); err != nil {
		t.Fatalf("failed to parse mcp: %v", err)
	}
	if mcp["lite-sandbox"].Command[0] != "/second/lite-sandbox" {
		t.Errorf("command not updated: %v", mcp["lite-sandbox"].Command)
	}
}

// TestConfigureOpencodeConfigPermissionString verifies that a bare-string
// permission config ("allow" applying to everything) is preserved as the
// catch-all "*" rule rather than being clobbered or rejected.
func TestConfigureOpencodeConfigPermissionString(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	if err := os.WriteFile(configPath, []byte(`{"permission": "allow"}`), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureOpencodeConfig(configPath, "/bin/lite-sandbox"); err != nil {
		t.Fatalf("configureOpencodeConfig failed: %v", err)
	}

	cfg := parseOpencodeConfig(t, configPath)
	var perm map[string]json.RawMessage
	if err := json.Unmarshal(cfg["permission"], &perm); err != nil {
		t.Fatalf("failed to parse permission: %v", err)
	}
	if string(perm["*"]) != `"allow"` {
		t.Errorf("global action not preserved as catch-all, got %s", perm["*"])
	}
	if string(perm["bash"]) != `"deny"` {
		t.Errorf("built-in bash not denied, got %s", perm["bash"])
	}
}

func TestConfigureOpencodeConfigRejectsInvalidJSON(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	jsonc := "{\n  // a comment encoding/json cannot parse\n  \"model\": \"x\"\n}\n"
	if err := os.WriteFile(configPath, []byte(jsonc), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureOpencodeConfig(configPath, "/bin/lite-sandbox"); err == nil {
		t.Fatal("expected error on JSONC content, got nil")
	}
	// The unparseable file must be left untouched.
	if readFile(t, configPath) != jsonc {
		t.Error("unparseable config was modified")
	}
}

func TestConfigureOpencodeAGENTSMD(t *testing.T) {
	tmpDir := t.TempDir()

	if err := configureOpencodeAGENTSMD(tmpDir); err != nil {
		t.Fatalf("configureOpencodeAGENTSMD failed: %v", err)
	}
	content := readFile(t, filepath.Join(tmpDir, "AGENTS.md"))
	if !strings.Contains(content, opencodeDirective) {
		t.Errorf("directive not written:\n%s", content)
	}

	// Idempotent: running again does not duplicate.
	if err := configureOpencodeAGENTSMD(tmpDir); err != nil {
		t.Fatalf("configureOpencodeAGENTSMD failed on second run: %v", err)
	}
	content = readFile(t, filepath.Join(tmpDir, "AGENTS.md"))
	if got := strings.Count(content, opencodeDirective); got != 1 {
		t.Errorf("expected directive once, got %d", got)
	}
}

func TestOpencodeConfigDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	dir, err := opencodeConfigDir()
	if err != nil {
		t.Fatalf("opencodeConfigDir failed: %v", err)
	}
	if dir != filepath.Join("/xdg", "opencode") {
		t.Errorf("XDG_CONFIG_HOME not honored, got %s", dir)
	}

	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", "/home/someone")
	dir, err = opencodeConfigDir()
	if err != nil {
		t.Fatalf("opencodeConfigDir failed: %v", err)
	}
	if dir != filepath.Join("/home/someone", ".config", "opencode") {
		t.Errorf("unexpected default dir: %s", dir)
	}
}
