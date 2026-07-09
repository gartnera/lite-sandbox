package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// grokServers parses the mcp.servers array out of a user-settings.json file.
func grokServers(t *testing.T, path string) []grokMCPServer {
	t.Helper()
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, path)), &cfg); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}
	var mcp map[string]json.RawMessage
	if err := json.Unmarshal(cfg["mcp"], &mcp); err != nil {
		t.Fatalf("failed to parse mcp: %v", err)
	}
	var servers []grokMCPServer
	if err := json.Unmarshal(mcp["servers"], &servers); err != nil {
		t.Fatalf("failed to parse mcp.servers: %v", err)
	}
	return servers
}

func TestConfigureGrokMCPServerNewFile(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "user-settings.json")

	if err := configureGrokMCPServer(settingsPath, "/usr/local/bin/lite-sandbox"); err != nil {
		t.Fatalf("configureGrokMCPServer failed: %v", err)
	}

	servers := grokServers(t, settingsPath)
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	s := servers[0]
	if s.ID != "lite-sandbox" || s.Transport != "stdio" || !s.Enabled {
		t.Errorf("unexpected server config: %+v", s)
	}
	if s.Command != "/usr/local/bin/lite-sandbox" || len(s.Args) != 1 || s.Args[0] != "serve-mcp" {
		t.Errorf("unexpected command: %s %v", s.Command, s.Args)
	}
}

func TestConfigureGrokMCPServerPreservesExisting(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "user-settings.json")

	existing := `{
  "apiKey": "xai-secret",
  "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo hi"}]}]},
  "mcp": {
    "somethingElse": true,
    "servers": [
      {"id": "other", "label": "Other", "enabled": false, "transport": "http", "url": "https://example.com/mcp"}
    ]
  }
}`
	if err := os.WriteFile(settingsPath, []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing settings: %v", err)
	}

	if err := configureGrokMCPServer(settingsPath, "/opt/lite-sandbox"); err != nil {
		t.Fatalf("configureGrokMCPServer failed: %v", err)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, settingsPath)), &cfg); err != nil {
		t.Fatalf("failed to parse settings: %v", err)
	}
	if string(cfg["apiKey"]) != `"xai-secret"` {
		t.Errorf("unrelated top-level key lost, got %s", cfg["apiKey"])
	}
	if !strings.Contains(string(cfg["hooks"]), "SessionStart") {
		t.Errorf("unrelated hooks lost, got %s", cfg["hooks"])
	}
	var mcp map[string]json.RawMessage
	if err := json.Unmarshal(cfg["mcp"], &mcp); err != nil {
		t.Fatalf("failed to parse mcp: %v", err)
	}
	if string(mcp["somethingElse"]) != "true" {
		t.Errorf("unknown mcp field lost, got %s", mcp["somethingElse"])
	}

	servers := grokServers(t, settingsPath)
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers (other + lite-sandbox), got %d: %+v", len(servers), servers)
	}
	if servers[0].ID != "other" {
		t.Errorf("existing server not preserved in place: %+v", servers[0])
	}
	if servers[1].ID != "lite-sandbox" {
		t.Errorf("lite-sandbox server not appended: %+v", servers[1])
	}

	// The other server's fields (url) must survive the round-trip verbatim.
	if !strings.Contains(readFile(t, settingsPath), "https://example.com/mcp") {
		t.Error("existing server's url lost")
	}
}

func TestConfigureGrokMCPServerIsIdempotent(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "user-settings.json")

	if err := configureGrokMCPServer(settingsPath, "/first/lite-sandbox"); err != nil {
		t.Fatalf("first configureGrokMCPServer failed: %v", err)
	}
	if err := configureGrokMCPServer(settingsPath, "/second/lite-sandbox"); err != nil {
		t.Fatalf("second configureGrokMCPServer failed: %v", err)
	}

	content := readFile(t, settingsPath)
	if strings.Contains(content, "/first/lite-sandbox") {
		t.Errorf("stale command not replaced:\n%s", content)
	}

	servers := grokServers(t, settingsPath)
	if len(servers) != 1 {
		t.Fatalf("expected one lite-sandbox entry, got %d", len(servers))
	}
	if servers[0].Command != "/second/lite-sandbox" {
		t.Errorf("command not updated: %+v", servers[0])
	}
}

func TestConfigureGrokMCPServerRejectsInvalidJSON(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "user-settings.json")

	broken := "{ not json"
	if err := os.WriteFile(settingsPath, []byte(broken), 0644); err != nil {
		t.Fatalf("failed to write existing settings: %v", err)
	}

	if err := configureGrokMCPServer(settingsPath, "/bin/lite-sandbox"); err == nil {
		t.Fatal("expected error on unparseable settings, got nil")
	}
	if readFile(t, settingsPath) != broken {
		t.Error("unparseable settings were modified")
	}
}

// TestReconcileGrokHooks verifies the multi-matcher registration Grok needs
// (exact-match matchers, one group per tool) and that mode switches converge.
func TestReconcileGrokHooks(t *testing.T) {
	settingsPath := filepath.Join(t.TempDir(), "user-settings.json")
	binPath := "/usr/local/bin/lite-sandbox"
	hookCommand := binPath + " hook --format grok"

	matchersOf := func() map[string]string {
		t.Helper()
		var raw map[string]any
		if err := json.Unmarshal([]byte(readFile(t, settingsPath)), &raw); err != nil {
			t.Fatalf("parse settings: %v", err)
		}
		got := map[string]string{}
		for _, g := range asSlice(asMap(raw["hooks"])["PreToolUse"]) {
			group := asMap(g)
			for _, c := range asSlice(group["hooks"]) {
				got[asString(group["matcher"])] = asString(asMap(c)["command"])
			}
		}
		return got
	}

	// --with-tool-hook: one group per governed tool.
	if err := reconcilePreToolUseHook(settingsPath, binPath, hookCommand, grokToolMatchers...); err != nil {
		t.Fatalf("reconcile (tool hook) failed: %v", err)
	}
	got := matchersOf()
	if len(got) != len(grokToolMatchers) {
		t.Fatalf("expected %d matcher groups, got %v", len(grokToolMatchers), got)
	}
	for _, m := range grokToolMatchers {
		if got[m] != hookCommand {
			t.Errorf("matcher %q: expected %q, got %q", m, hookCommand, got[m])
		}
	}

	// Switch to bash-only: the file tool groups must be removed, not stacked.
	if err := reconcilePreToolUseHook(settingsPath, binPath, hookCommand, grokBashMatchers...); err != nil {
		t.Fatalf("reconcile (bash only) failed: %v", err)
	}
	got = matchersOf()
	if len(got) != 1 || got["bash"] != hookCommand {
		t.Fatalf("expected only the bash matcher after switch, got %v", got)
	}
}

func TestConfigureGrokAGENTSMD(t *testing.T) {
	tmpDir := t.TempDir()

	if err := configureGrokAGENTSMD(tmpDir); err != nil {
		t.Fatalf("configureGrokAGENTSMD failed: %v", err)
	}
	content := readFile(t, filepath.Join(tmpDir, "AGENTS.md"))
	if !strings.Contains(content, grokDirective) {
		t.Errorf("directive not written:\n%s", content)
	}
	if !strings.Contains(content, "mcp_lite-sandbox__bash") {
		t.Errorf("directive should reference Grok's MCP tool name:\n%s", content)
	}

	// Idempotent: running again does not duplicate.
	if err := configureGrokAGENTSMD(tmpDir); err != nil {
		t.Fatalf("configureGrokAGENTSMD failed on second run: %v", err)
	}
	content = readFile(t, filepath.Join(tmpDir, "AGENTS.md"))
	if got := strings.Count(content, grokDirective); got != 1 {
		t.Errorf("expected directive once, got %d", got)
	}
}

func TestGrokConfigDir(t *testing.T) {
	t.Setenv("HOME", "/home/someone")
	dir, err := grokConfigDir()
	if err != nil {
		t.Fatalf("grokConfigDir failed: %v", err)
	}
	if dir != filepath.Join("/home/someone", ".grok") {
		t.Errorf("unexpected config dir: %s", dir)
	}
}
