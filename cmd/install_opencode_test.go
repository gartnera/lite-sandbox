package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tailscale/hujson"
)

func parseOpencodeConfig(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal([]byte(readFile(t, path)), &cfg); err != nil {
		t.Fatalf("failed to parse %s: %v", path, err)
	}
	return cfg
}

// parseJSONCConfig strips comments/trailing commas from a JSONC file and
// unmarshals the result, so tests can assert on the effective config.
func parseJSONCConfig(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	std, err := hujson.Standardize([]byte(readFile(t, path)))
	if err != nil {
		t.Fatalf("failed to standardize %s: %v", path, err)
	}
	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(std, &cfg); err != nil {
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

// TestConfigureOpencodeJSONCPreservesComments verifies that editing an
// opencode.jsonc keeps the user's comments and other keys, while adding the
// sandbox entries. The result must still parse once comments are stripped.
func TestConfigureOpencodeJSONCPreservesComments(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.jsonc")

	existing := `{
  // pick the model I like
  "model": "anthropic/claude-sonnet-4-5",
  "mcp": {
    // an existing remote server
    "other": {"type": "remote", "url": "https://example.com/mcp"}
  },
  "permission": {
    "edit": "ask", // careful with edits
  }
}`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureOpencodeJSONC(configPath, "/opt/lite-sandbox"); err != nil {
		t.Fatalf("configureOpencodeJSONC failed: %v", err)
	}

	raw := readFile(t, configPath)
	if !strings.Contains(raw, "// pick the model I like") {
		t.Errorf("top-level comment lost:\n%s", raw)
	}
	if !strings.Contains(raw, "// careful with edits") {
		t.Errorf("nested comment lost:\n%s", raw)
	}

	cfg := parseJSONCConfig(t, configPath)
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
	var server opencodeMCPLocal
	if err := json.Unmarshal(mcp["lite-sandbox"], &server); err != nil {
		t.Fatalf("lite-sandbox server not added/parseable: %v", err)
	}
	if server.Type != "local" || !server.Enabled || len(server.Command) != 2 || server.Command[0] != "/opt/lite-sandbox" {
		t.Errorf("unexpected server config: %+v", server)
	}

	var perm map[string]json.RawMessage
	if err := json.Unmarshal(cfg["permission"], &perm); err != nil {
		t.Fatalf("failed to parse permission: %v", err)
	}
	if string(perm["edit"]) != `"ask"` {
		t.Errorf("existing edit permission lost, got %s", perm["edit"])
	}
	if string(perm["bash"]) != `"deny"` {
		t.Errorf("built-in bash not denied, got %s", perm["bash"])
	}
	if string(perm["lite-sandbox*"]) != `"allow"` {
		t.Errorf("sandbox tools not auto-allowed, got %s", perm["lite-sandbox*"])
	}
}

// TestConfigureOpencodeJSONCStringPermission verifies a bare-string permission
// in a .jsonc is preserved as the catch-all "*" rule.
func TestConfigureOpencodeJSONCStringPermission(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.jsonc")

	if err := os.WriteFile(configPath, []byte("{\n  // everything allowed\n  \"permission\": \"allow\"\n}\n"), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureOpencodeJSONC(configPath, "/bin/lite-sandbox"); err != nil {
		t.Fatalf("configureOpencodeJSONC failed: %v", err)
	}

	cfg := parseJSONCConfig(t, configPath)
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

// TestConfigureOpencodeJSONCIsIdempotent verifies re-running rewrites the same
// entries without duplicating the server.
func TestConfigureOpencodeJSONCIsIdempotent(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.jsonc")
	if err := os.WriteFile(configPath, []byte("{\n  // hi\n}\n"), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureOpencodeJSONC(configPath, "/first/lite-sandbox"); err != nil {
		t.Fatalf("first configureOpencodeJSONC failed: %v", err)
	}
	if err := configureOpencodeJSONC(configPath, "/second/lite-sandbox"); err != nil {
		t.Fatalf("second configureOpencodeJSONC failed: %v", err)
	}

	content := readFile(t, configPath)
	if strings.Contains(content, "/first/lite-sandbox") {
		t.Errorf("stale command not replaced:\n%s", content)
	}
	if got := strings.Count(content, `"lite-sandbox":`); got != 1 {
		t.Errorf("expected one lite-sandbox server entry, got %d:\n%s", got, content)
	}
	if !strings.Contains(content, "// hi") {
		t.Errorf("comment lost across idempotent runs:\n%s", content)
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

// opencodeV2Config is the subset of an opencode v2 config the tests inspect.
type opencodeV2Config struct {
	Schema string `json:"$schema"`
	MCP    struct {
		Servers map[string]opencodeV2MCPLocal `json:"servers"`
	} `json:"mcp"`
	Permission  map[string]json.RawMessage `json:"permission"`
	Permissions []opencodeV2Rule           `json:"permissions"`
}

func parseOpencodeV2Config(t *testing.T, path string) (opencodeV2Config, map[string]json.RawMessage) {
	t.Helper()
	raw := parseJSONCConfig(t, path)
	b, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var cfg opencodeV2Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatalf("failed to parse %s as a v2 config: %v", path, err)
	}
	return cfg, raw
}

// assertOpencodeV2Rules checks the permissions array ends with our rules, once.
func assertOpencodeV2Rules(t *testing.T, rules []opencodeV2Rule) {
	t.Helper()
	n := len(opencodeV2Rules)
	if len(rules) < n || !slices.Equal(rules[len(rules)-n:], opencodeV2Rules) {
		t.Fatalf("permissions do not end with the sandbox rules: %+v", rules)
	}
	for _, r := range rules[:len(rules)-n] {
		if slices.Contains(opencodeV2Rules, r) {
			t.Errorf("sandbox rule %+v duplicated: %+v", r, rules)
		}
	}
}

func TestConfigureOpencodeV2NewFile(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")

	if err := configureOpencodeV2(configPath, "/usr/local/bin/lite-sandbox", false); err != nil {
		t.Fatalf("configureOpencodeV2 failed: %v", err)
	}
	if !json.Valid([]byte(readFile(t, configPath))) {
		t.Fatalf("opencode.json is not plain JSON:\n%s", readFile(t, configPath))
	}

	cfg, raw := parseOpencodeV2Config(t, configPath)
	if cfg.Schema != "https://opencode.ai/config.json" {
		t.Errorf("$schema not written, got %q", cfg.Schema)
	}
	server, ok := cfg.MCP.Servers["lite-sandbox"]
	if !ok {
		t.Fatalf("lite-sandbox server not under mcp.servers: %s", raw["mcp"])
	}
	if server.Type != "local" || !slices.Equal(server.Command, []string{"/usr/local/bin/lite-sandbox", "serve-mcp"}) {
		t.Errorf("unexpected server config: %+v", server)
	}
	if _, ok := raw["permission"]; ok {
		t.Errorf("v1 permission map written in v2 mode: %s", raw["permission"])
	}
	assertOpencodeV2Rules(t, cfg.Permissions)
}

// TestConfigureOpencodeV2CodeMode verifies a new server entry is left on v2's
// Code Mode default (no codemode key), while a codemode choice the user made
// on an earlier entry survives a re-install.
func TestConfigureOpencodeV2CodeMode(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")
	if err := configureOpencodeV2(configPath, "/bin/lite-sandbox", false); err != nil {
		t.Fatalf("configureOpencodeV2 failed: %v", err)
	}
	if strings.Contains(readFile(t, configPath), "codemode") {
		t.Errorf("codemode written:\n%s", readFile(t, configPath))
	}

	if err := os.WriteFile(configPath, []byte(`{"mcp": {"servers": {"lite-sandbox": {"type": "local", "command": ["/old"], "codemode": false}}}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := configureOpencodeV2(configPath, "/bin/lite-sandbox", false); err != nil {
		t.Fatalf("configureOpencodeV2 failed: %v", err)
	}
	cfg, _ := parseOpencodeV2Config(t, configPath)
	var raw struct {
		MCP struct {
			Servers map[string]map[string]json.RawMessage `json:"servers"`
		} `json:"mcp"`
	}
	if err := json.Unmarshal([]byte(readFile(t, configPath)), &raw); err != nil {
		t.Fatal(err)
	}
	if got := string(raw.MCP.Servers["lite-sandbox"]["codemode"]); got != "false" {
		t.Errorf("user's codemode not kept, got %q", got)
	}
	if cfg.MCP.Servers["lite-sandbox"].Command[0] != "/bin/lite-sandbox" {
		t.Errorf("command not updated: %+v", cfg.MCP.Servers["lite-sandbox"])
	}
}

// TestConfigureOpencodeV2KeepsUserRulesAndAppends verifies existing servers and
// rules survive, and the sandbox rules land after a user rule that would
// otherwise re-allow the shell (v2 applies the last matching rule).
func TestConfigureOpencodeV2KeepsUserRulesAndAppends(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")
	existing := `{
  "$schema": "https://opencode.ai/config.json",
  "model": {"providerID": "anthropic", "model": "claude"},
  "mcp": {
    "servers": {
      "other": {"type": "remote", "url": "https://example.com/mcp"}
    }
  },
  "permissions": [
    {"action": "shell", "resource": "*", "effect": "deny"},
    {"action": "shell", "resource": "git status *", "effect": "allow"},
    {"action": "edit", "resource": "*", "effect": "ask"}
  ]
}`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	if err := configureOpencodeV2(configPath, "/opt/lite-sandbox", false); err != nil {
		t.Fatalf("configureOpencodeV2 failed: %v", err)
	}

	cfg, raw := parseOpencodeV2Config(t, configPath)
	if !strings.Contains(string(raw["model"]), `"claude"`) {
		t.Errorf("unrelated key lost, got %s", raw["model"])
	}
	if _, ok := cfg.MCP.Servers["other"]; !ok {
		t.Error("existing MCP server lost")
	}
	if _, ok := cfg.MCP.Servers["lite-sandbox"]; !ok {
		t.Error("lite-sandbox server not added")
	}
	want := []opencodeV2Rule{
		{Action: "shell", Resource: "git status *", Effect: "allow"},
		{Action: "edit", Resource: "*", Effect: "ask"},
	}
	want = append(want, opencodeV2Rules...)
	if !slices.Equal(cfg.Permissions, want) {
		t.Errorf("permissions = %+v, want %+v", cfg.Permissions, want)
	}
}

// TestConfigureOpencodeV2MigratesV1Install verifies a v1 install's entries are
// replaced by their v2 equivalents while the user's own v1 keys stay.
func TestConfigureOpencodeV2MigratesV1Install(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")
	if err := os.WriteFile(configPath, []byte(`{"permission": {"edit": "ask"}, "mcp": {"other": {"type": "remote", "url": "https://example.com/mcp"}}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := configureOpencodeConfig(configPath, "/v1/lite-sandbox"); err != nil {
		t.Fatalf("v1 install failed: %v", err)
	}

	if err := configureOpencodeV2(configPath, "/v2/lite-sandbox", false); err != nil {
		t.Fatalf("configureOpencodeV2 failed: %v", err)
	}

	content := readFile(t, configPath)
	if strings.Contains(content, "/v1/lite-sandbox") {
		t.Errorf("v1 server entry left behind:\n%s", content)
	}
	cfg, raw := parseOpencodeV2Config(t, configPath)
	var mcp map[string]json.RawMessage
	if err := json.Unmarshal(raw["mcp"], &mcp); err != nil {
		t.Fatal(err)
	}
	if _, ok := mcp["other"]; !ok {
		t.Error("user's v1 MCP server lost")
	}
	if _, ok := mcp["lite-sandbox"]; ok {
		t.Error("v1 mcp.lite-sandbox not removed")
	}
	if cfg.MCP.Servers["lite-sandbox"].Command[0] != "/v2/lite-sandbox" {
		t.Errorf("v2 server not written: %+v", cfg.MCP.Servers)
	}
	if string(cfg.Permission["edit"]) != `"ask"` {
		t.Errorf("user's v1 permission lost: %v", cfg.Permission)
	}
	if _, ok := cfg.Permission["bash"]; ok {
		t.Error("v1 permission.bash not removed")
	}
	if _, ok := cfg.Permission["lite-sandbox*"]; ok {
		t.Error(`v1 permission."lite-sandbox*" not removed`)
	}
	assertOpencodeV2Rules(t, cfg.Permissions)
}

// TestConfigureOpencodeV2DropsEmptyV1PermissionMap verifies a permission map
// holding only the v1 install's rules is removed rather than left empty.
func TestConfigureOpencodeV2DropsEmptyV1PermissionMap(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")
	if err := configureOpencodeConfig(configPath, "/bin/lite-sandbox"); err != nil {
		t.Fatal(err)
	}
	if err := configureOpencodeV2(configPath, "/bin/lite-sandbox", false); err != nil {
		t.Fatalf("configureOpencodeV2 failed: %v", err)
	}
	if _, raw := parseOpencodeV2Config(t, configPath); raw["permission"] != nil {
		t.Errorf("empty v1 permission map left behind: %s", raw["permission"])
	}
}

func TestConfigureOpencodeV2IsIdempotent(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")
	if err := configureOpencodeV2(configPath, "/first/lite-sandbox", false); err != nil {
		t.Fatal(err)
	}
	// The user adds rules around ours after the first install; a re-install
	// must move ours back to the end without duplicating them.
	var cfg map[string]any
	if err := json.Unmarshal([]byte(readFile(t, configPath)), &cfg); err != nil {
		t.Fatal(err)
	}
	rules := cfg["permissions"].([]any)
	rules = append([]any{map[string]any{"action": "*", "resource": "*", "effect": "allow"}}, rules...)
	cfg["permissions"] = append(rules, map[string]any{"action": "shell", "resource": "*", "effect": "allow"})
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, b, 0644); err != nil {
		t.Fatal(err)
	}
	if err := configureOpencodeV2(configPath, "/second/lite-sandbox", false); err != nil {
		t.Fatal(err)
	}

	content := readFile(t, configPath)
	if strings.Contains(content, "/first/lite-sandbox") {
		t.Errorf("stale command not replaced:\n%s", content)
	}
	if got := strings.Count(content, `"lite-sandbox":`); got != 1 {
		t.Errorf("expected one lite-sandbox server entry, got %d:\n%s", got, content)
	}
	got, _ := parseOpencodeV2Config(t, configPath)
	want := []opencodeV2Rule{
		{Action: "*", Resource: "*", Effect: "allow"},
		{Action: "shell", Resource: "*", Effect: "allow"},
	}
	want = append(want, opencodeV2Rules...)
	if !slices.Equal(got.Permissions, want) {
		t.Errorf("permissions = %+v, want %+v", got.Permissions, want)
	}
}

func TestConfigureOpencodeV2JSONCPreservesComments(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.jsonc")
	existing := `{
  // pick the model I like
  "model": {"providerID": "anthropic", "model": "claude"},
  "permissions": [
    // ask before edits
    {"action": "edit", "resource": "*", "effect": "ask"},
  ],
}`
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}
	if err := configureOpencodeV2(configPath, "/opt/lite-sandbox", true); err != nil {
		t.Fatalf("configureOpencodeV2 failed: %v", err)
	}

	content := readFile(t, configPath)
	for _, c := range []string{"// pick the model I like", "// ask before edits"} {
		if !strings.Contains(content, c) {
			t.Errorf("comment %q lost:\n%s", c, content)
		}
	}
	cfg, _ := parseOpencodeV2Config(t, configPath)
	if _, ok := cfg.MCP.Servers["lite-sandbox"]; !ok {
		t.Error("lite-sandbox server not added")
	}
	if cfg.Permissions[0] != (opencodeV2Rule{Action: "edit", Resource: "*", Effect: "ask"}) {
		t.Errorf("user rule lost: %+v", cfg.Permissions)
	}
	assertOpencodeV2Rules(t, cfg.Permissions)
}

func TestConfigureOpencodeV2RejectsJSONCInJSON(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")
	jsonc := "{\n  // a comment\n  \"model\": \"x\"\n}\n"
	if err := os.WriteFile(configPath, []byte(jsonc), 0644); err != nil {
		t.Fatal(err)
	}
	if err := configureOpencodeV2(configPath, "/bin/lite-sandbox", false); err == nil {
		t.Fatal("expected an error on JSONC content in opencode.json")
	}
	if readFile(t, configPath) != jsonc {
		t.Error("unparseable config was modified")
	}
}

func TestConfigureOpencodeV2RejectsNonArrayPermissions(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "opencode.json")
	if err := os.WriteFile(configPath, []byte(`{"permissions": {"shell": "allow"}}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := configureOpencodeV2(configPath, "/bin/lite-sandbox", false); err == nil {
		t.Fatal("expected an error when permissions is not an array")
	}
}

func TestOpencodeMajorVersion(t *testing.T) {
	for out, want := range map[string]int{
		"1.18.29\n":       1,
		"2.2.5\n":         2,
		"opencode v2.0.0": 2,
		"local\n":         0,
		"":                0,
		"10.0.1-beta.3\n": 10,
		"0.15.3\n":        0,
	} {
		if got := opencodeMajorVersion(out); got != want {
			t.Errorf("opencodeMajorVersion(%q) = %d, want %d", out, got, want)
		}
	}
}

func TestDetectOpencodeConfigVersion(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	v1 := write("v1.json", `{"mcp": {"x": {"type": "local", "command": ["x"]}}, "permission": {"bash": "deny"}}`)
	v2Perms := write("v2-perms.jsonc", "{\n  // c\n  \"permissions\": [],\n}")
	v2Servers := write("v2-servers.json", `{"mcp": {"servers": {"x": {"type": "local", "command": ["x"]}}}}`)
	legacyServers := write("legacy-servers.json", `{"mcp": {"servers": {"type": "local", "command": ["x"]}}}`)
	missing := filepath.Join(dir, "missing.json")

	stub := func(out string, err error) {
		orig := opencodeVersionOutput
		opencodeVersionOutput = func() (string, error) { return out, err }
		t.Cleanup(func() { opencodeVersionOutput = orig })
	}

	tests := []struct {
		name    string
		out     string
		err     error
		configs []string
		want    opencodeConfigVersion
	}{
		{"v2 binary", "2.2.5\n", nil, []string{v1}, opencodeConfigV2},
		{"v1 binary wins over v2 keys", "1.18.29\n", nil, []string{v2Perms}, opencodeConfigV1},
		{"no binary, v1 config", "", os.ErrNotExist, []string{v1}, opencodeConfigV1},
		{"no binary, no config", "", os.ErrNotExist, []string{missing}, opencodeConfigV1},
		{"no binary, v2 permissions", "", os.ErrNotExist, []string{missing, v2Perms}, opencodeConfigV2},
		{"no binary, v2 servers", "", os.ErrNotExist, []string{v2Servers}, opencodeConfigV2},
		{"no binary, v1 server named servers", "", os.ErrNotExist, []string{legacyServers}, opencodeConfigV1},
		{"dev build, v2 config", "local\n", nil, []string{v2Servers}, opencodeConfigV2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stub(tt.out, tt.err)
			if got := detectOpencodeConfigVersion(tt.configs...); got != tt.want {
				t.Errorf("got v%d, want v%d", got, tt.want)
			}
		})
	}
}

// TestConfigureOpencodeAGENTSMDReplacesLegacyDirective verifies a directive
// written by an earlier release is swapped for the current one rather than
// gaining a near-duplicate.
func TestConfigureOpencodeAGENTSMDReplacesLegacyDirective(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "AGENTS.md")
	legacy := "# My rules\n\n" + opencodeLegacyDirectives[0] + "\n\nBe nice.\n"
	if err := os.WriteFile(path, []byte(legacy), 0644); err != nil {
		t.Fatal(err)
	}

	if err := configureOpencodeAGENTSMD(tmpDir); err != nil {
		t.Fatalf("configureOpencodeAGENTSMD failed: %v", err)
	}
	content := readFile(t, path)
	if strings.Contains(content, opencodeLegacyDirectives[0]) {
		t.Errorf("legacy directive left in place:\n%s", content)
	}
	if strings.Count(content, opencodeDirective) != 1 {
		t.Errorf("expected the directive once:\n%s", content)
	}
	if !strings.HasPrefix(content, "# My rules\n") || !strings.HasSuffix(content, "Be nice.\n") {
		t.Errorf("surrounding content changed:\n%s", content)
	}
}

func TestOpencodeV2ConfigDir(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	t.Setenv("OPENCODE_CONFIG_DIR", "")
	if dir, _ := opencodeV2ConfigDir(); dir != filepath.Join("/xdg", "opencode") {
		t.Errorf("default v2 dir = %s", dir)
	}
	t.Setenv("OPENCODE_CONFIG_DIR", "/custom/oc")
	if dir, _ := opencodeV2ConfigDir(); dir != "/custom/oc" {
		t.Errorf("OPENCODE_CONFIG_DIR not honored, got %s", dir)
	}
}

// TestRunInstallOpencodeSelectsDirAndFormat verifies the install writes v2's
// format to OPENCODE_CONFIG_DIR (which v2 reads in place of the XDG dir) and
// v1's to the XDG dir, editing an existing opencode.jsonc rather than adding
// an opencode.json beside it.
func TestRunInstallOpencodeSelectsDirAndFormat(t *testing.T) {
	stub := func(out string) {
		orig := opencodeVersionOutput
		opencodeVersionOutput = func() (string, error) { return out, nil }
		t.Cleanup(func() { opencodeVersionOutput = orig })
	}

	t.Run("v2", func(t *testing.T) {
		root := t.TempDir()
		xdg, oc := filepath.Join(root, "xdg"), filepath.Join(root, "oc")
		t.Setenv("XDG_CONFIG_HOME", xdg)
		t.Setenv("OPENCODE_CONFIG_DIR", oc)
		if err := os.MkdirAll(oc, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(oc, "opencode.jsonc"), []byte("{\n  // mine\n}\n"), 0644); err != nil {
			t.Fatal(err)
		}
		stub("2.2.5\n")

		if err := runInstallOpencode("/bin/lite-sandbox"); err != nil {
			t.Fatalf("runInstallOpencode failed: %v", err)
		}
		if fileExists(filepath.Join(oc, "opencode.json")) {
			t.Error("opencode.json created beside the existing opencode.jsonc")
		}
		cfg, _ := parseOpencodeV2Config(t, filepath.Join(oc, "opencode.jsonc"))
		if _, ok := cfg.MCP.Servers["lite-sandbox"]; !ok {
			t.Errorf("v2 server not written to OPENCODE_CONFIG_DIR")
		}
		if !strings.Contains(readFile(t, filepath.Join(oc, "opencode.jsonc")), "// mine") {
			t.Error("comment lost")
		}
		if !strings.Contains(readFile(t, filepath.Join(oc, "AGENTS.md")), opencodeDirective) {
			t.Error("directive not written to OPENCODE_CONFIG_DIR")
		}
		if fileExists(filepath.Join(xdg, "opencode")) {
			t.Error("XDG opencode dir written although v2 reads OPENCODE_CONFIG_DIR")
		}
	})

	t.Run("v1", func(t *testing.T) {
		root := t.TempDir()
		xdg, oc := filepath.Join(root, "xdg"), filepath.Join(root, "oc")
		t.Setenv("XDG_CONFIG_HOME", xdg)
		t.Setenv("OPENCODE_CONFIG_DIR", oc)
		stub("1.18.29\n")

		if err := runInstallOpencode("/bin/lite-sandbox"); err != nil {
			t.Fatalf("runInstallOpencode failed: %v", err)
		}
		cfg := parseOpencodeConfig(t, filepath.Join(xdg, "opencode", "opencode.json"))
		if _, ok := cfg["permissions"]; ok {
			t.Error("v2 permissions written for v1")
		}
		if string(cfg["permission"]) == "" {
			t.Error("v1 permission map not written")
		}
		if fileExists(oc) {
			t.Error("OPENCODE_CONFIG_DIR written for v1")
		}
	})
}
