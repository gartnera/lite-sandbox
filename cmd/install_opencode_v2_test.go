package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

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
