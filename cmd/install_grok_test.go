package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"

	"github.com/gartnera/lite-sandbox/internal/hook"
)

// grokConfig is the subset of Grok's config.toml the installer writes.
type grokConfig struct {
	MCPServers map[string]struct {
		Command string   `toml:"command"`
		Args    []string `toml:"args"`
	} `toml:"mcp_servers"`
	Permission struct {
		Allow []string `toml:"allow"`
		Rules []struct {
			Action  string `toml:"action"`
			Tool    string `toml:"tool"`
			Pattern string `toml:"pattern"`
		} `toml:"rules"`
	} `toml:"permission"`
	Model string `toml:"model"`
}

func readGrokConfig(t *testing.T, path string) grokConfig {
	t.Helper()
	var c grokConfig
	if err := toml.Unmarshal([]byte(readFile(t, path)), &c); err != nil {
		t.Fatalf("config.toml is not valid TOML: %v\n%s", err, readFile(t, path))
	}
	return c
}

// ruleSet renders the permission rules as "action:tool:pattern" strings.
func (c grokConfig) ruleSet() []string {
	var out []string
	for _, r := range c.Permission.Rules {
		out = append(out, r.Action+":"+r.Tool+":"+r.Pattern)
	}
	return out
}

// setupGrokHome points GROK_HOME at a fresh directory and resets the install
// flags the Grok installer reads.
func setupGrokHome(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "grok-home")
	t.Setenv("GROK_HOME", dir)
	t.Setenv("HOME", t.TempDir())
	prev := installBashASTHookMode
	t.Cleanup(func() { installBashASTHookMode = prev })
	installBashASTHookMode = false
	return dir
}

func TestRunInstallGrok(t *testing.T) {
	dir := setupGrokHome(t)
	bin := "/usr/local/bin/lite-sandbox"

	if err := runInstallGrok(bin); err != nil {
		t.Fatalf("runInstallGrok: %v", err)
	}

	cfg := readGrokConfig(t, filepath.Join(dir, "config.toml"))
	srv, ok := cfg.MCPServers["lite-sandbox"]
	if !ok || srv.Command != bin || strings.Join(srv.Args, " ") != "serve-mcp" {
		t.Errorf("MCP server = %+v (present=%v)", srv, ok)
	}
	if got, want := strings.Join(cfg.ruleSet(), ","), "allow:mcp:lite-sandbox__*,deny:bash:"; got != want {
		t.Errorf("permission rules = %s, want %s", got, want)
	}

	var hookDoc struct {
		Hooks map[string][]struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
				Timeout int    `json:"timeout"`
			} `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "hooks", "lite-sandbox.json"))), &hookDoc); err != nil {
		t.Fatalf("hook file is not JSON: %v", err)
	}
	pre := hookDoc.Hooks["PreToolUse"]
	if len(pre) != 1 || pre[0].Matcher != hook.GrokHookMatcher || len(pre[0].Hooks) != 1 {
		t.Fatalf("unexpected PreToolUse hooks: %+v", pre)
	}
	if h := pre[0].Hooks[0]; h.Type != "command" || h.Command != bin+" hook" || h.Timeout != grokHookTimeoutSec {
		t.Errorf("unexpected hook handler: %+v", h)
	}

	rules := readFile(t, filepath.Join(dir, "rules", "lite-sandbox.md"))
	if !strings.Contains(rules, "lite-sandbox__bash") || !strings.Contains(rules, "use_tool") {
		t.Errorf("directive does not explain how to reach the tool:\n%s", rules)
	}

	// Reinstalling converges: one server table, one permission block.
	if err := runInstallGrok(bin); err != nil {
		t.Fatalf("second runInstallGrok: %v", err)
	}
	content := readFile(t, filepath.Join(dir, "config.toml"))
	if n := strings.Count(content, "[mcp_servers.lite-sandbox]"); n != 1 {
		t.Errorf("expected one server table after reinstall, got %d:\n%s", n, content)
	}
	if n := strings.Count(content, grokPermissionBlockStart); n != 1 {
		t.Errorf("expected one permission block after reinstall, got %d:\n%s", n, content)
	}
	if got := len(readGrokConfig(t, filepath.Join(dir, "config.toml")).Permission.Rules); got != 2 {
		t.Errorf("expected 2 rules after reinstall, got %d", got)
	}
}

// TestRunInstallGrokPreservesUserConfig checks the installer extends a config
// that already has its own [permission] section and MCP servers.
func TestRunInstallGrokPreservesUserConfig(t *testing.T) {
	dir := setupGrokHome(t)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	existing := "# mine\nmodel = \"grok-4.7\"\n\n[permission]\nallow = [\"Bash(git *)\"]\n\n[mcp_servers.linear]\nurl = \"https://mcp.linear.app/mcp\"\n"
	configPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	if err := runInstallGrok("/bin/ls-sb"); err != nil {
		t.Fatalf("runInstallGrok: %v", err)
	}
	content := readFile(t, configPath)
	if !strings.HasPrefix(content, "# mine\n") {
		t.Errorf("user content was not preserved:\n%s", content)
	}
	cfg := readGrokConfig(t, configPath)
	if cfg.Model != "grok-4.7" || strings.Join(cfg.Permission.Allow, ",") != "Bash(git *)" {
		t.Errorf("user settings lost: model=%q allow=%v", cfg.Model, cfg.Permission.Allow)
	}
	if _, ok := cfg.MCPServers["linear"]; !ok {
		t.Error("user MCP server lost")
	}
	if _, ok := cfg.MCPServers["lite-sandbox"]; !ok {
		t.Error("lite-sandbox MCP server not added")
	}
	if len(cfg.Permission.Rules) != 2 {
		t.Errorf("expected our 2 rules, got %v", cfg.ruleSet())
	}
}

// TestRunInstallGrokInlineRulesConflict: a [permission] section that spells
// `rules` as an inline array cannot be extended with [[permission.rules]], so
// the installer leaves the file valid and reports the rules to add by hand.
func TestRunInstallGrokInlineRulesConflict(t *testing.T) {
	dir := setupGrokHome(t)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.toml")
	existing := "[permission]\nrules = [{ action = \"allow\", tool = \"read\" }]\n"
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatal(err)
	}

	if err := runInstallGrok("/bin/ls-sb"); err != nil {
		t.Fatalf("runInstallGrok: %v", err)
	}
	content := readFile(t, configPath)
	if strings.Contains(content, grokPermissionBlockStart) {
		t.Errorf("permission block written despite the conflict:\n%s", content)
	}
	cfg := readGrokConfig(t, configPath) // still valid TOML
	if _, ok := cfg.MCPServers["lite-sandbox"]; !ok {
		t.Error("MCP server should still be added")
	}
	if got := cfg.ruleSet(); len(got) != 1 || got[0] != "allow:read:" {
		t.Errorf("user rules changed: %v", got)
	}
}

// TestRunInstallGrokBashASTHookMode: no MCP server or directive, no shell deny
// (the hook validates the shell in place), but the file tools stay governed.
func TestRunInstallGrokBashASTHookMode(t *testing.T) {
	dir := setupGrokHome(t)

	// Start from a default install so the switch must clean up after it.
	if err := runInstallGrok("/bin/ls-sb"); err != nil {
		t.Fatal(err)
	}
	installBashASTHookMode = true
	if err := runInstallGrok("/bin/ls-sb"); err != nil {
		t.Fatalf("runInstallGrok: %v", err)
	}

	content := readFile(t, filepath.Join(dir, "config.toml"))
	if strings.Contains(content, grokPermissionBlockStart) {
		t.Errorf("permission block left in bash-ast-hook mode:\n%s", content)
	}
	if _, err := os.Stat(filepath.Join(dir, "rules", "lite-sandbox.md")); !os.IsNotExist(err) {
		t.Errorf("stale directive not removed: %v", err)
	}
	hookFile := readFile(t, filepath.Join(dir, "hooks", "lite-sandbox.json"))
	if !strings.Contains(hookFile, "hook --validate-bash") || !strings.Contains(hookFile, hook.GrokToolReadFile) {
		t.Errorf("hook should validate the shell and still match file tools:\n%s", hookFile)
	}
}

func TestDetectGrok(t *testing.T) {
	setupDetectionEnv(t)
	t.Setenv("GROK_HOME", "")
	if detectGrok() {
		t.Fatal("detected grok with nothing installed")
	}
	dir := t.TempDir()
	t.Setenv("GROK_HOME", dir)
	if !detectGrok() {
		t.Error("GROK_HOME directory not detected")
	}
}

// TestGrokHookCommandQuoting: Grok runs the hook through `sh -c`, so a binary
// path with a space must be quoted, and one with $ (which Grok treats as a
// variable it must resolve) is refused rather than written as a hook that
// never runs.
func TestGrokHookCommandQuoting(t *testing.T) {
	setupGrokHome(t)
	p, err := grokInstallPlan("/Users/Jane Doe/bin/lite-sandbox")
	if err != nil {
		t.Fatal(err)
	}
	if want := `'/Users/Jane Doe/bin/lite-sandbox' hook`; p.hookCommand != want {
		t.Errorf("hookCommand = %q, want %q", p.hookCommand, want)
	}
	if _, err := grokInstallPlan("/opt/$HOME/lite-sandbox"); err == nil {
		t.Error("expected an error for a binary path containing $")
	}
}
