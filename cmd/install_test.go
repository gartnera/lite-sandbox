package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestConfigureMCPServer(t *testing.T) {
	tmpDir := t.TempDir()
	claudeJsonPath := filepath.Join(tmpDir, ".claude.json")

	// Test with non-existent file
	err := configureMCPServer(claudeJsonPath, "/usr/local/bin/lite-sandbox")
	if err != nil {
		t.Fatalf("configureMCPServer failed: %v", err)
	}

	// Read and verify the file
	data, err := os.ReadFile(claudeJsonPath)
	if err != nil {
		t.Fatalf("failed to read .claude.json: %v", err)
	}

	var cfg map[string]json.RawMessage
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse .claude.json: %v", err)
	}

	var mcpServers map[string]mcpServerConfig
	if err := json.Unmarshal(cfg["mcpServers"], &mcpServers); err != nil {
		t.Fatalf("failed to parse mcpServers: %v", err)
	}

	if len(mcpServers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(mcpServers))
	}

	server, ok := mcpServers["lite-sandbox"]
	if !ok {
		t.Fatal("lite-sandbox server not found")
	}

	if server.Command != "/usr/local/bin/lite-sandbox" {
		t.Errorf("expected command /usr/local/bin/lite-sandbox, got %s", server.Command)
	}

	if len(server.Args) != 1 || server.Args[0] != "serve-mcp" {
		t.Errorf("expected args [serve], got %v", server.Args)
	}

	// Test updating existing file
	err = configureMCPServer(claudeJsonPath, "/opt/lite-sandbox")
	if err != nil {
		t.Fatalf("configureMCPServer failed on update: %v", err)
	}

	// Verify the update
	data, err = os.ReadFile(claudeJsonPath)
	if err != nil {
		t.Fatalf("failed to read .claude.json: %v", err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse .claude.json: %v", err)
	}

	if err := json.Unmarshal(cfg["mcpServers"], &mcpServers); err != nil {
		t.Fatalf("failed to parse mcpServers: %v", err)
	}

	server = mcpServers["lite-sandbox"]
	if server.Command != "/opt/lite-sandbox" {
		t.Errorf("expected updated command /opt/lite-sandbox, got %s", server.Command)
	}

	// Test that existing keys in ~/.claude.json are preserved
	existingContent := `{"someKey": "someValue", "numStartups": 5}`
	if err := os.WriteFile(claudeJsonPath, []byte(existingContent), 0644); err != nil {
		t.Fatalf("failed to write existing .claude.json: %v", err)
	}

	err = configureMCPServer(claudeJsonPath, "/usr/local/bin/lite-sandbox")
	if err != nil {
		t.Fatalf("configureMCPServer failed with existing content: %v", err)
	}

	data, err = os.ReadFile(claudeJsonPath)
	if err != nil {
		t.Fatalf("failed to read .claude.json: %v", err)
	}

	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("failed to parse .claude.json: %v", err)
	}

	// Verify existing keys are preserved
	if _, ok := cfg["someKey"]; !ok {
		t.Error("existing key 'someKey' was lost")
	}
	if _, ok := cfg["numStartups"]; !ok {
		t.Error("existing key 'numStartups' was lost")
	}
	// Verify mcpServers was added
	if _, ok := cfg["mcpServers"]; !ok {
		t.Error("mcpServers key was not added")
	}
}

func TestConfigurePermissions(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with non-existent file
	err := configurePermissions(tmpDir, true, true)
	if err != nil {
		t.Fatalf("configurePermissions failed: %v", err)
	}

	// Read and verify the file
	settingsPath := filepath.Join(tmpDir, "settings.json")
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("failed to read settings.json: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse settings.json: %v", err)
	}

	var perms permissionsConfig
	if err := json.Unmarshal(raw["permissions"], &perms); err != nil {
		t.Fatalf("failed to parse permissions: %v", err)
	}

	expected := "mcp__lite-sandbox__bash"
	for _, want := range mcpToolPermissions {
		if !slices.Contains(perms.Allow, want) {
			t.Errorf("expected permission %s not found in %v", want, perms.Allow)
		}
	}

	if !slices.Contains(perms.Deny, "Bash") {
		t.Errorf("expected built-in Bash to be denied, got deny list %v", perms.Deny)
	}

	// Test that running again doesn't duplicate
	err = configurePermissions(tmpDir, true, true)
	if err != nil {
		t.Fatalf("configurePermissions failed on second run: %v", err)
	}

	data, err = os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("failed to read settings.json: %v", err)
	}

	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse settings.json: %v", err)
	}

	if err := json.Unmarshal(raw["permissions"], &perms); err != nil {
		t.Fatalf("failed to parse permissions: %v", err)
	}

	count := 0
	for _, p := range perms.Allow {
		if p == expected {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected permission to appear once, got %d times", count)
	}

	denyCount := 0
	for _, p := range perms.Deny {
		if p == "Bash" {
			denyCount++
		}
	}
	if denyCount != 1 {
		t.Errorf("expected Bash deny to appear once, got %d times", denyCount)
	}
}

func TestConfigurePermissionsPreservesUnknownKeys(t *testing.T) {
	tmpDir := t.TempDir()
	settingsPath := filepath.Join(tmpDir, "settings.json")

	// Write a settings.json with extra keys (like hooks)
	existingContent := `{"hooks": {"PreToolUse": [{"matcher": "Bash"}]}, "someOther": true}`
	if err := os.WriteFile(settingsPath, []byte(existingContent), 0644); err != nil {
		t.Fatalf("failed to write existing settings.json: %v", err)
	}

	err := configurePermissions(tmpDir, true, true)
	if err != nil {
		t.Fatalf("configurePermissions failed: %v", err)
	}

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		t.Fatalf("failed to read settings.json: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse settings.json: %v", err)
	}

	// Verify existing keys are preserved
	if _, ok := raw["hooks"]; !ok {
		t.Error("existing key 'hooks' was lost")
	}
	if _, ok := raw["someOther"]; !ok {
		t.Error("existing key 'someOther' was lost")
	}
	// Verify permissions was added
	if _, ok := raw["permissions"]; !ok {
		t.Error("permissions key was not added")
	}
}

func TestConfigureCLAUDEMD(t *testing.T) {
	tmpDir := t.TempDir()

	// Test with non-existent file
	err := configureCLAUDEMD(tmpDir)
	if err != nil {
		t.Fatalf("configureCLAUDEMD failed: %v", err)
	}

	// Read and verify the file
	claudeMDPath := filepath.Join(tmpDir, "CLAUDE.md")
	data, err := os.ReadFile(claudeMDPath)
	if err != nil {
		t.Fatalf("failed to read CLAUDE.md: %v", err)
	}

	content := string(data)
	expectedDirective := "ALWAYS use the mcp__lite-sandbox__bash tool"
	if !contains(content, expectedDirective) {
		t.Errorf("expected CLAUDE.md to contain %q, got:\n%s", expectedDirective, content)
	}

	// Test that running again doesn't duplicate
	err = configureCLAUDEMD(tmpDir)
	if err != nil {
		t.Fatalf("configureCLAUDEMD failed on second run: %v", err)
	}

	data, err = os.ReadFile(claudeMDPath)
	if err != nil {
		t.Fatalf("failed to read CLAUDE.md: %v", err)
	}

	content = string(data)

	// Count occurrences
	count := 0
	for i := 0; i <= len(content)-len(expectedDirective); i++ {
		if content[i:i+len(expectedDirective)] == expectedDirective {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected directive to appear once, got %d times", count)
	}

	// Test appending to existing file
	tmpDir2 := t.TempDir()
	claudeMDPath2 := filepath.Join(tmpDir2, "CLAUDE.md")
	existingContent := "# Existing Content\n\nSome existing instructions.\n"
	if err := os.WriteFile(claudeMDPath2, []byte(existingContent), 0644); err != nil {
		t.Fatalf("failed to write existing CLAUDE.md: %v", err)
	}

	err = configureCLAUDEMD(tmpDir2)
	if err != nil {
		t.Fatalf("configureCLAUDEMD failed with existing file: %v", err)
	}

	data, err = os.ReadFile(claudeMDPath2)
	if err != nil {
		t.Fatalf("failed to read CLAUDE.md: %v", err)
	}

	content = string(data)
	if !contains(content, "# Existing Content") {
		t.Error("existing content was lost")
	}
	if !contains(content, expectedDirective) {
		t.Error("directive was not added")
	}
}

// TestClaudeHookPlan covers the hook command/matcher for each install mode. In
// every mode that configures the MCP server, the matcher must include the
// sandbox's own MCP tools so the hook pre-approves them in subagents/skills,
// which don't inherit permissions.allow (anthropics/claude-code#18950).
func TestClaudeHookPlan(t *testing.T) {
	const bin = "/usr/local/bin/lite-sandbox"

	tests := []struct {
		name                             string
		wantHook, validateBash, governFS bool
		configMCP                        bool
		wantCommand, wantMatcher         string
	}{
		{
			name:        "default install allows MCP tools via hook",
			configMCP:   true,
			wantCommand: bin + " hook",
			wantMatcher: mcpToolMatcher,
		},
		{
			name:     "with-tool-hook governs built-ins and allows MCP tools",
			wantHook: true, governFS: true, configMCP: true,
			wantCommand: bin + " hook",
			wantMatcher: hookToolMatcher + "|" + mcpToolMatcher,
		},
		{
			name:     "bash-ast mode matches only Bash (no MCP server)",
			wantHook: true, validateBash: true,
			wantCommand: bin + " hook --validate-bash",
			wantMatcher: bashValidateMatcher,
		},
		{
			name:     "bash-ast with tool hook matches built-ins only",
			wantHook: true, validateBash: true, governFS: true,
			wantCommand: bin + " hook --validate-bash",
			wantMatcher: hookToolMatcher,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command, matcher := claudeHookPlan(bin, tt.wantHook, tt.validateBash, tt.governFS, tt.configMCP)
			if command != tt.wantCommand {
				t.Errorf("command = %q, want %q", command, tt.wantCommand)
			}
			if matcher != tt.wantMatcher {
				t.Errorf("matcher = %q, want %q", matcher, tt.wantMatcher)
			}
		})
	}
}

// setupDetectionEnv points every detection input (PATH, HOME, CODEX_HOME,
// XDG_CONFIG_HOME) at empty temp directories so no real CLI on the test host
// leaks into the result. It returns the fake home and PATH directories.
func setupDetectionEnv(t *testing.T) (homeDir, pathDir string) {
	t.Helper()
	homeDir = t.TempDir()
	pathDir = t.TempDir()
	t.Setenv("HOME", homeDir)
	t.Setenv("PATH", pathDir)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	return homeDir, pathDir
}

func targetNames(targets []installTarget) []string {
	names := make([]string, len(targets))
	for i, t := range targets {
		names[i] = t.name
	}
	return names
}

func TestResolveInstallTargetsAutodetect(t *testing.T) {
	homeDir, pathDir := setupDetectionEnv(t)

	// Nothing installed: autodetection must fail rather than silently do nothing.
	if _, _, err := resolveInstallTargets(nil); err == nil {
		t.Fatal("expected error when no CLI is detected")
	}

	// Config-directory detection.
	if err := os.MkdirAll(filepath.Join(homeDir, ".claude"), 0755); err != nil {
		t.Fatal(err)
	}
	targets, auto, err := resolveInstallTargets(nil)
	if err != nil {
		t.Fatalf("resolveInstallTargets failed: %v", err)
	}
	if !auto || !slices.Equal(targetNames(targets), []string{"claude"}) {
		t.Errorf("expected autodetected [claude], got %v (auto=%v)", targetNames(targets), auto)
	}

	// PATH detection.
	if err := os.WriteFile(filepath.Join(pathDir, "opencode"), []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	// CODEX_HOME detection.
	codexDir := t.TempDir()
	t.Setenv("CODEX_HOME", codexDir)

	targets, _, err = resolveInstallTargets(nil)
	if err != nil {
		t.Fatalf("resolveInstallTargets failed: %v", err)
	}
	if !slices.Equal(targetNames(targets), []string{"claude", "codex", "opencode"}) {
		t.Errorf("expected [claude codex opencode], got %v", targetNames(targets))
	}
}

func TestResolveInstallTargetsExplicit(t *testing.T) {
	setupDetectionEnv(t) // nothing detected — explicit args must still work

	targets, auto, err := resolveInstallTargets([]string{"opencode", "codex", "opencode"})
	if err != nil {
		t.Fatalf("resolveInstallTargets failed: %v", err)
	}
	if auto {
		t.Error("explicit args must not report autodetection")
	}
	// Order preserved, duplicates dropped.
	if !slices.Equal(targetNames(targets), []string{"opencode", "codex"}) {
		t.Errorf("expected [opencode codex], got %v", targetNames(targets))
	}

	if _, _, err := resolveInstallTargets([]string{"cursor"}); err == nil {
		t.Error("expected error for unknown agent name")
	}
}

// TestResolveInstallTargetsDeprecatedCodexFlag verifies the old --codex flag
// still selects the codex target.
func TestResolveInstallTargetsDeprecatedCodexFlag(t *testing.T) {
	setupDetectionEnv(t)

	installCodex = true
	defer func() { installCodex = false }()

	targets, auto, err := resolveInstallTargets(nil)
	if err != nil {
		t.Fatalf("resolveInstallTargets failed: %v", err)
	}
	if auto || !slices.Equal(targetNames(targets), []string{"codex"}) {
		t.Errorf("expected explicit [codex], got %v (auto=%v)", targetNames(targets), auto)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
