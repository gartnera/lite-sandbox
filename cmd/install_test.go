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
	err := configurePermissions(tmpDir, false)
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
	if !slices.Contains(perms.Allow, expected) {
		t.Errorf("expected permission %s not found in %v", expected, perms.Allow)
	}

	if !slices.Contains(perms.Deny, "Bash") {
		t.Errorf("expected built-in Bash to be denied, got deny list %v", perms.Deny)
	}

	// Test that running again doesn't duplicate
	err = configurePermissions(tmpDir, false)
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

	err := configurePermissions(tmpDir, false)
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

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
