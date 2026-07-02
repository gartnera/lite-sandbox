package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigureCodexMCPServerNewFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	if err := configureCodexMCPServer(configPath, "/usr/local/bin/lite-sandbox"); err != nil {
		t.Fatalf("configureCodexMCPServer failed: %v", err)
	}

	content := readFile(t, configPath)
	want := "[mcp_servers.lite-sandbox]\ncommand = \"/usr/local/bin/lite-sandbox\"\nargs = [\"serve-mcp\"]\n"
	if content != want {
		t.Errorf("unexpected content:\n%q\nwant:\n%q", content, want)
	}
}

func TestConfigureCodexMCPServerAppendsPreservingExisting(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	existing := "# my config\nmodel = \"gpt-5\"\n\n[mcp_servers.other]\ncommand = \"other\"\nargs = []\n"
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureCodexMCPServer(configPath, "/opt/lite-sandbox"); err != nil {
		t.Fatalf("configureCodexMCPServer failed: %v", err)
	}

	content := readFile(t, configPath)
	// Existing content preserved verbatim (including the comment and other server).
	if !strings.Contains(content, "# my config") {
		t.Error("comment was lost")
	}
	if !strings.Contains(content, "[mcp_servers.other]") {
		t.Error("existing server was lost")
	}
	if !strings.Contains(content, "[mcp_servers.lite-sandbox]") {
		t.Error("lite-sandbox server was not added")
	}
	if !strings.Contains(content, `command = "/opt/lite-sandbox"`) {
		t.Errorf("expected command not found:\n%s", content)
	}
	// A blank line should separate the appended table from prior content.
	if !strings.Contains(content, "args = []\n\n[mcp_servers.lite-sandbox]") {
		t.Errorf("expected blank-line separation before appended table:\n%s", content)
	}
}

func TestConfigureCodexMCPServerIsIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	existing := "model = \"gpt-5\"\n"
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureCodexMCPServer(configPath, "/first/lite-sandbox"); err != nil {
		t.Fatalf("first configureCodexMCPServer failed: %v", err)
	}
	if err := configureCodexMCPServer(configPath, "/second/lite-sandbox"); err != nil {
		t.Fatalf("second configureCodexMCPServer failed: %v", err)
	}

	content := readFile(t, configPath)

	if got := strings.Count(content, "[mcp_servers.lite-sandbox]"); got != 1 {
		t.Errorf("expected table to appear once, got %d:\n%s", got, content)
	}
	// The path should be updated to the latest, not the first.
	if strings.Contains(content, "/first/lite-sandbox") {
		t.Errorf("stale command not replaced:\n%s", content)
	}
	if !strings.Contains(content, `command = "/second/lite-sandbox"`) {
		t.Errorf("command not updated:\n%s", content)
	}
	if !strings.Contains(content, `model = "gpt-5"`) {
		t.Errorf("unrelated key lost:\n%s", content)
	}
}

func TestConfigureCodexMCPServerReplacesInPlacePreservingSurrounding(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	existing := "[a]\nx = 1\n\n[mcp_servers.lite-sandbox]\ncommand = \"/old\"\nargs = [\"serve-mcp\"]\n\n[b]\ny = 2\n"
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureCodexMCPServer(configPath, "/new"); err != nil {
		t.Fatalf("configureCodexMCPServer failed: %v", err)
	}

	content := readFile(t, configPath)
	// Tables before and after our block must survive, in order.
	aIdx := strings.Index(content, "[a]")
	usIdx := strings.Index(content, "[mcp_servers.lite-sandbox]")
	bIdx := strings.Index(content, "[b]")
	if aIdx == -1 || usIdx == -1 || bIdx == -1 {
		t.Fatalf("a table was lost:\n%s", content)
	}
	if !(aIdx < usIdx && usIdx < bIdx) {
		t.Errorf("table ordering not preserved:\n%s", content)
	}
	if strings.Contains(content, "/old") {
		t.Errorf("old command not replaced:\n%s", content)
	}
	if !strings.Contains(content, "y = 2") {
		t.Errorf("trailing table body lost:\n%s", content)
	}
	// Blank-line separator before [b] preserved.
	if !strings.Contains(content, "\n\n[b]") {
		t.Errorf("separator before [b] not preserved:\n%s", content)
	}
}

func TestConfigureCodexMCPServerReplacesSubTable(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	// A prior config with an env sub-table under our server.
	existing := "[mcp_servers.lite-sandbox]\ncommand = \"/old\"\nargs = [\"serve-mcp\"]\n\n[mcp_servers.lite-sandbox.env]\nFOO = \"bar\"\n\n[keep]\nz = 3\n"
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureCodexMCPServer(configPath, "/new"); err != nil {
		t.Fatalf("configureCodexMCPServer failed: %v", err)
	}

	content := readFile(t, configPath)
	// The env sub-table is part of our block and should be rewritten away.
	if strings.Contains(content, "[mcp_servers.lite-sandbox.env]") {
		t.Errorf("stale sub-table not removed:\n%s", content)
	}
	if strings.Contains(content, "FOO = \"bar\"") {
		t.Errorf("stale sub-table body not removed:\n%s", content)
	}
	// The unrelated table after it must survive.
	if !strings.Contains(content, "[keep]") || !strings.Contains(content, "z = 3") {
		t.Errorf("unrelated table lost:\n%s", content)
	}
	if strings.Count(content, "[mcp_servers.lite-sandbox]") != 1 {
		t.Errorf("expected exactly one server table:\n%s", content)
	}
}

func TestConfigureCodexAGENTSMD(t *testing.T) {
	tmpDir := t.TempDir()

	// Non-existent file: created with the directive.
	if err := configureCodexAGENTSMD(tmpDir); err != nil {
		t.Fatalf("configureCodexAGENTSMD failed: %v", err)
	}
	content := readFile(t, filepath.Join(tmpDir, "AGENTS.md"))
	if !strings.Contains(content, codexDirective) {
		t.Errorf("directive not written:\n%s", content)
	}

	// Idempotent: running again does not duplicate.
	if err := configureCodexAGENTSMD(tmpDir); err != nil {
		t.Fatalf("configureCodexAGENTSMD failed on second run: %v", err)
	}
	content = readFile(t, filepath.Join(tmpDir, "AGENTS.md"))
	if got := strings.Count(content, codexDirective); got != 1 {
		t.Errorf("expected directive once, got %d", got)
	}

	// Appends to an existing file, preserving content.
	tmpDir2 := t.TempDir()
	existing := "# Existing\n\nSome instructions.\n"
	if err := os.WriteFile(filepath.Join(tmpDir2, "AGENTS.md"), []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing AGENTS.md: %v", err)
	}
	if err := configureCodexAGENTSMD(tmpDir2); err != nil {
		t.Fatalf("configureCodexAGENTSMD failed with existing file: %v", err)
	}
	content = readFile(t, filepath.Join(tmpDir2, "AGENTS.md"))
	if !strings.Contains(content, "# Existing") {
		t.Error("existing content was lost")
	}
	if !strings.Contains(content, codexDirective) {
		t.Error("directive was not appended")
	}
}

func TestTOMLString(t *testing.T) {
	cases := map[string]string{
		"/usr/local/bin/lite-sandbox": `"/usr/local/bin/lite-sandbox"`,
		`C:\bin\lite-sandbox`:         `"C:\\bin\\lite-sandbox"`,
		`weird"path`:                  `"weird\"path"`,
	}
	for in, want := range cases {
		if got := tomlString(in); got != want {
			t.Errorf("tomlString(%q) = %q, want %q", in, got, want)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	return string(data)
}
