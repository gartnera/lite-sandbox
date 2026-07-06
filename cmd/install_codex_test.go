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
	want := "[mcp_servers.lite-sandbox]\ncommand = \"/usr/local/bin/lite-sandbox\"\nargs = [\"serve-mcp\"]\ndefault_tools_approval_mode = \"approve\"\n"
	if content != want {
		t.Errorf("unexpected content:\n%q\nwant:\n%q", content, want)
	}
}

// TestConfigureCodexMCPServerUpgradesApprovalMode verifies that re-running over
// an older block (command + args only, no approval key) rewrites it in place to
// include default_tools_approval_mode, without duplicating the table.
func TestConfigureCodexMCPServerUpgradesApprovalMode(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	old := "[mcp_servers.lite-sandbox]\ncommand = \"/old\"\nargs = [\"serve-mcp\"]\n"
	if err := os.WriteFile(configPath, []byte(old), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureCodexMCPServer(configPath, "/new"); err != nil {
		t.Fatalf("configureCodexMCPServer failed: %v", err)
	}

	content := readFile(t, configPath)
	if !strings.Contains(content, `default_tools_approval_mode = "approve"`) {
		t.Errorf("approval mode not added on upgrade:\n%s", content)
	}
	if got := strings.Count(content, "[mcp_servers.lite-sandbox]"); got != 1 {
		t.Errorf("expected one server table, got %d:\n%s", got, content)
	}
	if strings.Contains(content, "/old") {
		t.Errorf("stale command not replaced:\n%s", content)
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

// TestConfigureCodexMCPServerPreservesFollowingContent verifies that rewriting
// the table in place preserves everything after it — a user-authored env
// sub-table, comments, and unrelated tables — rather than absorbing/deleting it.
func TestConfigureCodexMCPServerPreservesFollowingContent(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	existing := "[mcp_servers.lite-sandbox]\ncommand = \"/old\"\nargs = [\"serve-mcp\"]\n\n[mcp_servers.lite-sandbox.env]\nFOO = \"bar\"\n\n# notes about the next server\n[keep]\nz = 3\n"
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("failed to write existing config: %v", err)
	}

	if err := configureCodexMCPServer(configPath, "/new"); err != nil {
		t.Fatalf("configureCodexMCPServer failed: %v", err)
	}

	content := readFile(t, configPath)
	// Our table body is updated...
	if !strings.Contains(content, `command = "/new"`) || strings.Contains(content, "/old") {
		t.Errorf("table body not updated:\n%s", content)
	}
	// ...but the user's env sub-table, comment, and unrelated table survive.
	if !strings.Contains(content, "[mcp_servers.lite-sandbox.env]") || !strings.Contains(content, `FOO = "bar"`) {
		t.Errorf("user env sub-table lost:\n%s", content)
	}
	if !strings.Contains(content, "# notes about the next server") {
		t.Errorf("comment before next section lost:\n%s", content)
	}
	if !strings.Contains(content, "[keep]") || !strings.Contains(content, "z = 3") {
		t.Errorf("unrelated table lost:\n%s", content)
	}
	if strings.Count(content, "[mcp_servers.lite-sandbox]\n") != 1 {
		t.Errorf("expected exactly one server table:\n%s", content)
	}
}

func TestStripCodexHookBlockRemovesAllAndHandlesMalformed(t *testing.T) {
	// Two managed blocks: both must be removed so a re-append converges to one.
	block := codexHookBlockStart + "\nmatcher = \"Bash\"\n" + codexHookBlockEnd + "\n"
	two := "a = 1\n\n" + block + "\n" + block
	got := stripCodexHookBlock(two)
	if strings.Contains(got, codexHookBlockStart) {
		t.Errorf("not all blocks removed:\n%s", got)
	}
	if !strings.Contains(got, "a = 1") {
		t.Errorf("surrounding content lost:\n%s", got)
	}

	// Malformed: start marker but no end marker. Only the marker line is removed;
	// user content below it survives (no delete-to-EOF).
	malformed := "keep_above = 1\n" + codexHookBlockStart + "\n[user.table]\nkeep_below = 2\n"
	got = stripCodexHookBlock(malformed)
	if strings.Contains(got, codexHookBlockStart) {
		t.Errorf("orphaned start marker not removed:\n%s", got)
	}
	if !strings.Contains(got, "keep_above = 1") || !strings.Contains(got, "keep_below = 2") || !strings.Contains(got, "[user.table]") {
		t.Errorf("user content around orphaned marker was destroyed:\n%s", got)
	}
}

func TestConfigureCodexMCPServerDetectsBlockAcrossReinstalls(t *testing.T) {
	// After a full install, re-running the MCP step must not disturb a comment
	// that documents the managed hook block.
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")
	if err := configureCodexMCPServer(configPath, "/bin/lite-sandbox"); err != nil {
		t.Fatalf("configureCodexMCPServer: %v", err)
	}
	if err := reconcileCodexHook(configPath, "/bin/lite-sandbox", "/bin/lite-sandbox hook", bashValidateMatcher); err != nil {
		t.Fatalf("reconcileCodexHook: %v", err)
	}
	before := readFile(t, configPath)
	if err := configureCodexMCPServer(configPath, "/bin/lite-sandbox-v2"); err != nil {
		t.Fatalf("configureCodexMCPServer (2nd): %v", err)
	}
	after := readFile(t, configPath)
	if !strings.Contains(after, codexHookBlockStart) {
		t.Errorf("hook block lost on MCP re-run:\nbefore:\n%s\nafter:\n%s", before, after)
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

func TestReconcileCodexHookAppendAndIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	existing := "model = \"gpt-5\"\n\n[mcp_servers.lite-sandbox]\ncommand = \"/bin/lite-sandbox\"\nargs = [\"serve-mcp\"]\n"
	if err := os.WriteFile(configPath, []byte(existing), 0644); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	if err := reconcileCodexHook(configPath, "/bin/lite-sandbox", "/bin/lite-sandbox hook", hookToolMatcher); err != nil {
		t.Fatalf("reconcileCodexHook: %v", err)
	}
	content := readFile(t, configPath)

	// Managed block present with the array-of-tables shape.
	if !strings.Contains(content, codexHookBlockStart) || !strings.Contains(content, codexHookBlockEnd) {
		t.Errorf("markers missing:\n%s", content)
	}
	if !strings.Contains(content, "[[hooks.PreToolUse]]") || !strings.Contains(content, "[[hooks.PreToolUse.hooks]]") {
		t.Errorf("array-of-tables headers missing:\n%s", content)
	}
	if !strings.Contains(content, `matcher = "`+hookToolMatcher+`"`) {
		t.Errorf("matcher not written:\n%s", content)
	}
	if !strings.Contains(content, `command = "/bin/lite-sandbox hook"`) {
		t.Errorf("command not written:\n%s", content)
	}
	// The MCP table and unrelated keys survived.
	if !strings.Contains(content, "[mcp_servers.lite-sandbox]") || !strings.Contains(content, `model = "gpt-5"`) {
		t.Errorf("existing content lost:\n%s", content)
	}

	// Re-running with the same inputs converges byte-for-byte.
	if err := reconcileCodexHook(configPath, "/bin/lite-sandbox", "/bin/lite-sandbox hook", hookToolMatcher); err != nil {
		t.Fatalf("reconcileCodexHook (2nd): %v", err)
	}
	content2 := readFile(t, configPath)
	if content != content2 {
		t.Errorf("not idempotent:\nfirst:\n%s\nsecond:\n%s", content, content2)
	}
	if got := strings.Count(content2, codexHookBlockStart); got != 1 {
		t.Errorf("expected one managed block, got %d", got)
	}
}

func TestReconcileCodexHookModeSwitchReplacesInPlace(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	// First register the default redirect hook (matcher "Bash").
	if err := reconcileCodexHook(configPath, "/bin/ls", "/bin/ls hook", bashValidateMatcher); err != nil {
		t.Fatalf("reconcileCodexHook: %v", err)
	}
	// Switch to validate-bash + full matcher.
	if err := reconcileCodexHook(configPath, "/bin/ls", "/bin/ls hook --validate-bash", hookToolMatcher); err != nil {
		t.Fatalf("reconcileCodexHook (switch): %v", err)
	}
	content := readFile(t, configPath)

	if got := strings.Count(content, codexHookBlockStart); got != 1 {
		t.Errorf("expected exactly one managed block after switch, got %d:\n%s", got, content)
	}
	if strings.Contains(content, `command = "/bin/ls hook"`+"\n") && !strings.Contains(content, "--validate-bash") {
		t.Errorf("stale command not replaced:\n%s", content)
	}
	if !strings.Contains(content, `command = "/bin/ls hook --validate-bash"`) {
		t.Errorf("new command not present:\n%s", content)
	}
	if !strings.Contains(content, `matcher = "`+hookToolMatcher+`"`) {
		t.Errorf("matcher not updated:\n%s", content)
	}
}

// TestConfigureCodexMCPAndHookCoexist guards the interaction between the two
// text editors: rewriting the MCP table in place must not consume the managed
// hook block that follows it.
func TestConfigureCodexMCPAndHookCoexist(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.toml")

	// Simulate a full default install: MCP table, then hook block.
	if err := configureCodexMCPServer(configPath, "/bin/lite-sandbox"); err != nil {
		t.Fatalf("configureCodexMCPServer: %v", err)
	}
	if err := reconcileCodexHook(configPath, "/bin/lite-sandbox", "/bin/lite-sandbox hook", bashValidateMatcher); err != nil {
		t.Fatalf("reconcileCodexHook: %v", err)
	}

	// Re-run the MCP step (as a second install would): the hook block must remain.
	if err := configureCodexMCPServer(configPath, "/bin/lite-sandbox-v2"); err != nil {
		t.Fatalf("configureCodexMCPServer (2nd): %v", err)
	}
	content := readFile(t, configPath)

	if !strings.Contains(content, codexHookBlockStart) || !strings.Contains(content, codexHookBlockEnd) {
		t.Errorf("hook block clobbered by MCP rewrite:\n%s", content)
	}
	if !strings.Contains(content, "[[hooks.PreToolUse]]") {
		t.Errorf("hook table lost:\n%s", content)
	}
	if !strings.Contains(content, `command = "/bin/lite-sandbox-v2"`) {
		t.Errorf("MCP command not updated:\n%s", content)
	}
	if got := strings.Count(content, "[mcp_servers.lite-sandbox]"); got != 1 {
		t.Errorf("expected one MCP table, got %d:\n%s", got, content)
	}
}

func TestStripCodexHookBlock(t *testing.T) {
	block := codexHookBlockStart + "\nx = 1\n" + codexHookBlockEnd + "\n"

	// Present in the middle: surrounding content preserved, separated cleanly.
	content := "before = 1\n\n" + block + "\nafter = 2\n"
	got := stripCodexHookBlock(content)
	if strings.Contains(got, codexHookBlockStart) {
		t.Errorf("block not removed:\n%s", got)
	}
	if !strings.Contains(got, "before = 1") || !strings.Contains(got, "after = 2") {
		t.Errorf("surrounding content lost:\n%s", got)
	}

	// Absent: returned unchanged.
	plain := "just = 1\n"
	if stripCodexHookBlock(plain) != plain {
		t.Errorf("content without block was modified")
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
