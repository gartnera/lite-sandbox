package cmd

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

const testBin = "/usr/local/bin/lite-sandbox"

// setLaunchFlags sets the launch command's flag variables for one test and
// restores them afterwards.
func setLaunchFlags(t *testing.T, withToolHook, bashASTHookMode, alwaysLoad bool) {
	t.Helper()
	prevHook, prevAST, prevAlways := launchWithToolHook, launchBashASTHookMode, launchAlwaysLoad
	t.Cleanup(func() {
		launchWithToolHook, launchBashASTHookMode, launchAlwaysLoad = prevHook, prevAST, prevAlways
	})
	launchWithToolHook, launchBashASTHookMode, launchAlwaysLoad = withToolHook, bashASTHookMode, alwaysLoad
}

// flagValue returns the value that follows flag in argv.
func flagValue(t *testing.T, argv []string, flag string) string {
	t.Helper()
	i := slices.Index(argv, flag)
	if i == -1 {
		t.Fatalf("%s not found in argv: %v", flag, argv)
	}
	if i+1 >= len(argv) {
		t.Fatalf("%s has no value in argv: %v", flag, argv)
	}
	return argv[i+1]
}

// TestClaudeLaunchArgsDefault checks the default launch: the MCP server, the
// tool permissions plus the Bash deny, the subagent hook, and the usage
// directive — the same configuration `install claude` writes to disk.
func TestClaudeLaunchArgsDefault(t *testing.T) {
	setLaunchFlags(t, false, false, true)

	argv, err := claudeLaunchArgs(testBin, []string{"-p", "hello"})
	if err != nil {
		t.Fatalf("claudeLaunchArgs failed: %v", err)
	}

	// The agent's own arguments come last: --mcp-config is variadic and would
	// otherwise swallow them.
	if got := argv[len(argv)-2:]; !slices.Equal(got, []string{"-p", "hello"}) {
		t.Errorf("agent args = %v, want them last in %v", got, argv)
	}
	if i := slices.Index(argv, "--mcp-config"); i != 0 {
		t.Errorf("--mcp-config at index %d, want 0 (it is variadic, so nothing may follow its value except flags)", i)
	}

	var mcp struct {
		MCPServers map[string]mcpServerConfig `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(flagValue(t, argv, "--mcp-config")), &mcp); err != nil {
		t.Fatalf("parse --mcp-config: %v", err)
	}
	server, ok := mcp.MCPServers["lite-sandbox"]
	if !ok {
		t.Fatalf("lite-sandbox server missing from --mcp-config: %v", mcp.MCPServers)
	}
	if server.Command != testBin || !slices.Equal(server.Args, []string{"serve-mcp"}) {
		t.Errorf("server = %+v, want %s serve-mcp", server, testBin)
	}
	if !server.AlwaysLoad {
		t.Error("alwaysLoad not set (it is on by default)")
	}

	var settings claudeSettings
	if err := json.Unmarshal([]byte(flagValue(t, argv, "--settings")), &settings); err != nil {
		t.Fatalf("parse --settings: %v", err)
	}
	for _, want := range mcpToolPermissions {
		if !slices.Contains(settings.Permissions.Allow, want) {
			t.Errorf("permission %q not allowed: %v", want, settings.Permissions.Allow)
		}
	}
	if !slices.Contains(settings.Permissions.Deny, builtinBashPermission) {
		t.Errorf("built-in Bash not denied: %v", settings.Permissions.Deny)
	}
	if settings.Hooks == nil {
		t.Fatal("no PreToolUse hook in --settings")
	}
	group := asMap(asSlice(settings.Hooks["PreToolUse"])[0])
	if got := asString(group["matcher"]); got != mcpToolMatcher {
		t.Errorf("hook matcher = %q, want %q", got, mcpToolMatcher)
	}
	if got := asString(asMap(asSlice(group["hooks"])[0])["command"]); got != testBin+" hook" {
		t.Errorf("hook command = %q, want %q", got, testBin+" hook")
	}

	if got := flagValue(t, argv, "--append-system-prompt"); got != claudeDirective {
		t.Errorf("--append-system-prompt = %q, want the usage directive", got)
	}
}

// TestClaudeLaunchArgsWithToolHook checks that --with-tool-hook moves the Bash
// block from the permission deny to the hook, which then also governs the
// filesystem tools.
func TestClaudeLaunchArgsWithToolHook(t *testing.T) {
	setLaunchFlags(t, true, false, true)

	argv, err := claudeLaunchArgs(testBin, nil)
	if err != nil {
		t.Fatalf("claudeLaunchArgs failed: %v", err)
	}
	var settings claudeSettings
	if err := json.Unmarshal([]byte(flagValue(t, argv, "--settings")), &settings); err != nil {
		t.Fatalf("parse --settings: %v", err)
	}
	if slices.Contains(settings.Permissions.Deny, builtinBashPermission) {
		t.Error("built-in Bash denied by permission rule; the deny would suppress the hook's decision")
	}
	group := asMap(asSlice(settings.Hooks["PreToolUse"])[0])
	if want := hookToolMatcher + "|" + mcpToolMatcher; asString(group["matcher"]) != want {
		t.Errorf("hook matcher = %q, want %q", asString(group["matcher"]), want)
	}
}

// TestClaudeLaunchArgsBashASTHookMode checks that --bash-ast-hook-mode
// launches with no MCP server, no directive, and the validating hook.
func TestClaudeLaunchArgsBashASTHookMode(t *testing.T) {
	setLaunchFlags(t, false, true, true)

	argv, err := claudeLaunchArgs(testBin, nil)
	if err != nil {
		t.Fatalf("claudeLaunchArgs failed: %v", err)
	}
	if slices.Contains(argv, "--mcp-config") {
		t.Errorf("--mcp-config passed in --bash-ast-hook-mode: %v", argv)
	}
	if slices.Contains(argv, "--append-system-prompt") {
		t.Errorf("usage directive passed without an MCP server to point at: %v", argv)
	}
	var settings claudeSettings
	if err := json.Unmarshal([]byte(flagValue(t, argv, "--settings")), &settings); err != nil {
		t.Fatalf("parse --settings: %v", err)
	}
	if len(settings.Permissions.Allow) != 0 || len(settings.Permissions.Deny) != 0 {
		t.Errorf("permissions = %+v, want none (Bash is validated in place)", settings.Permissions)
	}
	group := asMap(asSlice(settings.Hooks["PreToolUse"])[0])
	if asString(group["matcher"]) != bashValidateMatcher {
		t.Errorf("hook matcher = %q, want %q", asString(group["matcher"]), bashValidateMatcher)
	}
	if want := testBin + " hook --validate-bash"; asString(asMap(asSlice(group["hooks"])[0])["command"]) != want {
		t.Errorf("hook command = %q, want %q", asString(asMap(asSlice(group["hooks"])[0])["command"]), want)
	}
}

// TestClaudeLaunchArgsAlwaysLoadOff checks --always-load=false leaves the flag
// off the MCP server entry.
func TestClaudeLaunchArgsAlwaysLoadOff(t *testing.T) {
	setLaunchFlags(t, false, false, false)

	argv, err := claudeLaunchArgs(testBin, nil)
	if err != nil {
		t.Fatalf("claudeLaunchArgs failed: %v", err)
	}
	if strings.Contains(flagValue(t, argv, "--mcp-config"), "alwaysLoad") {
		t.Errorf("alwaysLoad present with --always-load=false: %s", flagValue(t, argv, "--mcp-config"))
	}
}

// TestLaunchUnsupportedAgent checks that an agent launch does not support
// points at install instead.
func TestLaunchUnsupportedAgent(t *testing.T) {
	err := runLaunch(launchCmd, []string{"codex"})
	if err == nil {
		t.Fatal("expected an error for an unsupported agent")
	}
	if !strings.Contains(err.Error(), "lite-sandbox install codex") {
		t.Errorf("error %q does not point at install", err)
	}
}

// TestShellQuote covers the --dry-run rendering: arguments with shell
// metacharacters (every generated JSON document has them) must come back
// quoted, and plain ones unquoted.
func TestShellQuote(t *testing.T) {
	got := shellQuote([]string{"claude", "--settings", `{"a":"b"}`, "-p", "it's here"})
	want := `claude --settings '{"a":"b"}' -p 'it'\''s here'`
	if got != want {
		t.Errorf("shellQuote = %s, want %s", got, want)
	}
}
