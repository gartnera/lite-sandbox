package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const testBin = "/usr/local/bin/lite-sandbox"

// setLaunchFlags sets the launch command's flag variables for one test and
// restores them afterwards. The zero-argument defaults are the command's own
// (see its flag registration): the tool hook on, alwaysLoad on, acceptEdits.
func setLaunchFlags(t *testing.T, opts ...func(*launchFlags)) {
	t.Helper()
	f := launchFlags{withToolHook: true, alwaysLoad: true, permissionMode: "acceptEdits"}
	for _, o := range opts {
		o(&f)
	}
	prev := launchFlags{launchWithToolHook, launchBashASTHookMode, launchAlwaysLoad, launchPermissionMode}
	t.Cleanup(func() {
		launchWithToolHook, launchBashASTHookMode = prev.withToolHook, prev.bashASTHookMode
		launchAlwaysLoad, launchPermissionMode = prev.alwaysLoad, prev.permissionMode
	})
	launchWithToolHook, launchBashASTHookMode = f.withToolHook, f.bashASTHookMode
	launchAlwaysLoad, launchPermissionMode = f.alwaysLoad, f.permissionMode
}

// launchFlags mirrors the launch command's flag variables for setLaunchFlags.
type launchFlags struct {
	withToolHook    bool
	bashASTHookMode bool
	alwaysLoad      bool
	permissionMode  string
}

func noToolHook(f *launchFlags)       { f.withToolHook = false }
func bashASTHookMode(f *launchFlags)  { f.bashASTHookMode = true }
func noAlwaysLoad(f *launchFlags)     { f.alwaysLoad = false }
func noPermissionMode(f *launchFlags) { f.permissionMode = "" }

// launchSettings builds the argv for the current flags and returns it with the
// parsed --settings document.
func launchSettings(t *testing.T, agentArgs []string) ([]string, claudeSettings) {
	t.Helper()
	argv, err := claudeLaunchArgs(testBin, agentArgs)
	if err != nil {
		t.Fatalf("claudeLaunchArgs failed: %v", err)
	}
	var settings claudeSettings
	if err := json.Unmarshal([]byte(flagValue(t, argv, "--settings")), &settings); err != nil {
		t.Fatalf("parse --settings: %v", err)
	}
	return argv, settings
}

// hookGroup returns the single PreToolUse matcher group in settings.
func hookGroup(t *testing.T, settings claudeSettings) (matcher, command string) {
	t.Helper()
	groups := asSlice(settings.Hooks["PreToolUse"])
	if len(groups) != 1 {
		t.Fatalf("expected one PreToolUse group, got %d: %v", len(groups), settings.Hooks)
	}
	group := asMap(groups[0])
	return asString(group["matcher"]), asString(asMap(asSlice(group["hooks"])[0])["command"])
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
// tool permissions plus the Bash deny, the acceptEdits permission mode, the
// hook confining the built-in file tools, and the usage directive.
func TestClaudeLaunchArgsDefault(t *testing.T) {
	setLaunchFlags(t)

	argv, settings := launchSettings(t, []string{"-p", "hello"})

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
	if server.Command != testBin || !slices.Equal(server.Args, []string{"serve-mcp", "--config-requests"}) {
		t.Errorf("server = %+v, want %s serve-mcp --config-requests", server, testBin)
	}
	if !server.AlwaysLoad {
		t.Error("alwaysLoad not set (it is on by default)")
	}

	for _, want := range mcpToolPermissions {
		if !slices.Contains(settings.Permissions.Allow, want) {
			t.Errorf("permission %q not allowed: %v", want, settings.Permissions.Allow)
		}
	}
	// The built-in Bash tool is denied outright even though the hook is on: the
	// hook's Bash branch and its filesystem branch are independent, so there is
	// no reason to weaken the block to a hook decision.
	if !slices.Contains(settings.Permissions.Deny, builtinBashPermission) {
		t.Errorf("built-in Bash not denied: %v", settings.Permissions.Deny)
	}
	if settings.Permissions.DefaultMode != "acceptEdits" {
		t.Errorf("defaultMode = %q, want acceptEdits", settings.Permissions.DefaultMode)
	}

	matcher, command := hookGroup(t, settings)
	if want := hookToolMatcher + "|" + mcpToolMatcher; matcher != want {
		t.Errorf("hook matcher = %q, want %q (the file tools are confined by default)", matcher, want)
	}
	if want := testBin + " hook --config-requests"; command != want {
		t.Errorf("hook command = %q, want %q", command, want)
	}

	if got := flagValue(t, argv, "--append-system-prompt"); got != strings.Join(claudeDirectives, "\n\n") {
		t.Errorf("--append-system-prompt = %q, want the usage directive", got)
	}
}

// TestClaudeLaunchArgsNoToolHook checks that --with-tool-hook=false falls back
// to install's default posture: Bash denied, the hook only pre-approving the
// sandbox's own MCP tools, and the built-in file tools left to Claude Code.
func TestClaudeLaunchArgsNoToolHook(t *testing.T) {
	setLaunchFlags(t, noToolHook)

	_, settings := launchSettings(t, nil)
	if !slices.Contains(settings.Permissions.Deny, builtinBashPermission) {
		t.Errorf("built-in Bash not denied: %v", settings.Permissions.Deny)
	}
	matcher, _ := hookGroup(t, settings)
	if matcher != mcpToolMatcher {
		t.Errorf("hook matcher = %q, want %q", matcher, mcpToolMatcher)
	}
}

// TestClaudeLaunchArgsPermissionMode checks that an empty --permission-mode
// leaves Claude Code's own default in place.
func TestClaudeLaunchArgsPermissionMode(t *testing.T) {
	setLaunchFlags(t, noPermissionMode)

	argv, settings := launchSettings(t, nil)
	if settings.Permissions.DefaultMode != "" {
		t.Errorf("defaultMode = %q, want it absent", settings.Permissions.DefaultMode)
	}
	if strings.Contains(flagValue(t, argv, "--settings"), "defaultMode") {
		t.Errorf("defaultMode key present in --settings: %s", flagValue(t, argv, "--settings"))
	}
}

// TestClaudeLaunchArgsBashASTHookMode checks that --bash-ast-hook-mode
// launches with no MCP server and no directive, and that Bash reaches the
// validating hook instead of being denied.
func TestClaudeLaunchArgsBashASTHookMode(t *testing.T) {
	setLaunchFlags(t, bashASTHookMode)

	argv, settings := launchSettings(t, nil)
	if slices.Contains(argv, "--mcp-config") {
		t.Errorf("--mcp-config passed in --bash-ast-hook-mode: %v", argv)
	}
	if slices.Contains(argv, "--append-system-prompt") {
		t.Errorf("usage directive passed without an MCP server to point at: %v", argv)
	}
	if len(settings.Permissions.Allow) != 0 || len(settings.Permissions.Deny) != 0 {
		t.Errorf("permissions = %+v, want no allow/deny (Bash is validated in place; a deny would suppress the hook's allow)", settings.Permissions)
	}
	matcher, command := hookGroup(t, settings)
	// The tool hook is on by default, so the matcher covers the file tools too.
	if matcher != hookToolMatcher {
		t.Errorf("hook matcher = %q, want %q", matcher, hookToolMatcher)
	}
	if want := testBin + " hook --validate-bash"; command != want {
		t.Errorf("hook command = %q, want %q", command, want)
	}
}

// TestClaudeLaunchArgsAlwaysLoadOff checks --always-load=false leaves the flag
// off the MCP server entry.
func TestClaudeLaunchArgsAlwaysLoadOff(t *testing.T) {
	setLaunchFlags(t, noAlwaysLoad)

	argv, err := claudeLaunchArgs(testBin, nil)
	if err != nil {
		t.Fatalf("claudeLaunchArgs failed: %v", err)
	}
	if strings.Contains(flagValue(t, argv, "--mcp-config"), "alwaysLoad") {
		t.Errorf("alwaysLoad present with --always-load=false: %s", flagValue(t, argv, "--mcp-config"))
	}
}

// TestLaunchUnsupportedAgent checks that an agent launch does not support
// says why and points at install instead.
func TestLaunchUnsupportedAgent(t *testing.T) {
	err := runLaunch(launchCmd, []string{"grok"})
	if err == nil {
		t.Fatal("expected an error for an unsupported agent")
	}
	for _, want := range []string{"lite-sandbox install grok", "MCP server", "codex, opencode, crush"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
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

// isolatePiLaunch points pi's agent directory and lite-sandbox's cache at
// temp directories, with no pi on PATH (so no version check).
func isolatePiLaunch(t *testing.T) (agentDir, cacheDir string) {
	t.Helper()
	agentDir = filepath.Join(t.TempDir(), "agent")
	cacheDir = t.TempDir()
	t.Setenv("PI_CODING_AGENT_DIR", agentDir)
	t.Setenv("XDG_CACHE_HOME", cacheDir)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	return agentDir, cacheDir
}

func TestPiLaunchArgs(t *testing.T) {
	setLaunchFlags(t)
	_, cacheDir := isolatePiLaunch(t)

	argv, err := piLaunchArgs(testBin, []string{"-p", "hi"})
	if err != nil {
		t.Fatalf("piLaunchArgs: %v", err)
	}
	ext := flagValue(t, argv, "-e")
	if runtime.GOOS == "linux" && !strings.HasPrefix(ext, cacheDir) {
		t.Errorf("extension %s is not in the cache directory %s", ext, cacheDir)
	}
	src, err := os.ReadFile(ext)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `"bin": "`+testBin+`"`) || !strings.Contains(string(src), `"mcp": true`) {
		t.Errorf("extension does not carry the launch configuration:\n%s", src)
	}
	if got := flagValue(t, argv, "--exclude-tools"); got != "bash" {
		t.Errorf("--exclude-tools %s, want bash", got)
	}
	if !slices.Equal(argv[len(argv)-2:], []string{"-p", "hi"}) {
		t.Errorf("agent arguments not passed last: %v", argv)
	}

	// The same configuration reuses the same file.
	argv2, err := piLaunchArgs(testBin, nil)
	if err != nil {
		t.Fatal(err)
	}
	if flagValue(t, argv2, "-e") != ext {
		t.Error("an identical launch wrote a second extension file")
	}
}

func TestPiLaunchArgsBashASTHookMode(t *testing.T) {
	setLaunchFlags(t, bashASTHookMode)
	isolatePiLaunch(t)
	argv, err := piLaunchArgs(testBin, nil)
	if err != nil {
		t.Fatalf("piLaunchArgs: %v", err)
	}
	if slices.Contains(argv, "--exclude-tools") {
		t.Errorf("built-in bash excluded in --bash-ast-hook-mode: %v", argv)
	}
	src, err := os.ReadFile(flagValue(t, argv, "-e"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "--validate-bash") {
		t.Errorf("extension does not validate bash:\n%s", src)
	}
}

func TestPiLaunchArgsRefusesWhenInstalled(t *testing.T) {
	setLaunchFlags(t)
	agentDir, _ := isolatePiLaunch(t)
	if err := writeFileMkdir(filepath.Join(agentDir, "extensions", piExtensionFile), []byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := piLaunchArgs(testBin, nil); err == nil || !strings.Contains(err.Error(), "already installed") {
		t.Fatalf("err = %v, want already installed", err)
	}
}
