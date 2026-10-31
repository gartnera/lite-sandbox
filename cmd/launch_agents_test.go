package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/pflag"
)

// isolateUserDirs points HOME and the XDG cache at temp directories, so
// launchCacheDir and the agents' config lookups stay inside the test.
func isolateUserDirs(t *testing.T) (home string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	return home
}

// codexOverrides returns the -c overrides in argv as key → TOML value, after
// checking each value parses as TOML (Codex falls back to a literal string
// for one that doesn't, which would silently change its meaning).
func codexOverrides(t *testing.T, argv []string) map[string]any {
	t.Helper()
	out := map[string]any{}
	for i := 0; i < len(argv); i++ {
		if argv[i] != "-c" {
			continue
		}
		key, value, ok := strings.Cut(argv[i+1], "=")
		if !ok {
			t.Fatalf("-c %q is not key=value", argv[i+1])
		}
		var doc map[string]any
		if err := toml.Unmarshal([]byte("v = "+value), &doc); err != nil {
			t.Fatalf("-c %s: value %q is not TOML: %v", key, value, err)
		}
		out[key] = doc["v"]
	}
	return out
}

func codexSpec(t *testing.T, agentArgs ...string) (launchSpec, map[string]any) {
	t.Helper()
	spec, err := codexLaunchSpec(testBin, agentArgs)
	if err != nil {
		t.Fatalf("codexLaunchSpec: %v", err)
	}
	return spec, codexOverrides(t, spec.args)
}

// TestCodexLaunchSpecDefault checks the default Codex launch: the MCP server
// and directive as overrides, the built-in shell removed, and the file-tool
// hook passed with the trust bypass it needs to run.
func TestCodexLaunchSpecDefault(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv("CODEX_HOME", t.TempDir())
	setLaunchFlags(t)

	spec, ov := codexSpec(t, "exec", "hi")
	if got := spec.args[len(spec.args)-2:]; !slices.Equal(got, []string{"exec", "hi"}) {
		t.Errorf("agent args = %v, want them last in %v", got, spec.args)
	}
	if ov["mcp_servers.lite-sandbox.command"] != testBin {
		t.Errorf("MCP command = %v", ov["mcp_servers.lite-sandbox.command"])
	}
	if args, _ := ov["mcp_servers.lite-sandbox.args"].([]any); !slices.Equal(args, []any{"serve-mcp"}) {
		t.Errorf("MCP args = %v", ov["mcp_servers.lite-sandbox.args"])
	}
	if ov["mcp_servers.lite-sandbox.default_tools_approval_mode"] != "approve" {
		t.Errorf("approval mode = %v", ov["mcp_servers.lite-sandbox.default_tools_approval_mode"])
	}
	if _, ok := ov["mcp_servers.lite-sandbox.omit_tools_from"]; !ok {
		t.Error("omit_tools_from missing (always-load is on by default)")
	}
	if ov["developer_instructions"] != codexLaunchDirective {
		t.Errorf("developer_instructions = %v", ov["developer_instructions"])
	}
	if i := slices.Index(spec.args, "--disable"); i == -1 || spec.args[i+1] != "shell_tool" {
		t.Errorf("built-in shell not disabled: %v", spec.args)
	}

	groups, _ := ov["hooks.PreToolUse"].([]any)
	if len(groups) != 1 {
		t.Fatalf("hooks.PreToolUse = %v, want one group", ov["hooks.PreToolUse"])
	}
	group := asMap(groups[0])
	handler := asMap(asSlice(group["hooks"])[0])
	if group["matcher"] != hookToolMatcher || handler["type"] != "command" || handler["command"] != testBin+" hook" {
		t.Errorf("hook = %v", group)
	}
	if !slices.Contains(spec.args, "--dangerously-bypass-hook-trust") {
		t.Errorf("hook passed without the trust bypass; Codex would skip it: %v", spec.args)
	}
	if i := slices.Index(spec.args, "--enable"); i == -1 || spec.args[i+1] != "hooks" {
		t.Errorf("hooks feature not enabled for the hook: %v", spec.args)
	}
	if len(spec.notes) == 0 {
		t.Error("no note telling the user hook trust is bypassed")
	}
}

// TestCodexLaunchSpecNoToolHook checks that without the hook, nothing asks
// Codex to bypass hook trust: the shell is removed, not redirected.
func TestCodexLaunchSpecNoToolHook(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv("CODEX_HOME", t.TempDir())
	setLaunchFlags(t, noToolHook, noAlwaysLoad)

	spec, ov := codexSpec(t)
	if _, ok := ov["hooks.PreToolUse"]; ok {
		t.Errorf("hook registered with --with-tool-hook=false: %v", ov["hooks.PreToolUse"])
	}
	if slices.Contains(spec.args, "--dangerously-bypass-hook-trust") {
		t.Errorf("hook trust bypassed with no hook: %v", spec.args)
	}
	if _, ok := ov["mcp_servers.lite-sandbox.omit_tools_from"]; ok {
		t.Error("omit_tools_from set with --always-load=false")
	}
	if !slices.Contains(spec.args, "shell_tool") {
		t.Errorf("built-in shell not disabled: %v", spec.args)
	}
}

// TestCodexLaunchSpecBashASTHookMode checks the shell stays enabled for the
// validating hook, with no MCP server or directive.
func TestCodexLaunchSpecBashASTHookMode(t *testing.T) {
	isolateUserDirs(t)
	t.Setenv("CODEX_HOME", t.TempDir())
	setLaunchFlags(t, bashASTHookMode, noToolHook)

	spec, ov := codexSpec(t)
	for key := range ov {
		if strings.HasPrefix(key, "mcp_servers.") || key == "developer_instructions" {
			t.Errorf("%s set in --bash-ast-hook-mode", key)
		}
	}
	if slices.Contains(spec.args, "shell_tool") {
		t.Errorf("built-in shell disabled, but the hook is meant to validate it: %v", spec.args)
	}
	group := asMap(asSlice(ov["hooks.PreToolUse"])[0])
	if group["matcher"] != bashValidateMatcher || asMap(asSlice(group["hooks"])[0])["command"] != testBin+" hook --validate-bash" {
		t.Errorf("hook = %v", group)
	}
	if !slices.Contains(spec.args, "--dangerously-bypass-hook-trust") {
		t.Errorf("trust bypass missing: %v", spec.args)
	}
}

// TestCodexLaunchSpecKeepsUserDeveloperInstructions checks the override
// carries the user's own developer_instructions instead of replacing them.
func TestCodexLaunchSpecKeepsUserDeveloperInstructions(t *testing.T) {
	isolateUserDirs(t)
	codexDir := t.TempDir()
	t.Setenv("CODEX_HOME", codexDir)
	if err := os.WriteFile(filepath.Join(codexDir, "config.toml"), []byte(`developer_instructions = "be \"terse\""`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	setLaunchFlags(t)

	_, ov := codexSpec(t)
	if want := `be "terse"` + "\n\n" + codexLaunchDirective; ov["developer_instructions"] != want {
		t.Errorf("developer_instructions = %q, want %q", ov["developer_instructions"], want)
	}
}

// opencodeConfig parses the OPENCODE_CONFIG_CONTENT a spec sets.
func opencodeConfig(t *testing.T, spec launchSpec) map[string]any {
	t.Helper()
	for _, kv := range spec.env {
		if v, ok := strings.CutPrefix(kv, "OPENCODE_CONFIG_CONTENT="); ok {
			var cfg map[string]any
			if err := json.Unmarshal([]byte(v), &cfg); err != nil {
				t.Fatalf("parse OPENCODE_CONFIG_CONTENT: %v", err)
			}
			return cfg
		}
	}
	t.Fatalf("OPENCODE_CONFIG_CONTENT not set: %v", spec.env)
	return nil
}

// TestOpencodeLaunchSpec checks the inline config: the MCP server, the bash
// deny, and an instructions file holding the directive in lite-sandbox's
// cache (not opencode's config directory).
func TestOpencodeLaunchSpec(t *testing.T) {
	home := isolateUserDirs(t)
	t.Setenv("OPENCODE_CONFIG_CONTENT", "")

	spec, err := opencodeLaunchSpec(testBin, []string{"run", "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(spec.args, []string{"run", "hi"}) {
		t.Errorf("args = %v, want the agent's own untouched", spec.args)
	}
	cfg := opencodeConfig(t, spec)
	server := asMap(asMap(cfg["mcp"])["lite-sandbox"])
	if cmd := asSlice(server["command"]); len(cmd) != 2 || cmd[0] != testBin || cmd[1] != "serve-mcp" || server["type"] != "local" {
		t.Errorf("mcp server = %v", server)
	}
	perm := asMap(cfg["permission"])
	if perm["bash"] != "deny" || perm["lite-sandbox*"] != "allow" {
		t.Errorf("permission = %v", perm)
	}
	instructions := asSlice(cfg["instructions"])
	if len(instructions) != 1 {
		t.Fatalf("instructions = %v", instructions)
	}
	path := asString(instructions[0])
	if runtime.GOOS == "linux" && !strings.HasPrefix(path, filepath.Join(home, ".cache", "lite-sandbox", "launch")) {
		t.Errorf("directive file %s is not in lite-sandbox's cache", path)
	}
	if data, err := os.ReadFile(path); err != nil || !strings.Contains(string(data), opencodeDirective) {
		t.Errorf("directive file %s: %v %q", path, err, data)
	}
	if dirExists(filepath.Join(home, ".config", "opencode")) {
		t.Error("launch created opencode's config directory")
	}
}

// TestOpencodeLaunchConfigMergesExisting checks a user's own
// OPENCODE_CONFIG_CONTENT survives: unrelated keys kept, arrays appended, and
// a bare-string permission kept as the catch-all rule.
func TestOpencodeLaunchConfigMergesExisting(t *testing.T) {
	existing := `{"model":"x/y","instructions":["mine.md"],"permission":"ask","mcp":{"other":{"type":"local","command":["o"]}}}`
	content, err := opencodeLaunchConfig(testBin, "/cache/lite-sandbox.md", existing)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(content), &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg["model"] != "x/y" {
		t.Errorf("model = %v", cfg["model"])
	}
	if got := asSlice(cfg["instructions"]); len(got) != 2 || got[0] != "mine.md" || got[1] != "/cache/lite-sandbox.md" {
		t.Errorf("instructions = %v", got)
	}
	perm := asMap(cfg["permission"])
	if perm["*"] != "ask" || perm["bash"] != "deny" {
		t.Errorf("permission = %v", perm)
	}
	mcp := asMap(cfg["mcp"])
	if mcp["other"] == nil || mcp["lite-sandbox"] == nil {
		t.Errorf("mcp = %v", mcp)
	}

	if _, err := opencodeLaunchConfig(testBin, "/x", "not json"); err == nil {
		t.Error("invalid OPENCODE_CONFIG_CONTENT accepted")
	}
}

// stubCrushVersion makes crushVersionOutput report version for one test.
func stubCrushVersion(t *testing.T, version string) {
	t.Helper()
	prev := crushVersionOutput
	crushVersionOutput = func() (string, error) { return "crush version " + version, nil }
	t.Cleanup(func() { crushVersionOutput = prev })
}

// crushLaunchDir returns the stand-in global config directory a spec points
// CRUSH_GLOBAL_CONFIG at.
func crushLaunchDir(t *testing.T, spec launchSpec) string {
	t.Helper()
	for _, kv := range spec.env {
		if v, ok := strings.CutPrefix(kv, "CRUSH_GLOBAL_CONFIG="); ok {
			return v
		}
	}
	t.Fatalf("CRUSH_GLOBAL_CONFIG not set: %v", spec.env)
	return ""
}

// TestCrushLaunchSpec checks the stand-in config directory: the user's
// crushrc sourced from their directory, their crush.json linked, the
// sandbox's rules added, and the context paths covering their files and the
// directive — with the user's own directory left untouched.
func TestCrushLaunchSpec(t *testing.T) {
	isolateUserDirs(t)
	stubCrushVersion(t, "v0.92.0")
	userDir := t.TempDir()
	t.Setenv("CRUSH_GLOBAL_CONFIG", userDir)
	userRC := "provider add mock --type openai-compat\n"
	userJSON := `{"options":{"debug":true}}`
	if err := os.WriteFile(filepath.Join(userDir, "crushrc"), []byte(userRC), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(userDir, "crush.json"), []byte(userJSON), 0o644); err != nil {
		t.Fatal(err)
	}

	spec, err := crushLaunchSpec(testBin, []string{"run", "hi"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(spec.args, []string{"run", "hi"}) {
		t.Errorf("args = %v", spec.args)
	}
	dir := crushLaunchDir(t, spec)
	if dir == userDir {
		t.Fatal("CRUSH_GLOBAL_CONFIG still points at the user's directory")
	}

	rc, err := os.ReadFile(filepath.Join(dir, "crushrc"))
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := crushRCRules(testBin)
	for _, want := range []string{
		"(cd " + userDir + " && source ./crushrc)\n",
		rules,
		"option global-context-path " + filepath.Join(userDir, "CRUSH.md") + "\n",
		"option global-context-path " + filepath.Join(filepath.Dir(userDir), "AGENTS.md") + "\n",
		"option global-context-path " + filepath.Join(dir, "lite-sandbox.md") + "\n",
	} {
		if !strings.Contains(string(rc), want) {
			t.Errorf("crushrc missing %q:\n%s", want, rc)
		}
	}
	if strings.Index(string(rc), "source") > strings.Index(string(rc), "mcp add") {
		t.Errorf("the user's crushrc must run before the sandbox's rules:\n%s", rc)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "crush.json")); err != nil || string(data) != userJSON {
		t.Errorf("crush.json not linked to the user's: %v %q", err, data)
	}
	if data, err := os.ReadFile(filepath.Join(dir, "lite-sandbox.md")); err != nil || !strings.Contains(string(data), crushDirective) {
		t.Errorf("directive file: %v %q", err, data)
	}
	if data, _ := os.ReadFile(filepath.Join(userDir, "crushrc")); string(data) != userRC {
		t.Errorf("the user's crushrc was modified: %q", data)
	}

	// Without a user config, nothing is sourced and a stale link goes away.
	if err := os.Remove(filepath.Join(userDir, "crushrc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(userDir, "crush.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := crushLaunchSpec(testBin, nil); err != nil {
		t.Fatal(err)
	}
	if rc, _ := os.ReadFile(filepath.Join(dir, "crushrc")); strings.Contains(string(rc), "source") {
		t.Errorf("crushrc sources a crushrc the user doesn't have:\n%s", rc)
	}
	if _, err := os.Lstat(filepath.Join(dir, "crush.json")); !os.IsNotExist(err) {
		t.Errorf("stale crush.json link left behind: %v", err)
	}
}

// TestCrushLaunchSpecDirPerConfig checks launches for different config
// directories don't share (and so rewrite) one stand-in crushrc, while
// repeated launches for the same one reuse theirs.
func TestCrushLaunchSpecDirPerConfig(t *testing.T) {
	isolateUserDirs(t)
	stubCrushVersion(t, "v0.92.0")
	dirFor := func(userDir string) string {
		t.Setenv("CRUSH_GLOBAL_CONFIG", userDir)
		spec, err := crushLaunchSpec(testBin, nil)
		if err != nil {
			t.Fatal(err)
		}
		return crushLaunchDir(t, spec)
	}
	a, b := t.TempDir(), t.TempDir()
	if dirFor(a) == dirFor(b) {
		t.Error("two config directories share one stand-in directory")
	}
	if dirFor(a) != dirFor(a) {
		t.Error("the same config directory got a new stand-in directory")
	}
}

// TestCrushLaunchSpecOldCrush checks a crush that predates crushrc is refused.
func TestCrushLaunchSpecOldCrush(t *testing.T) {
	isolateUserDirs(t)
	stubCrushVersion(t, "v0.80.1")
	t.Setenv("CRUSH_GLOBAL_CONFIG", t.TempDir())
	if _, err := crushLaunchSpec(testBin, nil); err == nil || !strings.Contains(err.Error(), "v0.88.0") {
		t.Errorf("err = %v, want a crush version error", err)
	}
}

// TestCheckLaunchFlags checks that flags with no effect on the chosen agent
// are refused when set explicitly, but their defaults don't get in the way.
func TestCheckLaunchFlags(t *testing.T) {
	targets := launchTargets()
	target := func(name string) launchTarget {
		return targets[slices.IndexFunc(targets, func(t launchTarget) bool { return t.name == name })]
	}
	flags := func(set ...string) *pflag.FlagSet {
		fs := pflag.NewFlagSet("launch", pflag.ContinueOnError)
		fs.String("permission-mode", "acceptEdits", "")
		fs.Bool("with-tool-hook", true, "")
		fs.Bool("bash-ast-hook-mode", false, "")
		for _, f := range set {
			name, value, _ := strings.Cut(f, "=")
			if err := fs.Set(name, value); err != nil {
				t.Fatal(err)
			}
		}
		return fs
	}

	for _, name := range []string{"claude", "codex", "opencode", "crush", "pi"} {
		if err := checkLaunchFlags(target(name), flags()); err != nil {
			t.Errorf("%s with default flags: %v", name, err)
		}
	}
	if err := checkLaunchFlags(target("codex"), flags("permission-mode=plan")); err == nil {
		t.Error("--permission-mode accepted for codex")
	}
	if err := checkLaunchFlags(target("opencode"), flags("with-tool-hook=true")); err == nil {
		t.Error("explicit --with-tool-hook accepted for opencode")
	}
	if err := checkLaunchFlags(target("crush"), flags("with-tool-hook=false")); err != nil {
		t.Errorf("--with-tool-hook=false refused for crush: %v", err)
	}

	if err := checkLaunchFlags(target("crush"), flags("bash-ast-hook-mode=true")); err == nil {
		t.Error("--bash-ast-hook-mode accepted for crush")
	}
	if err := checkLaunchFlags(target("codex"), flags("bash-ast-hook-mode=true")); err != nil {
		t.Errorf("--bash-ast-hook-mode refused for codex: %v", err)
	}

	// pi's file tools are always confined.
	if err := checkLaunchFlags(target("pi"), flags()); err != nil {
		t.Errorf("pi with default flags: %v", err)
	}
	if err := checkLaunchFlags(target("pi"), flags("with-tool-hook=false")); err == nil {
		t.Error("--with-tool-hook=false accepted for pi")
	}
	if err := checkLaunchFlags(target("pi"), flags("bash-ast-hook-mode=true")); err != nil {
		t.Errorf("--bash-ast-hook-mode refused for pi: %v", err)
	}
	if err := checkLaunchFlags(target("pi"), flags("permission-mode=plan")); err == nil {
		t.Error("--permission-mode accepted for pi")
	}
}

// TestWithEnv checks launch's variables replace inherited ones of the same
// name rather than being shadowed by them.
func TestWithEnv(t *testing.T) {
	got := withEnv([]string{"A=1", "AB=2", "B=3"}, []string{"A=x", "C=y"})
	want := []string{"AB=2", "B=3", "A=x", "C=y"}
	if !slices.Equal(got, want) {
		t.Errorf("withEnv = %v, want %v", got, want)
	}
}
