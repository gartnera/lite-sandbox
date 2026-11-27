package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/internal/hook"
)

// runOpencodeHook feeds runHook a tool call the way lite-sandbox's opencode
// plugin forwards it, and returns the decision, or nil when the hook deferred.
func runOpencodeHook(t *testing.T, cwd, tool string, input any, opts hookOptions) *hook.Decision {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse",
		"opencode_event":  hook.OpencodeEventToolExecuteBefore,
		"session_id":      "ses_1",
		"cwd":             cwd,
		"tool_name":       tool,
		"tool_input":      input,
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	c := &cobra.Command{}
	c.SetIn(bytes.NewReader(payload))
	c.SetOut(&out)
	c.SetErr(&bytes.Buffer{})
	if err := runHook(c, opts); err != nil {
		t.Fatalf("runHook: %v", err)
	}
	if out.Len() == 0 {
		return nil
	}
	var d hook.Decision
	if err := json.Unmarshal(out.Bytes(), &d); err != nil {
		t.Fatalf("decision is not JSON: %v\n%s", err, out.String())
	}
	return &d
}

func TestOpencodeHookFileTools(t *testing.T) {
	isolateConfig(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	cwd := t.TempDir()
	outside := t.TempDir()
	patch := func(lines ...string) map[string]any {
		return map[string]any{"patchText": strings.Join(append(append([]string{"*** Begin Patch"}, lines...), "*** End Patch"), "\n")}
	}

	tests := []struct {
		name     string
		tool     string
		input    any
		wantDeny bool
	}{
		{"read inside", hook.OpencodeToolRead, map[string]any{"path": "src/main.go"}, false},
		{"read inside with paging", hook.OpencodeToolRead, map[string]any{"path": "a.go", "offset": 2, "limit": 10}, false},
		{"read outside", hook.OpencodeToolRead, map[string]any{"path": filepath.Join(outside, "secret")}, true},
		{"read home via tilde", hook.OpencodeToolRead, map[string]any{"path": "~/notes.txt"}, true},
		{"read home itself", hook.OpencodeToolRead, map[string]any{"path": "~"}, true},
		{"read traversal", hook.OpencodeToolRead, map[string]any{"path": "../../etc/passwd"}, true},
		{"glob workspace default", hook.OpencodeToolGlob, map[string]any{"pattern": "*.go"}, false},
		{"glob outside", hook.OpencodeToolGlob, map[string]any{"pattern": "*", "path": outside}, true},
		{"grep workspace default", hook.OpencodeToolGrep, map[string]any{"pattern": "TODO"}, false},
		{"grep home", hook.OpencodeToolGrep, map[string]any{"pattern": "TODO", "path": "~"}, true},
		{"write inside", hook.OpencodeToolWrite, map[string]any{"path": "a.go", "content": "x"}, false},
		{"write outside", hook.OpencodeToolWrite, map[string]any{"path": filepath.Join(outside, "x"), "content": "x"}, true},
		{"edit inside", hook.OpencodeToolEdit, map[string]any{"path": "a.go", "oldString": "a", "newString": "b"}, false},
		{"edit into .git", hook.OpencodeToolEdit, map[string]any{"path": ".git/hooks/pre-commit", "oldString": "a", "newString": "b"}, true},
		{"write project opencode.json", hook.OpencodeToolWrite, map[string]any{"path": "opencode.json", "content": "{}"}, true},
		{"write project .opencode plugin", hook.OpencodeToolWrite, map[string]any{"path": ".opencode/plugins/x.ts", "content": "x"}, true},
		{"write project .claude settings", hook.OpencodeToolWrite, map[string]any{"path": ".claude/settings.json", "content": "{}"}, true},
		{"write project AGENTS.md", hook.OpencodeToolWrite, map[string]any{"path": "AGENTS.md", "content": "x"}, false},
		{"patch inside", hook.OpencodeToolPatch, patch("*** Add File: a.go", "+x", "*** Update File: b.go", "@@", "-a", "+b"), false},
		{"patch adds outside", hook.OpencodeToolPatch, patch("*** Add File: "+filepath.Join(outside, "x"), "+x"), true},
		{"patch deletes outside", hook.OpencodeToolPatch, patch("*** Delete File: ../x"), true},
		{"patch moves outside", hook.OpencodeToolPatch, patch("*** Update File: a.go", "*** Move to: ~/a.go", "@@", "-a", "+b"), true},
		// opencode trims a header line before matching it, so an indented
		// header is still a hunk.
		{"patch indented header", hook.OpencodeToolPatch, patch("   *** Add File: "+filepath.Join(outside, "x"), "+x"), true},
		{"patch into .git", hook.OpencodeToolPatch, patch("*** Add File: .git/config", "+x"), true},
		// JavaScript's trim() strips a byte order mark, which Go's TrimSpace
		// keeps: around a header or a path it must not hide the target.
		{"patch header after a BOM", hook.OpencodeToolPatch, patch("\uFEFF*** Add File: ~/.bashrc", "+x"), true},
		{"patch path before a BOM", hook.OpencodeToolPatch, patch("*** Add File: opencode.json\uFEFF", "+x"), true},
		{"patch path in Unicode spaces", hook.OpencodeToolPatch, patch("*** Add File:\u00a0../x\u3000", "+x"), true},
		{"image written inside", hook.OpencodeToolGenerateImage, map[string]any{"prompt": "a cat", "path": "out/cat"}, false},
		{"image written outside", hook.OpencodeToolGenerateImage, map[string]any{"prompt": "a cat", "path": filepath.Join(outside, "cat")}, true},
		{"image reads outside", hook.OpencodeToolGenerateImage, map[string]any{"prompt": "a cat", "images": []string{"a.png", filepath.Join(outside, "b.png")}}, true},
		{"image reads a URL", hook.OpencodeToolGenerateImage, map[string]any{"prompt": "a cat", "images": []string{"https://example.com/a.png"}}, false},
		{"video starts outside", hook.OpencodeToolGenerateVideo, map[string]any{"prompt": "a cat", "start": "~/a.png"}, true},
		{"video references outside", hook.OpencodeToolGenerateVideo, map[string]any{"prompt": "a cat", "references": []string{filepath.Join(outside, "a.mp4")}}, true},
		{"video inside", hook.OpencodeToolGenerateVideo, map[string]any{"prompt": "a cat", "end": "b.png", "path": "out/v"}, false},
		// Keys are matched exactly, as JavaScript reads them.
		{"case-folded duplicate key", hook.OpencodeToolRead, map[string]any{"path": filepath.Join(outside, "secret"), "PATH": "a.go"}, true},
		// Input the hook can't read is refused rather than let through.
		{"path of the wrong type", hook.OpencodeToolWrite, map[string]any{"path": []string{filepath.Join(outside, "x")}, "content": "x"}, true},
		{"input not an object", hook.OpencodeToolRead, "/etc/passwd", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := runOpencodeHook(t, cwd, tt.tool, tt.input, hookOptions{configRequests: true})
			if got := decisionOf(d) == hook.DecisionDeny; got != tt.wantDeny {
				t.Fatalf("deny = %v, want %v (decision %+v)", got, tt.wantDeny, d)
			}
		})
	}
}

// TestOpencodeHookOpenMode checks the open mode only audits opencode's file
// tools, as it does every other agent's, including input it can't read.
func TestOpencodeHookOpenMode(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("mode: open\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITE_SANDBOX_CONFIG", cfgPath)
	outside := t.TempDir()
	for _, input := range []map[string]any{
		{"path": filepath.Join(outside, "secret")},
		{"path": 7},
	} {
		if d := runOpencodeHook(t, cwd, hook.OpencodeToolRead, input, hookOptions{}); decisionOf(d) == hook.DecisionDeny {
			t.Errorf("%v: decision = %+v, want no denial in open mode", input, d)
		}
	}
}

func TestOpencodeHookAgentConfigWriteDenied(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	// opencode's prompt could be answered unattended (run --auto), so a write
	// to agent configuration is denied, not asked about.
	d := runOpencodeHook(t, cwd, hook.OpencodeToolWrite, map[string]any{"path": ".opencode/plugins/x.ts", "content": "x"}, hookOptions{configRequests: true})
	if decisionOf(d) != hook.DecisionDeny {
		t.Fatalf("decision = %+v, want deny", d)
	}
}

func TestOpencodeHookShellRedirect(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	for _, opts := range []hookOptions{{}, {configRequests: true}, {validateBash: true}} {
		d := runOpencodeHook(t, cwd, hook.OpencodeToolShell, map[string]any{"command": "ls"}, opts)
		if decisionOf(d) != hook.DecisionDeny {
			t.Fatalf("%+v: decision = %+v, want deny", opts, d)
		}
		if reason := d.HookSpecificOutput.PermissionDecisionReason; !strings.Contains(reason, `tools["lite-sandbox"].bash`) {
			t.Errorf("reason %q does not name the sandbox's Code Mode tool", reason)
		}
	}
}

func TestOpencodeHookMCPTools(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	for _, tool := range []string{"lite-sandbox_bash", "lite-sandbox_list_shells", "lite-sandbox_kill_shell"} {
		if d := runOpencodeHook(t, cwd, tool, map[string]any{"command": "ls"}, hookOptions{configRequests: true}); decisionOf(d) != hook.DecisionAllow {
			t.Errorf("%s: decision = %+v, want allow", tool, d)
		}
	}
	// Other agents' spellings are some other tool to opencode, as are
	// opencode's own tools the hook doesn't govern: nothing to enforce. The
	// hook still answers, since the plugin rejects a call it gets no answer
	// for.
	for _, tool := range []string{mcpToolPrefix + "bash", piMCPToolPrefix + "bash", "webfetch"} {
		d := runOpencodeHook(t, cwd, tool, map[string]any{"command": "ls"}, hookOptions{})
		if decisionOf(d) != hook.DecisionAllow || !strings.Contains(d.HookSpecificOutput.PermissionDecisionReason, "nothing to enforce") {
			t.Errorf("%s from opencode: decision = %+v, want the explicit no-objection allow", tool, d)
		}
	}
}

// TestOpencodeHookConfigRequest checks a config request from opencode is put
// to the user, as from Claude Code, with the request on the reason's first
// line: the plugin names the approval prompt after it.
func TestOpencodeHookConfigRequest(t *testing.T) {
	isolateConfig(t)
	isolateConfigRequests(t)
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const command = "lite-sandbox config commands allow make"
	d := runOpencodeHook(t, cwd, "lite-sandbox_bash", map[string]any{"command": command}, hookOptions{configRequests: true})
	if decisionOf(d) != hook.DecisionAsk {
		t.Fatalf("decision = %+v, want ask", d)
	}
	if first, _, _ := strings.Cut(d.HookSpecificOutput.PermissionDecisionReason, "\n"); first != command {
		t.Errorf("reason's first line = %q, want the request", first)
	}
}

// TestOpencodeHookAskCommand checks an opencode call to the sandbox's bash
// tool that runs an ask: true command is answered "ask" (the plugin then puts
// it to the user) and records the approval the server consumes.
func TestOpencodeHookAskCommand(t *testing.T) {
	dir, c := setupAskProject(t, askConfig, serveOptions{configRequests: true})
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	const command = "rm f"
	d := runOpencodeHook(t, dir, "lite-sandbox_bash", map[string]any{"command": command}, hookOptions{configRequests: true})
	if decisionOf(d) != hook.DecisionAsk {
		t.Fatalf("hook decision = %+v, want ask", d)
	}
	// The prompt is titled after the reason, so it leads with the command.
	reason := d.HookSpecificOutput.PermissionDecisionReason
	if first, rest, _ := strings.Cut(reason, "\n"); first != command || strings.Contains(rest, "lite-sandbox:") {
		t.Errorf("reason = %q, want the command, then what asks about it", reason)
	}
	// A command the prompt can't show as it is is refused rather than asked.
	d = runOpencodeHook(t, dir, "lite-sandbox_bash", map[string]any{"command": "true\nrm f"}, hookOptions{configRequests: true})
	if decisionOf(d) != hook.DecisionDeny {
		t.Errorf("multi-line command: decision = %+v, want deny", d)
	}
	if text, isErr := runBash(t, c, command); isErr {
		t.Fatalf("approved call failed: %s", text)
	}
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatal("approved rm did not run")
	}
}

func TestOpencodeModelPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("OPENCODE_TEST_HOME", "") // restored after the test
	os.Unsetenv("OPENCODE_TEST_HOME")
	for _, tt := range []struct{ in, want string }{
		{"a.go", "a.go"},
		{"~", home},
		{"~/x", filepath.Join(home, "x")},
		{"~user/x", "~user/x"},
		{"@a.go", "@a.go"},
		{"/etc/passwd", "/etc/passwd"},
	} {
		if got := hook.OpencodeModelPath(tt.in); got != tt.want {
			t.Errorf("OpencodeModelPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestOpencodePluginConfig checks the plugin forwards every tool the hook
// models, and renders with its configuration in place.
func TestOpencodePluginConfig(t *testing.T) {
	cfg := newOpencodePluginConfig(testBin)
	for _, tool := range hook.OpencodeHookTools {
		if !hook.IsOpencodeTool(tool) {
			t.Errorf("plugin forwards %s, which the hook does not model", tool)
		}
	}
	if !slices.Contains(cfg.Tools, hook.OpencodeToolShell) || cfg.SandboxBash != "lite-sandbox_bash" {
		t.Errorf("config = %+v", cfg)
	}
	if !slices.Equal(cfg.HookArgs, []string{"hook", "--config-requests"}) {
		t.Errorf("hook args = %v", cfg.HookArgs)
	}
	src, err := renderOpencodePlugin(testBin)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(src, opencodePluginPlaceholder) || !strings.Contains(src, `"bin": "`+testBin+`"`) {
		t.Errorf("plugin not rendered:\n%s", src)
	}
}

// TestOpencodeModelPathHome checks "~" expands to the home directory opencode
// uses: $OPENCODE_TEST_HOME first, and the passwd entry when $HOME is unset,
// where Go's os.UserHomeDir would give up and leave "~" a name in the project.
func TestOpencodeModelPathHome(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("OPENCODE_TEST_HOME", testHome)
	if got := hook.OpencodeModelPath("~/x"); got != filepath.Join(testHome, "x") {
		t.Errorf("with OPENCODE_TEST_HOME: %q", got)
	}
	os.Unsetenv("OPENCODE_TEST_HOME")
	t.Setenv("HOME", "")
	got := hook.OpencodeModelPath("~/.ssh/id_rsa")
	if !filepath.IsAbs(got) {
		t.Errorf("with HOME empty: %q is not absolute", got)
	}
}

// TestOpencodeHookMediaOutputs checks the media tools' outputs are checked
// under the names opencode writes: generate_image swaps the path's extension
// for the image's, and generate_video numbers later videos, writing through
// a symlink already there.
func TestOpencodeHookMediaOutputs(t *testing.T) {
	isolateConfig(t)
	cwd := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(cwd, "out"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, link := range []string{"cat.png", "clip-1.mp4"} {
		if err := os.Symlink(filepath.Join(outside, link), filepath.Join(cwd, "out", link)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(outside, link), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, tt := range []struct {
		tool, path string
		wantDeny   bool
	}{
		{hook.OpencodeToolGenerateImage, "out/cat", true},
		{hook.OpencodeToolGenerateImage, "out/cat.jpg", true},
		{hook.OpencodeToolGenerateVideo, "out/clip.mp4", true},
		{hook.OpencodeToolGenerateImage, "out/dog", false},
	} {
		d := runOpencodeHook(t, cwd, tt.tool, map[string]any{"prompt": "x", "path": tt.path}, hookOptions{})
		if got := decisionOf(d) == hook.DecisionDeny; got != tt.wantDeny {
			t.Errorf("%s %s: deny = %v, want %v (%+v)", tt.tool, tt.path, got, tt.wantDeny, d)
		}
	}
}
