package hook

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// grokEnvelope builds a PreToolUse payload the way Grok Build serializes one
// (HookEventEnvelope::to_hook_json in xai-grok-hooks): camelCase keys, the
// snake_case aliases next to them, and hook_event_name carrying Claude's
// PascalCase value.
func grokEnvelope(tool, input string) string {
	return `{
  "hookEventName": "pre_tool_use",
  "hook_event_name": "PreToolUse",
  "sessionId": "s-1", "session_id": "s-1",
  "cwd": "/work/project",
  "workspaceRoot": "/work/project",
  "timestamp": "2026-09-23T12:00:00Z",
  "permissionMode": "default", "permission_mode": "default",
  "toolName": "` + tool + `", "tool_name": "` + tool + `",
  "toolUseId": "call-1", "tool_use_id": "call-1",
  "toolInput": ` + input + `, "tool_input": ` + input + `,
  "toolInputTruncated": false
}`
}

func TestParseGrokEvent(t *testing.T) {
	tests := []struct {
		name      string
		tool      string
		input     string
		wantPath  string
		wantWrite bool
	}{
		{"read_file", GrokToolReadFile, `{"target_file": "src/main.rs", "offset": "10"}`, "src/main.rs", false},
		{"codex read_file", GrokToolReadFile, `{"file_path": "/etc/hosts", "offset": 1, "limit": 20}`, "/etc/hosts", false},
		{"opencode read", GrokToolRead, `{"filePath": "/etc/hosts"}`, "/etc/hosts", false},
		{"grep", GrokToolGrep, `{"pattern": "TODO", "path": "/home", "-B": 2}`, "/home", false},
		{"grep without path", GrokToolGrep, `{"pattern": "TODO"}`, "", false},
		{"list_dir", GrokToolListDir, `{"target_directory": "/home"}`, "/home", false},
		{"search_replace", GrokToolSearchReplace, `{"file_path": "a.go", "old_string": "x", "new_string": "y", "replace_all": "true"}`, "a.go", true},
		{"write", GrokToolWrite, `{"file_path": "/tmp/x", "content": "hi"}`, "/tmp/x", true},
		{"hashline_edit", GrokToolHashlineEdit, `{"file_path": "b.go", "edits": "[]"}`, "b.go", true},
		{"opencode edit", GrokToolEdit, `{"filePath": "c.go", "oldString": "a", "newString": "b"}`, "c.go", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := ParseEvent(strings.NewReader(grokEnvelope(tt.tool, tt.input)))
			if err != nil {
				t.Fatalf("ParseEvent: %v", err)
			}
			if !e.FromGrok() {
				t.Error("FromGrok() = false for a Grok envelope")
			}
			if e.HookEventName != EventPreToolUse || e.CWD != "/work/project" || e.ToolName != tt.tool {
				t.Errorf("envelope decoded as event=%q cwd=%q tool=%q", e.HookEventName, e.CWD, e.ToolName)
			}
			in, ok := e.ToolInput.(*PathToolInput)
			if !ok {
				t.Fatalf("ToolInput = %T, want *PathToolInput", e.ToolInput)
			}
			if in.Target() != tt.wantPath || in.Write() != tt.wantWrite {
				t.Errorf("Target()=%q Write()=%v, want %q %v", in.Target(), in.Write(), tt.wantPath, tt.wantWrite)
			}
		})
	}
}

// TestParseGrokShellEvent covers the shell tools, including arguments a model
// sends as strings (Grok accepts them leniently): decoding must not fail and
// hide the command from the hook.
func TestParseGrokShellEvent(t *testing.T) {
	for _, tc := range []struct{ tool, input string }{
		{GrokToolRunTerminalCommand, `{"command": "cat ~/.ssh/id_rsa", "timeout": "120000", "description": "x"}`},
		{GrokToolMonitor, `{"command": "cat ~/.ssh/id_rsa", "description": "x", "timeout_ms": "5", "persistent": "true"}`},
		{GrokToolBash, `{"command": "cat ~/.ssh/id_rsa", "timeout": 5}`},
	} {
		e, err := ParseEvent(strings.NewReader(grokEnvelope(tc.tool, tc.input)))
		if err != nil {
			t.Fatalf("%s: ParseEvent: %v", tc.tool, err)
		}
		if !IsShellTool(e.ToolName) {
			t.Errorf("%s: IsShellTool = false", tc.tool)
		}
		in, ok := e.ToolInput.(ShellInput)
		if !ok || in.ShellCommand() != "cat ~/.ssh/id_rsa" {
			t.Errorf("%s: ToolInput = %#v, want the command", tc.tool, e.ToolInput)
		}
	}
}

func TestClaudeEventIsNotGrok(t *testing.T) {
	e, err := ParseEvent(strings.NewReader(`{"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": "/w", "tool_input": {"command": "ls"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.FromGrok() {
		t.Error("FromGrok() = true for a Claude Code envelope")
	}
	if in, ok := e.ToolInput.(ShellInput); !ok || in.ShellCommand() != "ls" {
		t.Errorf("Bash input not exposed as ShellInput: %#v", e.ToolInput)
	}
}

func TestGrokModelPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	tests := []struct{ in, want string }{
		{"src/main.rs", "src/main.rs"},
		{"~/.ssh/id_rsa", filepath.Join(home, ".ssh/id_rsa")},
		{"~", home},
		{"~other/x", "~other/x"}, // only ~ and ~/ expand
		{"  /etc/passwd\n", "/etc/passwd"},
		{`"/etc/passwd"`, "/etc/passwd"},
		{`'~/.aws/credentials'`, filepath.Join(home, ".aws/credentials")},
		{`"/etc/passwd\n"`, "/etc/passwd"}, // literal backslash-n inside quotes
		{`/etc/passwd\n`, `/etc/passwd\n`}, // unquoted: kept, as Grok does
	}
	for _, tt := range tests {
		if got := GrokModelPath(tt.in); got != tt.want {
			t.Errorf("GrokModelPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPathToolInputPaths(t *testing.T) {
	p := &PathToolInput{tool: GrokToolReadFile, Targets: []string{"~/.ssh/id_rsa"}}
	paths := p.Paths()
	if len(paths) != 2 || paths[0] != "~/.ssh/id_rsa" || strings.HasPrefix(paths[1], "~") {
		t.Errorf("Paths() = %q, want the raw and the expanded path", paths)
	}
	if got := (&PathToolInput{Targets: []string{"a.txt"}}).Paths(); !slices.Equal(got, []string{"a.txt"}) {
		t.Errorf("Paths() = %q, want just the raw path when nothing changes", got)
	}
	if got := (&PathToolInput{}).Paths(); got != nil {
		t.Errorf("Paths() = %q, want nil without a path", got)
	}
}

func TestGrokHookMatcher(t *testing.T) {
	names := strings.Split(GrokHookMatcher, "|")
	for _, want := range []string{GrokToolRunTerminalCommand, GrokToolMonitor, GrokToolReadFile, GrokToolGrep, GrokToolListDir, GrokToolSearchReplace, GrokToolWrite, ToolApplyPatch} {
		if !slices.Contains(names, want) {
			t.Errorf("GrokHookMatcher %q lacks %q", GrokHookMatcher, want)
		}
	}
	sorted := slices.Clone(names)
	slices.Sort(sorted)
	if len(slices.Compact(sorted)) != len(names) {
		t.Errorf("GrokHookMatcher has duplicates: %q", GrokHookMatcher)
	}
	// Every matched tool must be modeled, or the hook would see it and defer.
	for _, n := range names {
		if _, ok := toolInputFactories[n]; !ok {
			t.Errorf("matched tool %q has no input factory", n)
		}
	}
}

func TestParseGrokMediaEvent(t *testing.T) {
	tests := []struct {
		tool, input string
		want        []string
	}{
		{GrokToolImageEdit, `{"prompt": "x", "image": ["/home/u/a.png", "[Image #1]", "data:image/png;base64,AAAA", " file:///home/u/b.png "]}`, []string{"/home/u/a.png", "/home/u/b.png"}},
		{GrokToolImageToVideo, `{"image": "/home/u/a.png", "duration": "5"}`, []string{"/home/u/a.png"}},
		{GrokToolReferenceToVideo, `{"prompt": "x", "images": ["https://example.com/a.png", "/r/1.png"], "first_frame": "/r/2.png", "keyframes": [{"image": "/r/3.png", "timestamp_s": 1}]}`, []string{"/r/1.png", "/r/2.png", "/r/3.png"}},
	}
	for _, tt := range tests {
		e, err := ParseEvent(strings.NewReader(grokEnvelope(tt.tool, tt.input)))
		if err != nil {
			t.Fatalf("%s: ParseEvent: %v", tt.tool, err)
		}
		in, ok := e.ToolInput.(*MediaInput)
		if !ok {
			t.Fatalf("%s: ToolInput = %T, want *MediaInput", tt.tool, e.ToolInput)
		}
		if got := in.Paths(); !slices.Equal(got, tt.want) {
			t.Errorf("%s: Paths() = %q, want %q", tt.tool, got, tt.want)
		}
	}
}

// TestPathToolInputEverySpelling: the toolsets read different keys, so every
// spelling a call sets must be checked, not just the first.
func TestPathToolInputEverySpelling(t *testing.T) {
	e, err := ParseEvent(strings.NewReader(grokEnvelope(GrokToolRead, `{"target_file": "src/ok.go", "filePath": "/home/u/.ssh/id_rsa", "dir_path": "/etc"}`)))
	if err != nil {
		t.Fatal(err)
	}
	got := e.ToolInput.(*PathToolInput).Paths()
	for _, want := range []string{"src/ok.go", "/home/u/.ssh/id_rsa", "/etc"} {
		if !slices.Contains(got, want) {
			t.Errorf("Paths() = %q, missing %q", got, want)
		}
	}
}

// TestGrokInputExactKeys: Grok (serde) matches argument keys exactly and
// ignores unknown ones, so a key that differs only in case must not replace
// the one Grok reads.
func TestGrokInputExactKeys(t *testing.T) {
	e, err := ParseEvent(strings.NewReader(grokEnvelope(GrokToolSearchReplace, `{"file_path": "/etc/cron.d/x", "FILE_PATH": "a.go", "old_string": "", "new_string": "x"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if got := e.ToolInput.(*PathToolInput).Paths(); !slices.Equal(got, []string{"/etc/cron.d/x"}) {
		t.Errorf("Paths() = %q, want only the exact-case file_path", got)
	}
	e, err = ParseEvent(strings.NewReader(grokEnvelope(GrokToolRunTerminalCommand, `{"command": "cat ~/.ssh/id_rsa", "COMMAND": "ls"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if got := e.ToolInput.(ShellInput).ShellCommand(); got != "cat ~/.ssh/id_rsa" {
		t.Errorf("ShellCommand() = %q, want the exact-case command", got)
	}
}

// TestGrokInputWrongTypeFails: an argument of the wrong type must fail to
// decode (so the hook can fail closed) rather than be silently dropped.
func TestGrokInputWrongTypeFails(t *testing.T) {
	for _, tc := range []struct{ tool, input string }{
		{GrokToolReadFile, `{"target_file": 7}`},
		{GrokToolImageEdit, `{"image": [{"path": "/x"}]}`},
		{GrokToolReferenceToVideo, `{"keyframes": [{"image": 1}]}`},
	} {
		e, err := ParseEvent(strings.NewReader(grokEnvelope(tc.tool, tc.input)))
		if err == nil || e.ToolInput != nil {
			t.Errorf("%s %s: expected a decode error and no input, got err=%v input=%#v", tc.tool, tc.input, err, e.ToolInput)
		}
	}
}

func TestMediaInputTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	m := &MediaInput{Refs: []string{"~/.ssh/id_rsa"}}
	if got := m.Paths(); !slices.Contains(got, filepath.Join(home, ".ssh/id_rsa")) {
		t.Errorf("Paths() = %q, want the ~-expanded path too", got)
	}
}
