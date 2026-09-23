package hook

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// Grok Build (xAI's `grok` CLI) speaks a Claude-compatible PreToolUse protocol:
// its stdin envelope carries snake_case aliases (tool_name, tool_input, cwd,
// hook_event_name = "PreToolUse") next to its own camelCase keys, and it reads
// the same hookSpecificOutput.permissionDecision document back. What differs is
// the tool vocabulary: tool_input is the model's raw arguments for Grok's own
// tools, whose names and argument keys depend on the toolset the model runs
// with (the default grok_build set, the hashline variant, and the codex- and
// opencode-shaped sets Grok also ships). The names below cover all of them.
const (
	// Shell tools. monitor runs a command and streams its output as events, so
	// it executes arbitrary shell just like run_terminal_command.
	GrokToolRunTerminalCommand = "run_terminal_command"
	GrokToolRunTerminalCmd     = "run_terminal_cmd"
	GrokToolBash               = "bash" // opencode toolset
	GrokToolMonitor            = "monitor"

	// Read-family tools.
	GrokToolReadFile     = "read_file"
	GrokToolHashlineRead = "hashline_read"
	GrokToolRead         = "read" // opencode toolset
	GrokToolGrep         = "grep"
	GrokToolHashlineGrep = "hashline_grep"
	GrokToolGrepFiles    = "grep_files" // codex toolset
	GrokToolListDir      = "list_dir"
	GrokToolGlob         = "glob" // opencode toolset

	// Write-family tools. apply_patch (codex toolset) is shared with Codex CLI
	// and modeled by ApplyPatchInput.
	GrokToolSearchReplace = "search_replace"
	GrokToolHashlineEdit  = "hashline_edit"
	GrokToolEdit          = "edit"  // opencode toolset
	GrokToolWrite         = "write" // opencode toolset

	// Media tools. Their image references may be local file paths, which Grok
	// reads and uploads to xAI's image and video APIs — a read like any other.
	GrokToolImageEdit        = "image_edit"
	GrokToolImageToVideo     = "image_to_video"
	GrokToolReferenceToVideo = "reference_to_video"
)

// grokShellTools, grokReadTools and grokWriteTools classify the Grok tool
// names above. None collides with a Claude Code tool name (Claude's are
// capitalized), so they can share the one factory table.
var (
	grokShellTools = []string{GrokToolRunTerminalCommand, GrokToolRunTerminalCmd, GrokToolBash, GrokToolMonitor}
	grokReadTools  = []string{
		GrokToolReadFile, GrokToolHashlineRead, GrokToolRead,
		GrokToolGrep, GrokToolHashlineGrep, GrokToolGrepFiles,
		GrokToolListDir, GrokToolGlob,
	}
	grokWriteTools = []string{GrokToolSearchReplace, GrokToolHashlineEdit, GrokToolEdit, GrokToolWrite}
	grokMediaTools = []string{GrokToolImageEdit, GrokToolImageToVideo, GrokToolReferenceToVideo}
)

// GrokHookMatcher is the PreToolUse matcher lite-sandbox registers with Grok
// Build: every shell and filesystem tool above. A plain `|`-list is an exact
// match in Grok (not a regex), so e.g. "read" does not also fire on read_file.
var GrokHookMatcher = strings.Join(
	slices.Concat(grokShellTools, grokReadTools, grokWriteTools, grokMediaTools, []string{ToolApplyPatch}),
	"|",
)

func init() {
	for _, name := range grokShellTools {
		toolInputFactories[name] = func() ToolInput { return &GrokShellInput{tool: name} }
	}
	for _, name := range grokReadTools {
		toolInputFactories[name] = func() ToolInput { return &PathToolInput{tool: name} }
	}
	for _, name := range grokWriteTools {
		toolInputFactories[name] = func() ToolInput { return &PathToolInput{tool: name, write: true} }
	}
	for _, name := range grokMediaTools {
		toolInputFactories[name] = func() ToolInput { return &MediaInput{tool: name} }
	}
}

// IsGrokTool reports whether name is one of the Grok Build tools the hook
// governs (a shell, file, or media tool, or apply_patch).
func IsGrokTool(name string) bool {
	return slices.Contains(grokShellTools, name) || slices.Contains(grokReadTools, name) ||
		slices.Contains(grokWriteTools, name) || slices.Contains(grokMediaTools, name) ||
		name == ToolApplyPatch
}

// ShellInput is implemented by every shell tool's input — Claude Code's Bash
// and Grok's run_terminal_command family — so callers can reach the command
// without knowing which agent sent it.
type ShellInput interface {
	ToolInput
	ShellCommand() string
}

func (b *BashInput) ShellCommand() string { return b.Command }

// IsShellTool reports whether name is a built-in shell tool of a supported
// agent: Claude Code's (and Codex's) Bash, or one of Grok's.
func IsShellTool(name string) bool {
	return name == ToolBash || slices.Contains(grokShellTools, name)
}

// GrokShellInput is the argument shape of Grok's shell tools. Only the command
// is modeled: the other arguments (timeout, timeout_ms, persistent, ...) are
// lenient on Grok's side — a model may send a number as a string — so decoding
// them here could fail and blind the hook to the command.
type GrokShellInput struct {
	tool    string
	Command string `json:"command"`
}

func (g *GrokShellInput) Tool() string         { return g.tool }
func (g *GrokShellInput) ShellCommand() string { return g.Command }
func (g *GrokShellInput) Describe() string {
	return fmt.Sprintf("run shell command: %s", truncate(g.Command, 200))
}

// PathToolInput is the argument shape of a Grok filesystem tool. The toolsets
// spell the target differently (target_file, file_path, filePath, path,
// target_directory, dir_path), so every spelling is accepted and the first one
// set is the target. Only the path is modeled, for the same reason as
// GrokShellInput.
type PathToolInput struct {
	tool  string
	write bool

	TargetFile      string `json:"target_file,omitempty"`
	FilePath        string `json:"file_path,omitempty"`
	FilePathCamel   string `json:"filePath,omitempty"`
	Path            string `json:"path,omitempty"`
	TargetDirectory string `json:"target_directory,omitempty"`
	DirPath         string `json:"dir_path,omitempty"`
}

func (p *PathToolInput) Tool() string { return p.tool }

// Write reports whether the tool modifies the file (as opposed to reading or
// searching it).
func (p *PathToolInput) Write() bool { return p.write }

// Target returns the path argument as the model wrote it, or "" when the tool
// was called without one (grep and glob default to the workspace).
func (p *PathToolInput) Target() string {
	for _, s := range []string{p.TargetFile, p.FilePath, p.FilePathCamel, p.Path, p.TargetDirectory, p.DirPath} {
		if s != "" {
			return s
		}
	}
	return ""
}

// Paths returns the paths to check against the sandbox boundary: the target
// as written and, when it differs, the path Grok actually opens after its own
// clean-up (see GrokModelPath). Checking both keeps the hook from approving a
// spelling that only looks in bounds before Grok normalizes it.
func (p *PathToolInput) Paths() []string {
	raw := p.Target()
	if raw == "" {
		return nil
	}
	paths := []string{raw}
	if model := GrokModelPath(raw); model != "" && model != raw {
		paths = append(paths, model)
	}
	return paths
}

func (p *PathToolInput) Describe() string {
	verb := "read"
	if p.write {
		verb = "write"
	}
	return fmt.Sprintf("%s (%s): %s", p.tool, verb, p.Target())
}

// GrokModelPath mirrors how Grok's tools clean a model-supplied path before
// opening it (resolve_model_path in xai-grok-tools): surrounding whitespace and
// quotes are stripped — along with literal \n, \r, \t escapes left at the end
// of a quoted value — and a leading ~ expands to the home directory. Without
// this, a path like "~/.ssh/id_rsa" would be judged relative to the working
// directory and pass, while Grok reads the real key.
func GrokModelPath(p string) string {
	trimmed := strings.TrimSpace(p)
	quoted := len(trimmed) >= 2 && strings.ContainsAny(trimmed[:1], `"'`) && strings.ContainsAny(trimmed[len(trimmed)-1:], `"'`)
	out := strings.TrimSpace(strings.Trim(trimmed, `"'`))
	if quoted {
		for {
			stripped, ok := cutAnySuffix(out, `\n`, `\r`, `\t`)
			if !ok {
				break
			}
			out = strings.TrimRightFunc(stripped, unicode.IsSpace)
		}
	}
	if out == "~" || strings.HasPrefix(out, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			out = filepath.Join(home, out[1:])
		}
	}
	return out
}

func cutAnySuffix(s string, suffixes ...string) (string, bool) {
	for _, suf := range suffixes {
		if strings.HasSuffix(s, suf) {
			return strings.TrimSuffix(s, suf), true
		}
	}
	return s, false
}

// MediaInput is the argument shape of Grok's image and video tools: image
// (one reference, or a list for image_edit), images, first_frame, last_frame
// and keyframes[].image. A reference is a file path, a data: or https URL, or
// an attachment token like "[Image #1]"; only the paths touch the filesystem.
type MediaInput struct {
	tool string

	Image      json.RawMessage `json:"image,omitempty"`
	Images     []string        `json:"images,omitempty"`
	FirstFrame string          `json:"first_frame,omitempty"`
	LastFrame  string          `json:"last_frame,omitempty"`
	Keyframes  []struct {
		Image string `json:"image"`
	} `json:"keyframes,omitempty"`
}

func (m *MediaInput) Tool() string { return m.tool }

// Paths returns the references that name local files, the way Grok resolves
// them: trimmed, with a file:// prefix stripped.
func (m *MediaInput) Paths() []string {
	var refs []string
	var one string
	var many []string
	if json.Unmarshal(m.Image, &one) == nil {
		refs = append(refs, one)
	} else if json.Unmarshal(m.Image, &many) == nil {
		refs = append(refs, many...)
	}
	refs = append(refs, m.Images...)
	refs = append(refs, m.FirstFrame, m.LastFrame)
	for _, k := range m.Keyframes {
		refs = append(refs, k.Image)
	}

	var paths []string
	for _, r := range refs {
		r = strings.TrimPrefix(strings.TrimSpace(r), "file://")
		switch {
		case r == "",
			strings.HasPrefix(r, "data:"),
			strings.HasPrefix(r, "https://"), strings.HasPrefix(r, "http://"),
			strings.HasPrefix(r, "[") && strings.HasSuffix(r, "]"): // attachment token
			continue
		}
		paths = append(paths, r)
	}
	return paths
}

func (m *MediaInput) Describe() string {
	return fmt.Sprintf("%s: %s", m.tool, strings.Join(m.Paths(), ", "))
}
