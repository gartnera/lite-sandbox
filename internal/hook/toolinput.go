package hook

import (
	"fmt"
	"strings"
)

// Canonical tool names Claude Code uses for its built-in tools.
const (
	ToolBash      = "Bash"
	ToolEdit      = "Edit"
	ToolWrite     = "Write"
	ToolRead      = "Read"
	ToolGlob      = "Glob"
	ToolGrep      = "Grep"
	ToolWebFetch  = "WebFetch"
	ToolWebSearch = "WebSearch"
	ToolNotebook  = "NotebookEdit"
	// ToolApplyPatch is Codex CLI's native file-editing tool. Codex has no
	// Edit/Write tool — it applies changes via apply_patch — so governing writes
	// for Codex means governing this tool.
	ToolApplyPatch = "apply_patch"
)

// toolInputFactories maps a tool name to a constructor for its typed input.
// Adding support for a new tool is a one-line registration here plus the struct.
var toolInputFactories = map[string]func() ToolInput{
	ToolBash:       func() ToolInput { return &BashInput{} },
	ToolEdit:       func() ToolInput { return &EditInput{} },
	ToolWrite:      func() ToolInput { return &WriteInput{} },
	ToolRead:       func() ToolInput { return &ReadInput{} },
	ToolGlob:       func() ToolInput { return &GlobInput{} },
	ToolGrep:       func() ToolInput { return &GrepInput{} },
	ToolWebFetch:   func() ToolInput { return &WebFetchInput{} },
	ToolWebSearch:  func() ToolInput { return &WebSearchInput{} },
	ToolNotebook:   func() ToolInput { return &NotebookEditInput{} },
	ToolApplyPatch: func() ToolInput { return &ApplyPatchInput{} },
}

// BashInput is the argument shape for the Bash tool.
type BashInput struct {
	Command         string `json:"command"`
	Description     string `json:"description,omitempty"`
	Timeout         int    `json:"timeout,omitempty"`
	RunInBackground bool   `json:"run_in_background,omitempty"`
}

func (b *BashInput) Tool() string { return ToolBash }
func (b *BashInput) Describe() string {
	return fmt.Sprintf("run shell command: %s", truncate(b.Command, 200))
}

// EditInput is the argument shape for the Edit tool.
type EditInput struct {
	FilePath   string `json:"file_path"`
	OldString  string `json:"old_string"`
	NewString  string `json:"new_string"`
	ReplaceAll bool   `json:"replace_all,omitempty"`
}

func (e *EditInput) Tool() string { return ToolEdit }
func (e *EditInput) Describe() string {
	return fmt.Sprintf("edit file: %s", e.FilePath)
}

// WriteInput is the argument shape for the Write tool.
type WriteInput struct {
	FilePath string `json:"file_path"`
	Content  string `json:"content"`
}

func (w *WriteInput) Tool() string { return ToolWrite }
func (w *WriteInput) Describe() string {
	return fmt.Sprintf("write file: %s (%d bytes)", w.FilePath, len(w.Content))
}

// ReadInput is the argument shape for the Read tool.
type ReadInput struct {
	FilePath string `json:"file_path"`
	Offset   int    `json:"offset,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

func (r *ReadInput) Tool() string { return ToolRead }
func (r *ReadInput) Describe() string {
	return fmt.Sprintf("read file: %s", r.FilePath)
}

// GlobInput is the argument shape for the Glob tool.
type GlobInput struct {
	Pattern string `json:"pattern"`
	Path    string `json:"path,omitempty"`
}

func (g *GlobInput) Tool() string { return ToolGlob }
func (g *GlobInput) Describe() string {
	if g.Path != "" {
		return fmt.Sprintf("glob: %s in %s", g.Pattern, g.Path)
	}
	return fmt.Sprintf("glob: %s", g.Pattern)
}

// GrepInput is the argument shape for the Grep tool.
type GrepInput struct {
	Pattern    string `json:"pattern"`
	Path       string `json:"path,omitempty"`
	Glob       string `json:"glob,omitempty"`
	Type       string `json:"type,omitempty"`
	OutputMode string `json:"output_mode,omitempty"`
}

func (g *GrepInput) Tool() string { return ToolGrep }
func (g *GrepInput) Describe() string {
	if g.Path != "" {
		return fmt.Sprintf("grep: %s in %s", g.Pattern, g.Path)
	}
	return fmt.Sprintf("grep: %s", g.Pattern)
}

// WebFetchInput is the argument shape for the WebFetch tool.
type WebFetchInput struct {
	URL    string `json:"url"`
	Prompt string `json:"prompt,omitempty"`
}

func (w *WebFetchInput) Tool() string { return ToolWebFetch }
func (w *WebFetchInput) Describe() string {
	return fmt.Sprintf("fetch URL: %s", w.URL)
}

// WebSearchInput is the argument shape for the WebSearch tool.
type WebSearchInput struct {
	Query string `json:"query"`
}

func (w *WebSearchInput) Tool() string { return ToolWebSearch }
func (w *WebSearchInput) Describe() string {
	return fmt.Sprintf("web search: %s", w.Query)
}

// NotebookEditInput is the argument shape for the NotebookEdit tool.
type NotebookEditInput struct {
	NotebookPath string `json:"notebook_path"`
	CellID       string `json:"cell_id,omitempty"`
	NewSource    string `json:"new_source"`
	CellType     string `json:"cell_type,omitempty"`
	EditMode     string `json:"edit_mode,omitempty"`
}

func (n *NotebookEditInput) Tool() string { return ToolNotebook }
func (n *NotebookEditInput) Describe() string {
	return fmt.Sprintf("edit notebook: %s", n.NotebookPath)
}

// ApplyPatchInput is the argument shape for Codex CLI's apply_patch tool. Codex
// delivers the patch body in the command field (per Codex's hook docs,
// "apply_patch uses tool_input.command"); Input/Patch are accepted as tolerant
// fallbacks in case a build uses a different key. The patch body is the standard
// apply_patch envelope, from which Paths extracts the affected files.
type ApplyPatchInput struct {
	Command string `json:"command,omitempty"`
	Input   string `json:"input,omitempty"`
	Patch   string `json:"patch,omitempty"`
}

func (a *ApplyPatchInput) Tool() string { return ToolApplyPatch }

// patchText returns whichever field carries the patch body.
func (a *ApplyPatchInput) patchText() string {
	for _, s := range []string{a.Command, a.Input, a.Patch} {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

// Paths returns the files the patch adds, updates, deletes, or renames to,
// resolved later against the sandbox's writable boundary. Empty when no patch
// body was visible or no file markers were found.
func (a *ApplyPatchInput) Paths() []string {
	return parseApplyPatchPaths(a.patchText())
}

func (a *ApplyPatchInput) Describe() string {
	paths := a.Paths()
	if len(paths) == 0 {
		return "apply patch"
	}
	return fmt.Sprintf("apply patch to: %s", strings.Join(paths, ", "))
}

// parseApplyPatchPaths extracts the target file paths from an apply_patch
// envelope. The format uses "*** Add File: <path>", "*** Update File: <path>",
// "*** Delete File: <path>", and "*** Move to: <path>" markers.
//
// Markers are matched only at the start of a line (column 0), NOT after trimming
// leading whitespace: inside a hunk, unchanged context lines are prefixed with a
// space and added lines with "+", so a file's own content that happens to read
// like a marker (e.g. " *** Add File: /etc/passwd") must not be mistaken for a
// real target. Paths are returned de-duplicated in first-seen order.
func parseApplyPatchPaths(patch string) []string {
	markers := []string{
		"*** Add File:",
		"*** Update File:",
		"*** Delete File:",
		"*** Move to:",
	}
	var paths []string
	seen := map[string]bool{}
	for _, line := range strings.Split(patch, "\n") {
		for _, m := range markers {
			if strings.HasPrefix(line, m) {
				// TrimSpace on the value handles surrounding spaces and a trailing
				// carriage return (CRLF input).
				p := strings.TrimSpace(strings.TrimPrefix(line, m))
				if p != "" && !seen[p] {
					seen[p] = true
					paths = append(paths, p)
				}
			}
		}
	}
	return paths
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
