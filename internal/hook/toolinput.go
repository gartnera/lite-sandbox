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
)

// toolInputFactories maps a tool name to a constructor for its typed input.
// Adding support for a new tool is a one-line registration here plus the struct.
var toolInputFactories = map[string]func() ToolInput{
	ToolBash:      func() ToolInput { return &BashInput{} },
	ToolEdit:      func() ToolInput { return &EditInput{} },
	ToolWrite:     func() ToolInput { return &WriteInput{} },
	ToolRead:      func() ToolInput { return &ReadInput{} },
	ToolGlob:      func() ToolInput { return &GlobInput{} },
	ToolGrep:      func() ToolInput { return &GrepInput{} },
	ToolWebFetch:  func() ToolInput { return &WebFetchInput{} },
	ToolWebSearch: func() ToolInput { return &WebSearchInput{} },
	ToolNotebook:  func() ToolInput { return &NotebookEditInput{} },
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

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
