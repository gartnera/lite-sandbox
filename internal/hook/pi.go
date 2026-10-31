package hook

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// pi (the `pi` coding agent, @earendil-works/pi-coding-agent) has no hook
// protocol of its own. Its extensions see every tool call in a `tool_call`
// event and may block it, so lite-sandbox's pi extension forwards each call it
// governs to `lite-sandbox hook` as a PreToolUse event in Claude Code's shape,
// marked with pi_event, and acts on the decision: deny blocks the call, ask
// puts it to the user with a confirmation dialog. tool_input is pi's own
// arguments, already validated against the tool's schema by pi.
//
// pi's tool names are lowercase, like some of Grok Build's, so its events
// carry the marker and are decoded with pi's own vocabulary below.
const (
	// Shell tools. powershell is off by default; it runs PowerShell, not bash,
	// so it is always redirected rather than AST-checked.
	PiToolBash       = "bash"
	PiToolPowerShell = "powershell"

	// Read-family tools: each takes an optional `path` (read requires it).
	PiToolRead = "read"
	PiToolGrep = "grep"
	PiToolFind = "find"
	PiToolLs   = "ls"

	// Write-family tools: each takes a required `path`.
	PiToolWrite = "write"
	PiToolEdit  = "edit"
)

// PiEventToolCall is the pi_event value the extension sends with a tool call.
const PiEventToolCall = "tool_call"

var (
	piShellTools = []string{PiToolBash, PiToolPowerShell}
	piReadTools  = []string{PiToolRead, PiToolGrep, PiToolFind, PiToolLs}
	piWriteTools = []string{PiToolWrite, PiToolEdit}
)

// PiHookTools lists the built-in pi tools the extension forwards to the hook.
var PiHookTools = slices.Concat(piShellTools, piReadTools, piWriteTools)

var piToolInputFactories = map[string]func() ToolInput{}

func init() {
	for _, name := range piShellTools {
		piToolInputFactories[name] = func() ToolInput { return &PiShellInput{tool: name} }
	}
	for _, name := range piReadTools {
		piToolInputFactories[name] = func() ToolInput { return &PiPathInput{tool: name} }
	}
	for _, name := range piWriteTools {
		piToolInputFactories[name] = func() ToolInput { return &PiPathInput{tool: name, write: true} }
	}
}

// FromPi reports whether the event was sent by lite-sandbox's pi extension.
func (e *Event) FromPi() bool { return e.PiEvent != "" }

// IsShellTool reports whether the event's tool is a built-in shell tool of the
// agent that sent it (see the package-level IsShellTool for the other agents).
func (e *Event) IsShellTool() bool {
	if e.FromPi() {
		return slices.Contains(piShellTools, e.ToolName)
	}
	return IsShellTool(e.ToolName)
}

// PiShellInput is the argument shape of pi's bash and powershell tools:
// {command, timeout?}.
type PiShellInput struct {
	tool    string
	Command string
}

func (p *PiShellInput) Tool() string         { return p.tool }
func (p *PiShellInput) ShellCommand() string { return p.Command }
func (p *PiShellInput) Describe() string {
	return fmt.Sprintf("run shell command: %s", truncate(p.Command, 200))
}

func (p *PiShellInput) UnmarshalJSON(b []byte) error {
	f, err := exactFields(b)
	if err != nil {
		return err
	}
	return f.str("command", &p.Command)
}

// PiPathInput is the argument shape of pi's file tools, which all name their
// target `path`. Only the path is modeled. Keys are matched exactly, as
// JavaScript reads them.
type PiPathInput struct {
	tool  string
	write bool

	// Path is the target as the model wrote it; "" when the tool was called
	// without one (grep, find and ls then use the working directory).
	Path string
}

func (p *PiPathInput) Tool() string { return p.tool }

// Write reports whether the tool modifies the file.
func (p *PiPathInput) Write() bool { return p.write }

func (p *PiPathInput) UnmarshalJSON(b []byte) error {
	f, err := exactFields(b)
	if err != nil {
		return err
	}
	return f.str("path", &p.Path)
}

// Paths returns the paths to check against the sandbox boundary: the target
// as written and, where it differs, the path pi opens after its own clean-up
// (see PiModelPath). A call without a path returns none.
func (p *PiPathInput) Paths() []string {
	if p.Path == "" {
		return nil
	}
	out := []string{p.Path}
	if m := PiModelPath(p.Path); m != p.Path {
		out = append(out, m)
	}
	return out
}

func (p *PiPathInput) Describe() string {
	verb := "read"
	if p.write {
		verb = "write"
	}
	return fmt.Sprintf("%s (%s): %s", p.tool, verb, p.Path)
}

// piUnicodeSpaces are the space variants pi's file tools turn into a plain
// space before opening a path (UNICODE_SPACES in pi's utils/paths.ts).
var piUnicodeSpaces = strings.NewReplacer(
	" ", " ", " ", " ", " ", " ", " ", " ", " ", " ",
	" ", " ", " ", " ", " ", " ", " ", " ", " ", " ",
	" ", " ", " ", " ", " ", " ", " ", " ", "　", " ",
)

// PiModelPath mirrors how pi's file tools clean a model-supplied path before
// resolving it against the working directory (resolveToCwd → normalizePath in
// pi's utils/paths.ts): unicode spaces become plain spaces, one leading @ is
// dropped, a leading ~ expands to the home directory, and a file:// URL
// becomes its path. Without this, "@/etc/passwd" or "~/.ssh/id_rsa" would be
// judged relative to the working directory and pass, while pi opens the real
// file.
func PiModelPath(p string) string {
	out := piUnicodeSpaces.Replace(p)
	out = strings.TrimPrefix(out, "@")
	if out == "~" || strings.HasPrefix(out, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, out[1:])
		}
		return out
	}
	if strings.HasPrefix(out, "file://") {
		if u, err := url.Parse(out); err == nil && u.Path != "" {
			return u.Path
		}
	}
	return out
}
