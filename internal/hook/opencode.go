package hook

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// opencode v2 has no hook protocol of its own. Its plugins register a
// tool "execute.before" hook, which sees every tool call (Code Mode calls
// included) and may reject it by throwing. lite-sandbox's opencode plugin
// forwards each call it governs to `lite-sandbox hook` as a PreToolUse event
// in Claude Code's shape, marked with opencode_event, and acts on the
// decision: deny rejects the call, ask puts it to the user through opencode's
// own permission prompt.
//
// tool_input is the call's input as the hook sees it, after opencode's
// built-in input repair and before the tool decodes it against its schema.
// opencode's tool names are lowercase and overlap pi's and Grok Build's, so
// its events carry the marker and are decoded with opencode's own vocabulary
// below.
const (
	// OpencodeToolShell is v2's built-in shell (v1's bash). opencode's input
	// repair maps a model's bash or Bash call to it before the hook runs.
	OpencodeToolShell = "shell"

	// Read-family tools: read requires a path; glob and grep search the
	// working directory when they have none.
	OpencodeToolRead = "read"
	OpencodeToolGlob = "glob"
	OpencodeToolGrep = "grep"

	// Write-family tools, each with a required path.
	OpencodeToolWrite = "write"
	OpencodeToolEdit  = "edit"

	// OpencodeToolPatch applies a patch ({patchText}) in the apply_patch
	// envelope, adding, updating, deleting and moving files.
	OpencodeToolPatch = "patch"

	// Media generation tools: each writes its result to an optional path and
	// reads the local files it is given as input images (or videos, audio).
	OpencodeToolGenerateImage = "generate_image"
	OpencodeToolGenerateVideo = "generate_video"
)

// OpencodeEventToolExecuteBefore is the opencode_event value the plugin sends
// with a tool call.
const OpencodeEventToolExecuteBefore = "tool.execute.before"

var (
	opencodeReadTools  = []string{OpencodeToolRead, OpencodeToolGlob, OpencodeToolGrep}
	opencodeWriteTools = []string{OpencodeToolWrite, OpencodeToolEdit}
	opencodeMediaTools = []string{OpencodeToolGenerateImage, OpencodeToolGenerateVideo}
)

// OpencodeHookTools lists the built-in opencode tools the plugin forwards to
// the hook.
var OpencodeHookTools = slices.Concat(
	[]string{OpencodeToolShell}, opencodeReadTools, opencodeWriteTools,
	[]string{OpencodeToolPatch}, opencodeMediaTools,
)

var opencodeToolInputFactories = map[string]func() ToolInput{
	OpencodeToolShell:         func() ToolInput { return &OpencodeShellInput{} },
	OpencodeToolPatch:         func() ToolInput { return &OpencodePatchInput{} },
	OpencodeToolGenerateImage: func() ToolInput { return &OpencodeMediaInput{tool: OpencodeToolGenerateImage} },
	OpencodeToolGenerateVideo: func() ToolInput { return &OpencodeMediaInput{tool: OpencodeToolGenerateVideo} },
}

func init() {
	for _, name := range opencodeReadTools {
		opencodeToolInputFactories[name] = func() ToolInput { return &OpencodePathInput{tool: name} }
	}
	for _, name := range opencodeWriteTools {
		opencodeToolInputFactories[name] = func() ToolInput { return &OpencodePathInput{tool: name, write: true} }
	}
}

// FromOpencode reports whether the event was sent by lite-sandbox's opencode
// plugin.
func (e *Event) FromOpencode() bool { return e.OpencodeEvent != "" }

// IsOpencodeTool reports whether name is one of the built-in opencode tools
// whose arguments the hook models.
func IsOpencodeTool(name string) bool {
	_, ok := opencodeToolInputFactories[name]
	return ok
}

// OpencodeShellInput is the argument shape of opencode's shell tool:
// {command, workdir?, background?}.
type OpencodeShellInput struct {
	Command string
}

func (o *OpencodeShellInput) Tool() string         { return OpencodeToolShell }
func (o *OpencodeShellInput) ShellCommand() string { return o.Command }
func (o *OpencodeShellInput) Describe() string {
	return fmt.Sprintf("run shell command: %s", truncate(o.Command, 200))
}

func (o *OpencodeShellInput) UnmarshalJSON(b []byte) error {
	f, err := exactFields(b)
	if err != nil {
		return err
	}
	return f.str("command", &o.Command)
}

// OpencodePathInput is the argument shape of opencode's read, glob, grep,
// write and edit tools, which all name their target `path`. Only the path is
// modeled. Keys are matched exactly, as JavaScript reads them.
type OpencodePathInput struct {
	tool  string
	write bool

	// Path is the target as the model wrote it; "" when the tool was called
	// without one (glob and grep then search the working directory).
	Path string
}

func (o *OpencodePathInput) Tool() string { return o.tool }

// Write reports whether the tool modifies the file.
func (o *OpencodePathInput) Write() bool { return o.write }

func (o *OpencodePathInput) UnmarshalJSON(b []byte) error {
	f, err := exactFields(b)
	if err != nil {
		return err
	}
	return f.str("path", &o.Path)
}

// Paths returns the paths to check against the sandbox boundary (see
// opencodePaths). A call without a path returns none.
func (o *OpencodePathInput) Paths() []string { return opencodePaths(o.Path) }

func (o *OpencodePathInput) Describe() string {
	verb := "read"
	if o.write {
		verb = "write"
	}
	return fmt.Sprintf("%s (%s): %s", o.tool, verb, o.Path)
}

// OpencodePatchInput is the argument shape of opencode's patch tool:
// {patchText}.
type OpencodePatchInput struct {
	PatchText string
}

func (o *OpencodePatchInput) Tool() string { return OpencodeToolPatch }

func (o *OpencodePatchInput) UnmarshalJSON(b []byte) error {
	f, err := exactFields(b)
	if err != nil {
		return err
	}
	return f.str("patchText", &o.PatchText)
}

// Paths returns every file the patch may add, update, delete or move to, in
// each spelling opencode may open (see opencodePaths).
func (o *OpencodePatchInput) Paths() []string {
	var out []string
	for _, p := range parseOpencodePatchPaths(o.PatchText) {
		for _, q := range opencodePaths(p) {
			if !slices.Contains(out, q) {
				out = append(out, q)
			}
		}
	}
	return out
}

func (o *OpencodePatchInput) Describe() string {
	paths := parseOpencodePatchPaths(o.PatchText)
	if len(paths) == 0 {
		return "patch"
	}
	return fmt.Sprintf("patch (write): %s", strings.Join(paths, ", "))
}

// parseOpencodePatchPaths extracts the target paths of an opencode patch.
// opencode's parser (parsePatch in its util/src/patch.ts) trims each line
// before matching a hunk header, unlike Codex's, and treats any trimmed line
// that starts with a header as the start of a hunk, so the hook does too:
// every line whose trimmed text starts with a file marker names a target. It
// may over-match (a context line that reads like a header), which only makes
// a denial more likely, never less. Lines and paths are trimmed as
// JavaScript's trim() does (jsTrim), so a byte order mark around a header or
// path can't hide it.
func parseOpencodePatchPaths(patch string) []string {
	markers := []string{
		"*** Add File:",
		"*** Update File:",
		"*** Delete File:",
		"*** Move to:",
	}
	var paths []string
	for _, line := range strings.Split(patch, "\n") {
		line = jsTrim(line)
		for _, m := range markers {
			if rest, ok := strings.CutPrefix(line, m); ok {
				if p := jsTrim(rest); p != "" && !slices.Contains(paths, p) {
					paths = append(paths, p)
				}
			}
		}
	}
	return paths
}

// jsTrim trims s as JavaScript's String.prototype.trim() does: its white space
// is Go's (unicode.IsSpace) without U+0085, which JavaScript keeps, and with
// U+FEFF, the byte order mark, which Go keeps.
func jsTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return r == '\uFEFF' || (unicode.IsSpace(r) && r != '\u0085')
	})
}

// OpencodeMediaInput is the argument shape of opencode's generate_image
// ({prompt, images?, model?, path?}) and generate_video ({prompt, start?,
// end?, references?, path?, ...}) tools: path is where the result is
// written, and the others name local files (or http(s) URLs) the tool reads.
type OpencodeMediaInput struct {
	tool string

	Path  string
	Reads []string
}

func (o *OpencodeMediaInput) Tool() string { return o.tool }

func (o *OpencodeMediaInput) UnmarshalJSON(b []byte) error {
	f, err := exactFields(b)
	if err != nil {
		return err
	}
	if err := f.str("path", &o.Path); err != nil {
		return err
	}
	for _, key := range []string{"images", "start", "end", "references"} {
		if err := f.strs(key, &o.Reads); err != nil {
			return err
		}
	}
	return nil
}

// WritePaths returns the paths the tool writes, in each spelling opencode may
// open.
func (o *OpencodeMediaInput) WritePaths() []string { return opencodePaths(o.Path) }

// ReadPaths returns the local files the tool reads. http(s) URLs are fetched,
// not read from disk, and are left out.
func (o *OpencodeMediaInput) ReadPaths() []string {
	var out []string
	for _, r := range o.Reads {
		lower := strings.ToLower(r)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			continue
		}
		for _, q := range opencodePaths(r) {
			if !slices.Contains(out, q) {
				out = append(out, q)
			}
		}
	}
	return out
}

func (o *OpencodeMediaInput) Describe() string {
	parts := []string{}
	if o.Path != "" {
		parts = append(parts, "writes "+o.Path)
	}
	if len(o.Reads) > 0 {
		parts = append(parts, "reads "+strings.Join(o.Reads, ", "))
	}
	if len(parts) == 0 {
		return o.tool
	}
	return fmt.Sprintf("%s: %s", o.tool, strings.Join(parts, "; "))
}

// opencodePaths returns the spellings of a model-supplied path to check: the
// path as written and, where it differs, the one opencode opens (see
// OpencodeModelPath). An empty path returns none.
func opencodePaths(p string) []string {
	if p == "" {
		return nil
	}
	out := []string{p}
	if m := OpencodeModelPath(p); m != p {
		out = append(out, m)
	}
	return out
}

// OpencodeModelPath mirrors how opencode's file tools resolve a model-supplied
// path (resolvePath in its core/src/file-access.ts): "~" and a leading "~/"
// expand to the home directory (opencodeHome), and anything else is resolved
// against the working directory as written. Without this, "~/.ssh/id_rsa"
// would be judged relative to the working directory and pass, while opencode
// opens the real file.
func OpencodeModelPath(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		return filepath.Join(opencodeHome(), p[1:])
	}
	return p
}

// opencodeHome returns the home directory opencode expands "~" to
// (Global.Path.home in its util/src/global.ts): $OPENCODE_TEST_HOME when set,
// otherwise Node's os.homedir(), which is $HOME or, when that is unset or
// empty, the user's passwd entry. The hook runs with the plugin's
// environment, so it sees the same variables. When no home directory can be
// found it returns "/", so a "~" path is judged as one outside the project
// rather than as a name inside it.
func opencodeHome() string {
	if home, ok := os.LookupEnv("OPENCODE_TEST_HOME"); ok {
		return home
	}
	if home := os.Getenv("HOME"); home != "" {
		return home
	}
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	return string(filepath.Separator)
}
