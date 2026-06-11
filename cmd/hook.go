package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/hook"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

// hookToolMatcher is the tool matcher used when the PreToolUse hook is
// registered in settings.json. It covers the built-in Bash tool (which the hook
// redirects to the MCP tool) and the filesystem tools whose paths we govern. The
// hook itself re-checks the tool name, so the matcher is just an optimization
// that avoids invoking the binary for unrelated tools.
const hookToolMatcher = "Bash|Read|Edit|Write|NotebookEdit|Glob|Grep"

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Evaluate a Claude Code PreToolUse event from stdin",
	Long: "Reads a Claude Code PreToolUse hook event as JSON on stdin and enforces " +
		"the sandbox's filesystem boundaries: reads outside the readable paths and " +
		"writes outside the writable paths are denied. All other calls defer to " +
		"Claude Code's normal permission flow. Invoked by Claude Code; register it " +
		"with `lite-sandbox install --with-fs-hook`.",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runHook(cmd)
	},
}

func init() {
	rootCmd.AddCommand(hookCmd)
}

// runHook is the hot path Claude Code invokes per tool call. It is deliberately
// fail-open: any internal error (unparseable event, missing cwd) defers to
// Claude Code's normal permission flow rather than blocking the user's work.
func runHook(cmd *cobra.Command) error {
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()

	event, perr := hook.ParseEvent(cmd.InOrStdin())
	if event == nil {
		// Could not even decode the envelope; defer (exit 0, no output).
		fmt.Fprintf(errOut, "lite-sandbox hook: %v\n", perr)
		return nil
	}
	if perr != nil {
		// tool_input failed to decode but we can still act on tool name.
		fmt.Fprintf(errOut, "lite-sandbox hook: %v\n", perr)
	}
	if event.HookEventName != hook.EventPreToolUse {
		// Not our event; defer.
		return nil
	}

	decision := evaluate(event)
	if decision == nil {
		// Nothing to enforce: defer to normal permission flow (no JSON).
		return nil
	}
	return decision.Write(out)
}

// evaluate returns a deny decision for a governed tool call, or nil to defer to
// Claude Code's normal permission flow. The built-in Bash tool is redirected to
// the sandboxed MCP tool; filesystem tools are checked against path boundaries.
func evaluate(event *hook.Event) *hook.Decision {
	if d := denyBuiltinBash(event); d != nil {
		return d
	}
	return evaluatePathPolicy(event)
}

// denyBuiltinBash blocks the built-in Bash tool and points the model at the
// sandboxed MCP tool, which runs the same command through lite-sandbox's
// validation and path boundaries. The built-in Bash tool has no sandbox.
func denyBuiltinBash(event *hook.Event) *hook.Decision {
	if event.ToolName != hook.ToolBash {
		return nil
	}
	what := event.ToolName
	if event.ToolInput != nil {
		what = event.ToolInput.Describe()
	}
	reason := fmt.Sprintf(
		"Blocked by lite-sandbox: the built-in Bash tool is disabled.\n"+
			"Attempted action: %s\n"+
			"What to do instead: run this command with the mcp__lite-sandbox__bash tool, "+
			"which executes it through lite-sandbox's validation and path boundaries. "+
			"The built-in Bash tool bypasses the sandbox and is not permitted.",
		what,
	)
	return hook.NewDecision(hook.DecisionDeny, reason)
}

// evaluatePathPolicy returns a deny decision when a filesystem tool targets a
// path outside the sandbox boundary, or nil to defer to Claude Code's normal
// flow. Read-family tools (Read/Glob/Grep) are checked against the readable
// paths; write-family tools (Edit/Write/NotebookEdit) against the writable
// paths.
func evaluatePathPolicy(event *hook.Event) *hook.Decision {
	path, write, governed := fsTarget(event)
	if !governed || path == "" {
		// Not a filesystem tool we govern, or no explicit path was supplied
		// (e.g. Glob/Grep without a path default to cwd, which is allowed).
		return nil
	}

	cwd := event.CWD
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if cwd == "" {
		// Without a working directory we cannot resolve the boundary; fail-open.
		return nil
	}

	readPaths, writePaths := sandboxPaths(cwd)
	allowed := readPaths
	boundary := "readable"
	configNoun := "readable"
	if write {
		allowed = writePaths
		boundary = "writable"
		configNoun = "writable"
	}

	resolved := bash_sandboxed.ResolvePath(path, cwd)
	if bash_sandboxed.IsUnderAllowedPaths(resolved, allowed) {
		// Inside the boundary: defer to Claude Code's normal permission flow.
		return nil
	}

	what := event.ToolName
	if event.ToolInput != nil {
		what = event.ToolInput.Describe()
	}
	reason := fmt.Sprintf(
		"Blocked by lite-sandbox: %s\n"+
			"%q resolves to %q, which is outside the sandbox's %s paths.\n"+
			"Allowed %s paths: %s\n"+
			"What to do instead: work within the project directory (%s). "+
			"If this path is genuinely needed, ask the user to add it via "+
			"`lite-sandbox config %s-paths add <path>`.",
		what, path, resolved, boundary,
		boundary, strings.Join(allowed, ", "),
		cwd, configNoun,
	)
	return hook.NewDecision(hook.DecisionDeny, reason)
}

// fsTarget reports the filesystem path a tool call targets, whether the access
// is a write, and whether the tool is one whose paths the sandbox governs.
func fsTarget(e *hook.Event) (path string, write bool, governed bool) {
	switch in := e.ToolInput.(type) {
	case *hook.ReadInput:
		return in.FilePath, false, true
	case *hook.GlobInput:
		return in.Path, false, true
	case *hook.GrepInput:
		return in.Path, false, true
	case *hook.EditInput:
		return in.FilePath, true, true
	case *hook.WriteInput:
		return in.FilePath, true, true
	case *hook.NotebookEditInput:
		return in.NotebookPath, true, true
	}
	return "", false, false
}

// sandboxPaths computes the readable and writable path sets for cwd, mirroring
// the boundaries the bash tool enforces (see cmd/serve.go) so the filesystem
// hook and the bash sandbox agree on what is in-bounds. Writable paths are also
// readable, so they are folded into the read set.
func sandboxPaths(cwd string) (readPaths, writePaths []string) {
	sb := bash_sandboxed.NewSandbox()
	defer sb.Close()
	if cfg, err := config.Load(); err == nil && cfg != nil {
		sb.UpdateConfig(cfg, cwd)
	}

	readPaths = append([]string{cwd}, sb.RuntimeReadPaths()...)
	readPaths = append(readPaths, sb.ConfigReadPaths()...)
	readPaths = append(readPaths, sb.ConfigWritePaths()...)

	writePaths = append([]string{cwd}, sb.ConfigWritePaths()...)

	if parent := sb.WorktreeParentPath(cwd); parent != "" {
		readPaths = append(readPaths, parent)
		writePaths = append(writePaths, parent)
	}
	return readPaths, writePaths
}
