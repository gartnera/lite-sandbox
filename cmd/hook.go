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
// registered in settings.json (Claude Code) or config.toml (Codex). It covers
// the built-in Bash tool (which the hook redirects to the MCP tool) and the
// filesystem tools whose paths we govern. apply_patch is Codex's file-editing
// tool (Claude never emits it, so it is a harmless no-op there). The hook itself
// re-checks the tool name, so the matcher is just an optimization that avoids
// invoking the binary for unrelated tools.
const hookToolMatcher = "Bash|Read|Edit|Write|NotebookEdit|Glob|Grep|apply_patch"

// bashValidateMatcher is the matcher used in --bash-ast-hook-mode, where the
// hook only governs the built-in Bash tool (validating its command rather than
// redirecting it) and leaves the filesystem tools to Claude Code's normal flow.
const bashValidateMatcher = "Bash"

// hookValidateBash selects the --bash-ast-hook-mode behavior: instead of denying the
// built-in Bash tool, parse and validate its command against the sandbox and
// allow it when it passes. Set by the --validate-bash flag.
var hookValidateBash bool

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Evaluate a Claude Code PreToolUse event from stdin",
	Long: "Reads a Claude Code PreToolUse hook event as JSON on stdin and enforces " +
		"the sandbox's filesystem boundaries: reads outside the readable paths and " +
		"writes outside the writable paths are denied. All other calls defer to " +
		"Claude Code's normal permission flow. Invoked by Claude Code; register it " +
		"with `lite-sandbox install --with-tool-hook`.\n\n" +
		"With --validate-bash, the built-in Bash tool is validated through the " +
		"sandbox (AST whitelist + path boundaries) and allowed when it passes " +
		"instead of being redirected to the MCP tool.",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runHook(cmd, hookValidateBash)
	},
}

func init() {
	hookCmd.Flags().BoolVar(&hookValidateBash, "validate-bash", false,
		"validate the built-in Bash command through the sandbox and allow it when it passes, instead of denying it")
	rootCmd.AddCommand(hookCmd)
}

// runHook is the hot path Claude Code invokes per tool call. It is deliberately
// fail-open: any internal error (unparseable event, missing cwd) defers to
// Claude Code's normal permission flow rather than blocking the user's work.
func runHook(cmd *cobra.Command, validateBash bool) error {
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

	decision := evaluate(event, validateBash)
	if decision == nil {
		// Nothing to enforce: defer to normal permission flow (no JSON).
		return nil
	}
	return decision.Write(out)
}

// evaluate returns a decision for a governed tool call, or nil to defer to
// Claude Code's normal permission flow. For the built-in Bash tool: when
// validateBash is set (--bash-ast-hook-mode) the command is validated through
// the sandbox and allowed when it passes; otherwise it is redirected to the
// sandboxed MCP tool. Filesystem tools are checked against path boundaries.
func evaluate(event *hook.Event, validateBash bool) *hook.Decision {
	if event.ToolName == hook.ToolBash {
		if validateBash {
			return validateBuiltinBash(event)
		}
		return denyBuiltinBash(event)
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

// validateBuiltinBash parses and validates the built-in Bash tool's command
// through the sandbox (AST whitelist + read/write path boundaries). A command
// that passes is allowed outright (skipping the permission prompt, mirroring the
// MCP tool's pre-approval); a command that fails is denied with the validation
// error so the model can correct it. Any inability to inspect the command
// (missing input, no cwd) fails open to Claude Code's normal flow.
func validateBuiltinBash(event *hook.Event) *hook.Decision {
	in, ok := event.ToolInput.(*hook.BashInput)
	if !ok || in.Command == "" {
		// Could not see the command; defer rather than guess.
		return nil
	}

	cwd := event.CWD
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if cwd == "" {
		// Without a working directory we cannot resolve path boundaries; defer.
		return nil
	}

	sb := configuredSandbox(cwd)
	defer sb.Close()
	readPaths, writePaths := computeSandboxPaths(sb, cwd)

	if err := sb.ValidateCommand(in.Command, cwd, readPaths, writePaths); err != nil {
		reason := fmt.Sprintf(
			"Blocked by lite-sandbox: this command did not pass sandbox validation.\n"+
				"Attempted action: %s\n"+
				"Reason: %v\n"+
				"What to do instead: rework the command to use only sandbox-approved, "+
				"non-destructive operations within the project's paths. If this command "+
				"is genuinely needed, ask the user to permit it via `lite-sandbox config` "+
				"(e.g. extra-commands or readable/writable paths).",
			in.Describe(), err,
		)
		return hook.NewDecision(hook.DecisionDeny, reason)
	}
	return hook.NewDecision(hook.DecisionAllow, "Validated by lite-sandbox: command passed the sandbox AST whitelist and path boundaries.")
}

// evaluatePathPolicy returns a deny decision when a filesystem tool targets a
// path outside the sandbox boundary, or nil to defer to Claude Code's normal
// flow. Read-family tools (Read/Glob/Grep) are checked against the readable
// paths; write-family tools (Edit/Write/NotebookEdit) against the writable
// paths.
func evaluatePathPolicy(event *hook.Event) *hook.Decision {
	// Codex's apply_patch can touch several files in one call; check every write
	// target against the writable boundary.
	if ap, ok := event.ToolInput.(*hook.ApplyPatchInput); ok {
		return evaluateApplyPatch(event, ap)
	}

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

	sb := configuredSandbox(cwd)
	defer sb.Close()

	resolved := bash_sandboxed.ResolvePath(path, cwd)

	// Cheap boundary first: cwd plus the user-configured paths cover the vast
	// majority of accesses and need no runtime detection or git invocation.
	cheap := append([]string{cwd}, sb.ConfigWritePaths()...)
	if !write {
		cheap = append(cheap, sb.ConfigReadPaths()...)
	}
	if bash_sandboxed.IsUnderAllowedPaths(resolved, cheap) {
		// Inside the boundary: defer to Claude Code's normal permission flow.
		return nil
	}

	// Outside the cheap set: compute the full boundary, which adds detected
	// runtime paths (read side) and the worktree parent before deciding.
	readPaths, writePaths := computeSandboxPaths(sb, cwd)
	allowed := readPaths
	boundary := "readable"
	configNoun := "readable"
	if write {
		allowed = writePaths
		boundary = "writable"
		configNoun = "writable"
	}

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

// evaluateApplyPatch enforces the writable-path boundary on Codex's apply_patch
// tool, which edits, creates, deletes, or renames files. Every target the patch
// touches must resolve inside the writable paths; the first one outside is
// denied. When no patch targets are visible (unexpected input shape) it defers,
// keeping the hook fail-open.
func evaluateApplyPatch(event *hook.Event, ap *hook.ApplyPatchInput) *hook.Decision {
	paths := ap.Paths()
	if len(paths) == 0 {
		// Could not see the patch targets; defer rather than guess.
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

	sb := configuredSandbox(cwd)
	defer sb.Close()
	_, writePaths := computeSandboxPaths(sb, cwd)

	for _, p := range paths {
		resolved := bash_sandboxed.ResolvePath(p, cwd)
		if bash_sandboxed.IsUnderAllowedPaths(resolved, writePaths) {
			continue
		}
		reason := fmt.Sprintf(
			"Blocked by lite-sandbox: %s\n"+
				"%q resolves to %q, which is outside the sandbox's writable paths.\n"+
				"Allowed writable paths: %s\n"+
				"What to do instead: work within the project directory (%s). "+
				"If this path is genuinely needed, ask the user to add it via "+
				"`lite-sandbox config writable-paths add <path>`.",
			ap.Describe(), p, resolved,
			strings.Join(writePaths, ", "),
			cwd,
		)
		return hook.NewDecision(hook.DecisionDeny, reason)
	}
	return nil
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

// configuredSandbox builds a sandbox for cwd with the user's config applied,
// matching how the MCP server constructs it. The caller owns Close().
func configuredSandbox(cwd string) *bash_sandboxed.Sandbox {
	sb := bash_sandboxed.NewSandbox()
	if cfg, err := config.Load(); err == nil && cfg != nil {
		sb.UpdateConfig(cfg, cwd)
	}
	return sb
}

// computeSandboxPaths derives the readable and writable path sets from an
// already-configured sandbox. Writable paths are also readable, so they are
// folded into the read set.
func computeSandboxPaths(sb *bash_sandboxed.Sandbox, cwd string) (readPaths, writePaths []string) {
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
