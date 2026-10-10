package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/approval"
	"github.com/gartnera/lite-sandbox/internal/audit"
	"github.com/gartnera/lite-sandbox/internal/configrequest"
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

// mcpToolPrefix identifies the sandbox's own MCP tools (mcp__lite-sandbox__bash
// and its background-process companions), and mcpToolMatcher is the
// corresponding settings.json hook matcher (matchers are regexes).
const (
	mcpToolPrefix  = "mcp__lite-sandbox__"
	mcpToolMatcher = "mcp__lite-sandbox__.*"
)

// grokMCPToolPrefix is how Grok Build names the sandbox's MCP tools:
// `<server>__<tool>`, with no mcp__ prefix (lite-sandbox__bash, ...). The model
// reaches them through Grok's use_tool dispatcher, and hooks see the qualified
// name.
const grokMCPToolPrefix = grokServerName + "__"

// hookOptions are the hook's flags, fixed by the installer when it registers
// the hook.
type hookOptions struct {
	// validateBash selects the --bash-ast-hook-mode behavior: instead of
	// denying the built-in Bash tool, parse and validate its command against
	// the sandbox and allow it when it passes. Set by --validate-bash.
	validateBash bool
	// configRequests says the MCP server runs config requests
	// (serve-mcp --config-requests) and this agent prompts the user when the
	// hook answers "ask". Only then does the hook put a config request — a bash
	// tool call that is just `lite-sandbox config ...` — before the user; without
	// it the call is pre-approved like any other and the sandbox's deny list
	// refuses it. Set by --config-requests.
	configRequests bool
}

var hookFlags hookOptions

var hookCmd = &cobra.Command{
	Use:   "hook",
	Short: "Evaluate a Claude Code, Codex, or Grok Build PreToolUse event from stdin",
	Long: "Reads a PreToolUse hook event as JSON on stdin (Claude Code's protocol, which " +
		"Codex and Grok Build also speak) and enforces " +
		"the sandbox's filesystem boundaries: reads outside the readable paths and " +
		"writes outside the writable paths are denied. The sandbox's own MCP tools " +
		"(mcp__lite-sandbox__*) are allowed outright, so they stay prompt-free in " +
		"subagents and skills, which do not inherit permissions.allow " +
		"(anthropics/claude-code#18950). All other calls defer to " +
		"Claude Code's normal permission flow. Invoked by Claude Code; registered " +
		"by `lite-sandbox install`.\n\n" +
		"With --validate-bash, the built-in Bash tool is validated through the " +
		"sandbox (AST whitelist + path boundaries) and allowed when it passes " +
		"instead of being redirected to the MCP tool.\n\n" +
		"With --config-requests, a bash tool call that is just `lite-sandbox config ...` " +
		"is answered \"ask\" instead, and recorded so the MCP server (serve-mcp " +
		"--config-requests) knows the user was asked before it runs the change. " +
		"Likewise a bash tool call that runs a command whose commands entry has ask: true.\n\n" +
		"With --validate-bash, a built-in Bash command that runs such a command is answered " +
		"\"ask\" when the agent puts an ask to the user (Claude Code), and denied otherwise.",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runHook(cmd, hookFlags)
	},
}

func init() {
	hookCmd.Flags().BoolVar(&hookFlags.validateBash, "validate-bash", false,
		"validate the built-in Bash command through the sandbox and allow it when it passes, instead of denying it")
	hookCmd.Flags().BoolVar(&hookFlags.configRequests, "config-requests", false,
		"ask the user to approve each `lite-sandbox config` command run with the sandbox's bash tool (the server runs only those the hook asked about)")
	rootCmd.AddCommand(hookCmd)
}

// runHook is the hot path Claude Code invokes per tool call. It is deliberately
// fail-open: any internal error (unparseable event, missing cwd) defers to
// Claude Code's normal permission flow rather than blocking the user's work.
func runHook(cmd *cobra.Command, opts hookOptions) error {
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

	decision := evaluate(event, opts)
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
func evaluate(event *hook.Event, opts hookOptions) *hook.Decision {
	// A config request rewrites the policy itself, so unlike every other
	// sandbox bash command it is never pre-approved: the user confirms it.
	// Its decisions are about running `lite-sandbox config`, so they get no
	// hint suggesting it.
	if event.ToolName == mcpToolPrefix+"bash" {
		if d := evaluateConfigRequest(event, opts); d != nil {
			return d
		}
		if d := evaluateAskCommand(event, opts); d != nil {
			return d
		}
	}
	d := evaluateTool(event, opts)
	// A denial naming a `lite-sandbox config` fix also says the agent can run
	// it, when this agent can put config requests to the user.
	if d != nil && opts.configRequests && !event.FromGrok() &&
		d.HookSpecificOutput.PermissionDecision == hook.DecisionDeny {
		d.HookSpecificOutput.PermissionDecisionReason = withConfigRequestHint(d.HookSpecificOutput.PermissionDecisionReason)
	}
	return d
}

// evaluateTool is evaluate before the config request hint.
func evaluateTool(event *hook.Event, opts hookOptions) *hook.Decision {
	validateBash := opts.validateBash
	// The sandbox's own MCP tools are pre-approved via the hook because
	// subagents and skills do not inherit permissions.allow from settings.json
	// (anthropics/claude-code#18950) but PreToolUse hooks still fire there.
	// This grants nothing the installer's allow rules don't already: the tools
	// validate and sandbox every command themselves.
	if strings.HasPrefix(event.ToolName, mcpToolPrefix) || strings.HasPrefix(event.ToolName, grokMCPToolPrefix) {
		return hook.NewDecision(hook.DecisionAllow,
			"Pre-approved by lite-sandbox: its MCP tools validate and sandbox every command themselves.")
	}
	// Claude Code's and Codex's Bash, or one of Grok Build's shell tools
	// (run_terminal_command, monitor, ...). The redirect needs only the name.
	if hook.IsShellTool(event.ToolName) && !validateBash {
		return denyBuiltinBash(event)
	}
	if d := denyUninspectableGrokInput(event); d != nil {
		return d
	}
	if hook.IsShellTool(event.ToolName) {
		return validateBuiltinBash(event)
	}
	return evaluatePathPolicy(event)
}

// evaluateConfigRequest decides a sandbox bash tool call that is a config
// request (configrequest.Parse), or returns nil for any other command. When
// this agent was installed to make config requests (--config-requests), it
// scopes the request to the working directory (Request.Scope: always a --dir
// override, never the global config), records a ticket for the exact scoped
// request and answers "ask", so the agent prompts the user; the server runs the request only on that ticket (see
// internal/configrequest). Without the flag it returns nil: the call is
// pre-approved like any other, and the sandbox's deny list refuses it.
func evaluateConfigRequest(event *hook.Event, opts hookOptions) *hook.Decision {
	if !opts.configRequests || event.FromGrok() {
		return nil
	}
	// Read exactly as the server does (bashToolArgs), so the command the hook
	// judges is the one that runs. Input the server cannot read either is
	// refused there, so deferring to the usual pre-approval is safe.
	var args map[string]any
	if err := json.Unmarshal(event.RawToolInput, &args); err != nil {
		return nil
	}
	command, background, ok := bashToolArgs(args)
	if !ok {
		return nil
	}
	req, ok := configrequest.Parse(command)
	if !ok {
		return nil
	}
	if background {
		return hook.NewDecision(hook.DecisionDeny,
			"Blocked by lite-sandbox: run `lite-sandbox config` in the foreground (run_in_background false).")
	}
	if err := req.Validate(); err != nil {
		return hook.NewDecision(hook.DecisionDeny, "Blocked by lite-sandbox: "+err.Error())
	}
	cwd := eventCWD(event)
	scoped, err := req.Scope(cwd)
	if err != nil {
		return hook.NewDecision(hook.DecisionDeny, "Blocked by lite-sandbox: "+err.Error())
	}
	if err := configrequest.Issue(cwd, req); err != nil {
		return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
			"Blocked by lite-sandbox: could not record the request for the user's approval: %v", err))
	}
	return hook.NewDecision(hook.DecisionAsk,
		"lite-sandbox: the agent asks to change the sandbox's own configuration, for this directory only (the global config is left alone): "+scoped.Command())
}

// evaluateAskCommand decides a sandbox bash tool call whose command runs
// a prompted invocation (a commands entry with ask: true), or returns nil
// for any other command. When this agent was installed to make config
// requests (--config-requests, which the server's flag of the same name
// pairs with), it validates the command as the server would once approved —
// a command the sandbox refuses anyway is denied with that error rather than
// put to the user — then records a ticket for the exact command and answers
// "ask"; the server treats the call as approved only on that ticket (see
// internal/approval). Without the flag it returns nil: the call is
// pre-approved like any other, and the sandbox refuses the prompted command
// for want of an approval.
func evaluateAskCommand(event *hook.Event, opts hookOptions) *hook.Decision {
	if !opts.configRequests || !event.CanAsk() {
		return nil
	}
	var args map[string]any
	if err := json.Unmarshal(event.RawToolInput, &args); err != nil {
		return nil
	}
	command, _, ok := bashToolArgs(args)
	if !ok {
		return nil
	}
	cwd := eventCWD(event)
	if cwd == "" {
		return nil
	}
	// The hot path for every sandbox bash call: read the settings alone, and
	// build a sandbox only when some entry asks.
	if cfg, err := config.LoadSettingsForDirectory(cwd); err != nil || len(cfg.AskCommandList()) == 0 {
		return nil
	}
	sb := configuredSandbox(cwd)
	defer sb.Close()
	prompted := sb.AskCommands(command)
	if len(prompted) == 0 {
		return nil
	}
	readPaths, writePaths := sandboxPaths(sb, cwd)
	if err := sb.ValidateCommandContext(bash_sandboxed.WithApproval(context.Background()), command, cwd, readPaths, writePaths); err != nil {
		return hook.NewDecision(hook.DecisionDeny, "Blocked by lite-sandbox: this command did not pass sandbox validation: "+withConfigRequestHint(err.Error()))
	}
	if err := approval.Issue(cwd, approval.CommandSubject(command), command); err != nil {
		return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
			"Blocked by lite-sandbox: could not record the command for the user's approval: %v", err))
	}
	return hook.NewDecision(hook.DecisionAsk, askReason(prompted))
}

// askReason is the "ask" reason for a command running the prompted
// entries, shown with the user's permission prompt.
func askReason(prompted []string) string {
	quoted := make([]string, len(prompted))
	for i, p := range prompted {
		quoted[i] = "`" + p + "`"
	}
	return "lite-sandbox: this command runs " + strings.Join(quoted, ", ") +
		", which the sandbox's config asks you to approve each time (commands entries with ask: true)."
}

// denyUninspectableGrokInput blocks a governed Grok Build tool call whose
// arguments the hook cannot read: either Grok clipped them (over its 128 KiB
// hook payload limit, sent as a truncated string) or they do not decode (a
// value of the wrong type). With no command or path to check, deferring would
// let a large write outside the project, or a command in
// --bash-ast-hook-mode, through unchecked — Grok's own argument parsing is
// lenient enough that the call may still run. This is the one case the hook
// fails closed, and only where the mode enforces the checks.
func denyUninspectableGrokInput(event *hook.Event) *hook.Decision {
	if !event.FromGrok() || !hook.IsGrokTool(event.ToolName) {
		return nil
	}
	if !event.ToolInputTruncated && event.ToolInput != nil {
		return nil
	}
	if cfg, _ := config.LoadSettingsForDirectory(eventCWD(event)); cfg.EffectiveMode() == config.ModeOpen {
		return nil
	}
	if event.ToolInputTruncated {
		return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
			"Blocked by lite-sandbox: this %s call is over Grok's 128 KiB hook limit, so its paths cannot be checked. "+
				"Split it into smaller calls (e.g. write part of the file, then add the rest with edits).",
			event.ToolName,
		))
	}
	return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
		"Blocked by lite-sandbox: the %s arguments could not be read, so their paths cannot be checked. "+
			"Pass each path (and the command) as a plain string.",
		event.ToolName,
	))
}

// denyBuiltinBash blocks the built-in Bash tool and points the model at the
// sandboxed MCP tool, which runs the same command through lite-sandbox's
// validation and path boundaries. The built-in Bash tool has no sandbox.
func denyBuiltinBash(event *hook.Event) *hook.Decision {
	if !hook.IsShellTool(event.ToolName) {
		return nil
	}
	what := event.ToolName
	if event.ToolInput != nil {
		what = event.ToolInput.Describe()
	}
	if event.FromGrok() {
		// Grok clips the reason to 256 characters, so it carries only the
		// redirect; the rules file explains the rest.
		return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
			"Blocked by lite-sandbox: the built-in %s tool is disabled. %s",
			event.ToolName, grokRedirectHint,
		))
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
//
// A command that runs a prompted invocation (a commands entry with
// ask: true) is validated as approved and, when it passes, answered "ask"
// so the agent puts it to the user — when the agent does that
// (hook.Event.CanAsk: Claude Code, not Codex or Grok Build). The built-in Bash
// tool runs only once the user approves, so no ticket is needed. Otherwise
// the ask check stands and the command is denied.
func validateBuiltinBash(event *hook.Event) *hook.Decision {
	in, ok := event.ToolInput.(hook.ShellInput)
	if !ok || in.ShellCommand() == "" {
		// Could not see the command; defer rather than guess.
		return nil
	}

	sb, cwd := sandboxForEvent(event)
	if sb == nil {
		// Without a working directory we cannot resolve path boundaries; defer.
		return nil
	}
	defer sb.Close()
	readPaths, writePaths := sandboxPaths(sb, cwd)

	var prompted []string
	ctx := context.Background()
	if event.CanAsk() {
		if prompted = sb.AskCommands(in.ShellCommand()); len(prompted) > 0 {
			ctx = bash_sandboxed.WithApproval(ctx)
		}
	}
	if err := sb.ValidateCommandContext(ctx, in.ShellCommand(), cwd, readPaths, writePaths); err != nil {
		if event.FromGrok() {
			// Short enough to survive Grok's 256-character clip, with the
			// validation error (which names the fix) up front.
			return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
				"Blocked by lite-sandbox: this command did not pass sandbox validation: %v", err))
		}
		reason := fmt.Sprintf(
			"Blocked by lite-sandbox: this command did not pass sandbox validation.\n"+
				"Attempted action: %s\n"+
				"Reason: %v\n"+
				"What to do instead: rework the command to use only sandbox-approved, "+
				"non-destructive operations within the project's paths. If this command "+
				"is genuinely needed, ask the user to permit it via `lite-sandbox config` "+
				"(e.g. `config commands allow` or `config paths allow`).",
			in.Describe(), err,
		)
		return hook.NewDecision(hook.DecisionDeny, reason)
	}
	// A pass auto-approves (skipping the permission prompt) only in allowlist
	// mode, where "passed" means the full whitelist held. In denylist and open
	// mode the whitelist is advisory, so a pass says nothing about what the
	// command runs — and the built-in Bash tool has no runtime layer and no OS
	// sandbox worker behind it. Defer to Claude Code's normal permission flow
	// instead: the static checks that did apply were still enforced above.
	if len(prompted) > 0 {
		return hook.NewDecision(hook.DecisionAsk, askReason(prompted))
	}
	if cfg, _ := config.LoadSettingsForDirectory(cwd); cfg.EffectiveMode() != config.ModeAllowlist {
		return nil
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
	// Grok Build's file tools: check every spelling of the target the tool may
	// open (see PathToolInput.Paths).
	if pt, ok := event.ToolInput.(*hook.PathToolInput); ok {
		return evaluatePaths(event, pt.Describe(), pt.Paths(), pt.Write())
	}
	// Grok Build's image and video tools read the local files they reference.
	if mi, ok := event.ToolInput.(*hook.MediaInput); ok {
		return evaluatePaths(event, mi.Describe(), mi.Paths(), false)
	}

	path, write, governed := fsTarget(event)
	if !governed || path == "" {
		// Not a filesystem tool we govern, or no explicit path was supplied
		// (e.g. Glob/Grep without a path default to cwd, which is allowed).
		return nil
	}

	if isClaudeConfigTarget(path, eventCWD(event), write) {
		return nil
	}

	sb, cwd := sandboxForEvent(event)
	if sb == nil {
		// Without a working directory we cannot resolve the boundary; fail-open.
		return nil
	}
	defer sb.Close()

	what := event.ToolName
	if event.ToolInput != nil {
		what = event.ToolInput.Describe()
	}
	return boundaryDenial(sb, cwd, what, path, write, event.FromGrok())
}

// isClaudeConfigTarget reports whether a Claude Code file tool's target
// resolves inside a .claude directory (see bash_sandboxed.IsClaudeConfigPath).
// The hook leaves those calls to Claude Code's normal permission flow, reads
// and writes alike: Claude Code treats .claude as a protected path and prompts
// before writing it, so the user decides — rather than the hook denying
// ~/.claude as outside the boundary, or letting a project's .claude through as
// inside it. Sandboxed bash, by contrast, may only read .claude.
//
// Only the resolved path counts, so a symlink named .claude (a cloned repo's
// .claude -> ~/.ssh) gets the boundary check like any other path. A write into
// .git keeps its denial, and the read-denied built-ins and config denials
// (~/.claude/.credentials.json) keep the boundary check: deferring them
// would hand the agent's credentials to a read Claude Code may not prompt for.
func isClaudeConfigTarget(path, cwd string, write bool) bool {
	if cwd == "" && !filepath.IsAbs(path) {
		return false
	}
	resolved := bash_sandboxed.ResolvePath(path, cwd)
	if !bash_sandboxed.IsClaudeConfigPath(resolved) {
		return false
	}
	if write && bash_sandboxed.IsGitInternalPath(resolved) {
		return false
	}
	cfg, err := config.LoadForDirectory(cwd)
	if err != nil {
		return false
	}
	return !bash_sandboxed.IsUnderAllowedPaths(resolved, cfg.EffectiveDeniedReadPaths())
}

// evaluateApplyPatch enforces the writable-path boundary on Codex's apply_patch
// tool, which edits, creates, deletes, or renames files. Every target the patch
// touches must resolve inside the writable paths; the first one outside (or
// inside .git) is denied. When no patch targets are visible (unexpected input
// shape) it defers, keeping the hook fail-open.
func evaluateApplyPatch(event *hook.Event, ap *hook.ApplyPatchInput) *hook.Decision {
	return evaluatePaths(event, ap.Describe(), ap.Paths(), true)
}

// evaluatePaths enforces the sandbox boundary on every path a tool call
// touches (Codex's apply_patch, Grok Build's file and media tools): the
// readable paths for reads and searches, the writable paths for edits. A call
// without a path (grep or glob over the workspace) defers.
func evaluatePaths(event *hook.Event, what string, paths []string, write bool) *hook.Decision {
	if len(paths) == 0 {
		return nil
	}

	sb, cwd := sandboxForEvent(event)
	if sb == nil {
		// Without a working directory we cannot resolve the boundary; fail-open.
		return nil
	}
	defer sb.Close()

	for _, p := range paths {
		if d := boundaryDenial(sb, cwd, what, p, write, event.FromGrok()); d != nil {
			return d
		}
	}
	return nil
}

// boundaryDenial checks a single path against the sandbox boundary for the given
// access and returns a deny Decision if it is outside — or, for writes, inside a
// .git directory — otherwise nil (in bounds; defer). `what` describes the action
// for the deny message. It does the cheap boundary check (cwd + configured
// paths, profiles' included) before the full computation that may shell out to
// git, so common in-project accesses stay cheap. sb must be configured for cwd.
//
// compact selects the short form of the deny reason for Grok Build, which
// clips a hook's reason to 256 characters before the model sees it: the
// verdict and the fix come first, the paths last. The audit log always gets
// the full reason.
func boundaryDenial(sb *bash_sandboxed.Sandbox, cwd, what, path string, write, compact bool) *hook.Decision {
	resolved := bash_sandboxed.ResolvePath(path, cwd)

	// Writes into .git are blocked outright (matching the bash sandbox), so an
	// agent cannot plant a hook or rewrite git internals to escape the sandbox.
	if write && bash_sandboxed.IsGitInternalPath(resolved) {
		reason := fmt.Sprintf(
			"Blocked by lite-sandbox: %s\n"+
				"%q resolves to %q, which is inside a .git directory.\n"+
				"Writing git internals directly is not allowed; use git commands instead.",
			what, path, resolved,
		)
		if !auditHookFinding(cwd, what, resolved, reason) {
			return nil
		}
		if compact {
			reason = fmt.Sprintf("Blocked by lite-sandbox: writing inside a .git directory is not allowed; use git commands instead. Path: %s", resolved)
		}
		return hook.NewDecision(hook.DecisionDeny, reason)
	}

	// Cheap boundary first: cwd plus the configured paths cover the vast
	// majority of accesses and need no git invocation.
	cheap := append([]string{cwd}, sb.ConfigWritePaths()...)
	if !write {
		cheap = append(cheap, sb.ConfigReadPaths()...)
	}
	if bash_sandboxed.IsUnderAllowedPaths(resolved, cheap) {
		return nil
	}

	// Outside the cheap set: compute the full boundary, which adds the temp
	// and scratchpad roots and the worktree parent before deciding.
	readPaths, writePaths := sandboxPaths(sb, cwd)
	allowed := readPaths
	boundary := "readable"
	allowFlag := ""
	if write {
		allowed = writePaths
		boundary = "writable"
		allowFlag = " --write"
	}
	if bash_sandboxed.IsUnderAllowedPaths(resolved, allowed) {
		return nil
	}

	reason := fmt.Sprintf(
		"Blocked by lite-sandbox: %s\n"+
			"%q resolves to %q, which is outside the sandbox's %s paths.\n"+
			"Allowed %s paths: %s\n"+
			"What to do instead: work within the project directory (%s). "+
			"If this path is genuinely needed, ask the user to add it via "+
			"`lite-sandbox config paths allow <path>%s`.",
		what, path, resolved, boundary,
		boundary, strings.Join(allowed, ", "),
		cwd, allowFlag,
	)
	// The file-tool boundary is a path_boundary finding: enforced in denylist
	// and allowlist mode, advisory (audited, then deferred to Claude Code's
	// normal flow) in open mode.
	if !auditHookFinding(cwd, what, resolved, reason) {
		return nil
	}
	if compact {
		reason = fmt.Sprintf(
			"Blocked by lite-sandbox: outside the sandbox's %s paths. Work within the project, "+
				"or ask the user to run `lite-sandbox config paths allow <path>%s`. Path: %s",
			boundary, allowFlag, resolved,
		)
	}
	return hook.NewDecision(hook.DecisionDeny, reason)
}

// auditHookFinding records a hook path-boundary finding to the audit log when
// auditing is on and reports whether the current mode enforces it. In open mode
// nothing is enforced, so the caller defers instead of denying.
func auditHookFinding(cwd, tool, resolved, reason string) bool {
	cfg, _ := config.LoadSettingsForDirectory(cwd)
	mode := cfg.EffectiveMode()
	blocked := mode != config.ModeOpen
	if cfg.AuditEnabled() {
		if p, err := audit.DefaultPath(); err == nil {
			_ = audit.New(p, 0).Write(audit.Record{
				CWD:          cwd,
				Mode:         string(mode),
				Source:       "hook",
				Tool:         tool,
				Layer:        "hook",
				Rule:         "path_boundary",
				Message:      reason,
				Subject:      resolved,
				Blocked:      blocked,
				WouldBlockIn: []string{string(config.ModeDenylist), string(config.ModeAllowlist)},
			})
		}
	}
	return blocked
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

// sandboxForEvent resolves the working directory an event's paths are relative
// to (the event's cwd, falling back to the process's) and returns a sandbox
// configured for it. A nil sandbox means no working directory could be
// determined, so the caller must defer to Claude Code's normal flow. The caller
// owns Close() on a non-nil sandbox.
func sandboxForEvent(event *hook.Event) (*bash_sandboxed.Sandbox, string) {
	cwd := eventCWD(event)
	if cwd == "" {
		return nil, ""
	}
	return configuredSandbox(cwd), cwd
}

// eventCWD is the working directory an event's paths are relative to: the
// event's cwd, falling back to the process's ("" when neither is known).
func eventCWD(event *hook.Event) string {
	if event.CWD != "" {
		return event.CWD
	}
	cwd, _ := os.Getwd()
	return cwd
}

// configuredSandbox builds a sandbox for cwd with the user's config applied,
// matching how the MCP server constructs it. The caller owns Close().
func configuredSandbox(cwd string) *bash_sandboxed.Sandbox {
	sb := bash_sandboxed.NewSandbox()
	// Resolve per-directory overrides for cwd so the hook confines file tools to
	// the same effective path boundary the MCP server would for this directory.
	if cfg, err := config.LoadForDirectory(cwd); err == nil && cfg != nil {
		sb.UpdateConfig(cfg, cwd)
	}
	return sb
}
