package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
// the built-in shell tools, Bash and Monitor (which the hook redirects to the
// MCP tool), and the filesystem tools whose paths we govern. apply_patch is
// Codex's file-editing tool (Claude never emits it, so it is a harmless no-op
// there). The hook itself re-checks the tool name, so the matcher is just an
// optimization that avoids invoking the binary for unrelated tools.
const hookToolMatcher = "Bash|Monitor|Read|Edit|Write|NotebookEdit|Glob|Grep|apply_patch"

// bashValidateMatcher is the matcher used in --bash-ast-hook-mode, where the
// hook only governs the built-in shell tools (validating their command rather
// than redirecting it) and leaves the filesystem tools to Claude Code's normal
// flow. Monitor runs its command in the background with the same shell as
// Bash, so it is governed alongside it.
const bashValidateMatcher = "Bash|Monitor"

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

// piMCPToolPrefix is how pi names the sandbox's MCP tools:
// `mcp__<server>__<tool>` with every character other than letters, digits and
// _ replaced by _, so lite-sandbox's tools are mcp__lite_sandbox__bash, ...
const piMCPToolPrefix = "mcp__lite_sandbox__"

// opencodeMCPToolPrefix is how opencode names the sandbox's MCP tools,
// `<server>_<tool>` (lite-sandbox_bash, ...), in its tool hooks and
// permission rules. In a Code Mode program the model calls the same tool as
// tools["lite-sandbox"].bash, and a top-level call may spell it by that
// qualified name, lite-sandbox.bash; the plugin sends either as
// lite-sandbox_bash.
const opencodeMCPToolPrefix = "lite-sandbox_"

// isSandboxBashTool reports whether the event is a call to the sandbox's own
// bash MCP tool, under the name the sending agent gives it.
func isSandboxBashTool(event *hook.Event) bool {
	switch {
	case event.FromPi():
		return event.ToolName == piMCPToolPrefix+"bash"
	case event.FromOpencode():
		return event.ToolName == opencodeMCPToolPrefix+"bash"
	}
	return event.ToolName == mcpToolPrefix+"bash"
}

// isSandboxMCPTool reports whether the event is a call to any of the
// sandbox's MCP tools (bash, kill_shell, list_shells).
func isSandboxMCPTool(event *hook.Event) bool {
	switch {
	case event.FromPi():
		return strings.HasPrefix(event.ToolName, piMCPToolPrefix)
	case event.FromOpencode():
		return strings.HasPrefix(event.ToolName, opencodeMCPToolPrefix)
	}
	return strings.HasPrefix(event.ToolName, mcpToolPrefix) || strings.HasPrefix(event.ToolName, grokMCPToolPrefix)
}

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
	Short: "Evaluate a Claude Code, Codex, Grok Build, pi, or opencode PreToolUse event (or a Claude Code PermissionRequest event) from stdin",
	Long: "Reads a PreToolUse hook event as JSON on stdin (Claude Code's protocol, which " +
		"Codex and Grok Build also speak, and lite-sandbox's pi extension and opencode plugin send) and enforces " +
		"the sandbox's filesystem boundaries: reads outside the readable paths and " +
		"writes outside the writable paths are denied. The sandbox's own MCP tools " +
		"(mcp__lite-sandbox__*) are allowed outright, so they stay prompt-free in " +
		"subagents and skills, which do not inherit permissions.allow " +
		"(anthropics/claude-code#18950). All other calls defer to " +
		"Claude Code's normal permission flow. Invoked by Claude Code; registered " +
		"by `lite-sandbox install`.\n\n" +
		"For Claude Code's PermissionRequest event, it allows the sandbox's MCP tools in " +
		"plan mode, where Claude Code ignores the PreToolUse allow and permissions.allow, " +
		"except for a call the PreToolUse hook answers \"ask\", which is left to the user.\n\n" +
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
	if event.HookEventName == hook.EventPermissionRequest {
		if d := evaluatePermissionRequest(event, opts); d != nil {
			return d.Write(out)
		}
		return nil
	}
	if event.HookEventName != hook.EventPreToolUse {
		// Not our event; defer.
		return nil
	}

	decision := evaluate(event, opts)
	if decision == nil && event.FromOpencode() {
		// lite-sandbox's opencode plugin forwards only the calls it governs,
		// and rejects one the hook gives no answer for, so that a hook that
		// failed before deciding blocks the call. Its deferrals are allows.
		decision = hook.NewDecision(hook.DecisionAllow, "lite-sandbox: nothing to enforce for this call.")
	}
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
	if isSandboxBashTool(event) {
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
	if isSandboxMCPTool(event) {
		return hook.NewDecision(hook.DecisionAllow,
			"Pre-approved by lite-sandbox: its MCP tools validate and sandbox every command themselves.")
	}
	// A Monitor WebSocket watch runs no shell: it is network access by the
	// agent itself, like WebFetch, and Claude Code asks before opening one.
	if in, ok := event.ToolInput.(*hook.MonitorInput); ok && in.IsWebSocket() {
		return nil
	}
	// Claude Code's and Codex's Bash, Claude Code's Monitor, one of Grok
	// Build's shell tools (run_terminal_command, monitor, ...), pi's bash, or
	// opencode's shell. The redirect needs only the name. pi's powershell
	// tool runs PowerShell, which the bash validator cannot check, so it is
	// always redirected, as is opencode's shell: opencode has no
	// --bash-ast-hook-mode.
	if event.IsShellTool() && (!validateBash || event.FromOpencode() ||
		(event.FromPi() && event.ToolName == hook.PiToolPowerShell)) {
		return denyBuiltinBash(event)
	}
	if d := denyUninspectableGrokInput(event); d != nil {
		return d
	}
	if d := denyUninspectableOpencodeInput(event); d != nil {
		return d
	}
	if event.IsShellTool() {
		return validateBuiltinBash(event)
	}
	return evaluatePathPolicy(event)
}

// evaluateConfigRequest decides a sandbox bash tool call that is a config
// request (configrequest.Parse), or returns nil for any other command. When
// this agent was installed to make config requests (--config-requests), it
// parses the request as the config command will (parseConfigRequest, which
// refuses --dir and whole-file commands), records a ticket for the exact
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
	scope, err := parseConfigRequest(req)
	if err != nil {
		return hook.NewDecision(hook.DecisionDeny, "Blocked by lite-sandbox: "+err.Error())
	}
	if scope.ReadOnly {
		// A read changes nothing; the server runs it without a ticket.
		return hook.NewDecision(hook.DecisionAllow,
			"Pre-approved by lite-sandbox: `"+req.Command()+"` only reads the config.")
	}
	cwd := eventCWD(event)
	// The ticket names the directory shown here, so the server runs the
	// request only if it resolves the same one.
	scopeDir := configrequest.DefaultDir(cwd)
	if !configrequest.Displayable(scopeDir) {
		return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
			"Blocked by lite-sandbox: the project directory %q contains characters the approval prompt cannot show faithfully", scopeDir))
	}
	if err := configrequest.Issue(cwd, scopeDir, req); err != nil {
		return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
			"Blocked by lite-sandbox: could not record the request for the user's approval: %v", err))
	}
	return hook.NewDecision(hook.DecisionAsk,
		req.Command()+"\n"+scope.Summary(tildePath(scopeDir)))
}

// tildePath abbreviates the home directory in p as ~, for display.
func tildePath(p string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return p
	}
	if p == home {
		return "~"
	}
	if rest, ok := strings.CutPrefix(p, home+string(filepath.Separator)); ok {
		return "~" + string(filepath.Separator) + rest
	}
	return p
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
	sb, prompted := promptedCommands(command, cwd)
	if sb == nil {
		return nil
	}
	defer sb.Close()
	readPaths, writePaths := sandboxPaths(sb, cwd)
	if err := sb.ValidateCommandContext(bash_sandboxed.WithApproval(context.Background()), command, cwd, readPaths, writePaths); err != nil {
		return hook.NewDecision(hook.DecisionDeny, "Blocked by lite-sandbox: this command did not pass sandbox validation: "+withConfigRequestHint(err.Error()))
	}
	reason := askReason(prompted)
	if event.FromOpencode() {
		// opencode's prompt shows the plugin's request by its title alone, and
		// a Code Mode program can build the command at run time, so the reason
		// leads with the command itself, which must then show as it is.
		if !configrequest.Displayable(command) {
			return hook.NewDecision(hook.DecisionDeny,
				"Blocked by lite-sandbox: this command runs a command the sandbox's config asks the user to approve, "+
					"and it contains characters (such as a line break) the approval prompt cannot show faithfully. "+
					"Put it on one line.")
		}
		reason = command + "\n" + strings.TrimPrefix(reason, "lite-sandbox: ")
	}
	if err := approval.Issue(cwd, approval.CommandSubject(command), command); err != nil {
		return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
			"Blocked by lite-sandbox: could not record the command for the user's approval: %v", err))
	}
	return hook.NewDecision(hook.DecisionAsk, reason)
}

// promptedCommands returns the commands entries with ask: true that command
// runs, with the sandbox that found them (the caller closes it), or a nil
// sandbox when it runs none. It has no side effects. It is the hot path for
// every sandbox bash call, so it reads the settings alone and builds a sandbox
// only when some entry asks.
func promptedCommands(command, cwd string) (*bash_sandboxed.Sandbox, []string) {
	if cfg, err := config.LoadSettingsForDirectory(cwd); err != nil || len(cfg.AskCommandList()) == 0 {
		return nil, nil
	}
	sb := configuredSandbox(cwd)
	prompted := sb.AskCommands(command)
	if len(prompted) == 0 {
		sb.Close()
		return nil, nil
	}
	return sb, prompted
}

// evaluatePermissionRequest answers Claude Code's PermissionRequest event,
// which fires when Claude Code is about to prompt the user for a tool call.
// It allows a call to one of the sandbox's MCP tools in plan mode, and
// otherwise returns nil to leave the prompt to the user.
//
// Plan mode is the one place the PreToolUse allow (evaluateTool) and the
// installer's permissions.allow rules don't reach: Claude Code ignores both
// for a call it doesn't consider read-only, and it counts every MCP tool as
// such (https://code.claude.com/docs/en/permissions.md#hook-approvals-in-plan-mode,
// anthropics/claude-code#104446). A PermissionRequest allow still applies
// there. Like the PreToolUse allow, it grants nothing the sandbox doesn't
// already police: the tools validate and sandbox every command themselves,
// and Claude Code still applies matching deny and ask rules.
//
// It must not answer for a call that PreToolUse put to the user on purpose.
// Claude Code shows that prompt too, and so fires this event for it. That
// covers a config request and a command whose commands entry has ask: true:
// for those it defers, so the user still decides. It is side-effect free:
// the approval tickets those prompts depend on are issued by PreToolUse
// alone.
//
// Plan mode writes: a call allowed here runs with the sandbox's usual write
// set, the same as outside plan mode. This is the place to consult a setting
// that confines plan mode to reads instead.
func evaluatePermissionRequest(event *hook.Event, opts hookOptions) *hook.PermissionRequestDecision {
	if event.PermissionMode != hook.PermissionModePlan || !isSandboxMCPTool(event) ||
		event.FromGrok() || event.FromPi() || event.FromCodex() || event.FromOpencode() {
		return nil
	}
	if isSandboxBashTool(event) && needsUserApproval(event, opts) {
		return nil
	}
	return hook.NewPermissionRequestDecision(hook.BehaviorAllow)
}

// needsUserApproval reports whether a sandbox bash call is one that
// evaluateConfigRequest or evaluateAskCommand would put to the user: a config
// request that changes the config, or a command running a commands entry with
// ask: true. It reads the call as they do but issues no ticket. When the
// arguments can't be read it answers true, so the user decides.
func needsUserApproval(event *hook.Event, opts hookOptions) bool {
	if !opts.configRequests {
		// Without --config-requests neither is ever put to the user: the server
		// refuses both outright, so there is nothing to protect.
		return false
	}
	var args map[string]any
	if err := json.Unmarshal(event.RawToolInput, &args); err != nil {
		return true
	}
	command, _, ok := bashToolArgs(args)
	if !ok {
		return true
	}
	if req, ok := configrequest.Parse(command); ok {
		scope, err := parseConfigRequest(req)
		return err != nil || !scope.ReadOnly
	}
	cwd := eventCWD(event)
	if cwd == "" {
		return true
	}
	sb, _ := promptedCommands(command, cwd)
	if sb == nil {
		return false
	}
	sb.Close()
	return true
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

// opencodeMediaOutputs returns the paths an opencode media tool may write for
// each requested path: the path itself, and every existing entry beside it
// whose name starts with the path's name without its extension.
// generate_image saves to the path with the extension of the image's real
// format, and generate_video its second and later videos to name-1.ext,
// name-2.ext, ..., writing through a symlink already at that name; listing
// the entries lets the boundary check follow such a link.
func opencodeMediaOutputs(cwd string, paths []string) []string {
	out := slices.Clone(paths)
	for _, p := range paths {
		abs := p
		if !filepath.IsAbs(abs) {
			if cwd == "" {
				continue
			}
			abs = filepath.Join(cwd, abs)
		}
		dir, base := filepath.Split(abs)
		stem := strings.TrimSuffix(base, filepath.Ext(base))
		entries, err := os.ReadDir(dir)
		if err != nil || stem == "" {
			continue
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), stem) {
				if q := filepath.Join(dir, e.Name()); !slices.Contains(out, q) {
					out = append(out, q)
				}
			}
		}
	}
	return out
}

// denyUninspectableOpencodeInput blocks a governed opencode tool call whose
// arguments the hook cannot read (a value of the wrong type, or input that is
// not an object). The plugin forwards a call before the tool decodes it, and
// deferring would let the call run unchecked if opencode reads the input
// some other way, so the hook fails closed here, where the mode enforces the
// checks. A call opencode would reject anyway loses nothing.
func denyUninspectableOpencodeInput(event *hook.Event) *hook.Decision {
	if !event.FromOpencode() || !hook.IsOpencodeTool(event.ToolName) || event.ToolInput != nil {
		return nil
	}
	if cfg, _ := config.LoadSettingsForDirectory(eventCWD(event)); cfg.EffectiveMode() == config.ModeOpen {
		return nil
	}
	return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
		"Blocked by lite-sandbox: the %s arguments could not be read, so their paths cannot be checked. "+
			"Pass each path as a plain string.",
		event.ToolName,
	))
}

// denyBuiltinBash blocks a built-in shell tool and points the model at the
// sandboxed MCP tool, which runs the same command through lite-sandbox's
// validation and path boundaries. The built-in shell tools have no sandbox.
func denyBuiltinBash(event *hook.Event) *hook.Decision {
	if !event.IsShellTool() {
		return nil
	}
	if event.FromGrok() {
		// Grok clips the reason to 256 characters, so it carries only the
		// redirect; the rules file explains the rest.
		return hook.NewDecision(hook.DecisionDeny, fmt.Sprintf(
			"Blocked by lite-sandbox: the built-in %s tool is disabled. %s",
			event.ToolName, grokRedirectHint,
		))
	}
	tool := "mcp__lite-sandbox__bash"
	if event.FromPi() {
		tool = piMCPToolPrefix + "bash"
	}
	instead := "Use the " + tool + " tool instead."
	switch {
	case event.FromOpencode():
		instead = "Use the `bash` tool of the `lite-sandbox` MCP server instead " +
			"(in Code Mode, call `tools[\"lite-sandbox\"].bash({ command })` from `execute`)."
	case event.FromPi() && event.ToolName == hook.PiToolPowerShell:
		instead = "Use the " + tool + " tool instead (it runs bash, not PowerShell)."
	case event.ToolName == hook.ToolMonitor:
		// The MCP tool's background shells take Monitor's place. A client
		// that runs MCP tasks reports when one finishes, so a watch written
		// to exit once its condition holds wakes the model when it matters,
		// where a stream that never ends would have to be polled.
		instead = "Run it in a background shell instead: call " + tool +
			" with run_in_background: true. Write the command to exit once the condition " +
			"you are waiting for is met and prints a line saying so (e.g. an until-loop " +
			"that checks and sleeps, then echoes), so its finishing is the signal, " +
			"rather than streaming output forever; " +
			"read the output file it names to follow progress."
	}
	// The model knows the command it just sent, so the reason does not
	// echo it back.
	reason := fmt.Sprintf("Blocked by lite-sandbox: the built-in %s tool is disabled.\n%s",
		event.ToolName, instead)
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
	// pi has no permission flow of its own — deferring there runs the command
	// unasked — so its extension is told to ask the user instead.
	if len(prompted) > 0 {
		return hook.NewDecision(hook.DecisionAsk, askReason(prompted))
	}
	if cfg, _ := config.LoadSettingsForDirectory(cwd); cfg.EffectiveMode() != config.ModeAllowlist {
		if event.FromPi() {
			return hook.NewDecision(hook.DecisionAsk, fmt.Sprintf(
				"lite-sandbox: in %s mode the command whitelist is advisory, and pi's bash runs this command "+
					"outside the sandbox: %s", cfg.EffectiveMode(), in.Describe()))
		}
		return nil
	}
	return hook.NewDecision(hook.DecisionAllow, "Validated by lite-sandbox: command passed the sandbox AST whitelist and path boundaries.")
}

// evaluatePathPolicy returns a deny decision when a filesystem tool targets a
// path outside the sandbox boundary, or nil to defer to Claude Code's normal
// flow. Read-family tools (Read/Glob/Grep) are checked against the readable
// paths; write-family tools (Edit/Write/NotebookEdit) against the writable
// paths. A Claude Code write that passes every check is allowed outright
// (fileWriteApproval).
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
	// pi's file tools.
	if pt, ok := event.ToolInput.(*hook.PiPathInput); ok {
		return evaluatePaths(event, pt.Describe(), pt.Paths(), pt.Write())
	}
	// opencode's file tools, patch, and media generation tools.
	switch in := event.ToolInput.(type) {
	case *hook.OpencodePathInput:
		return evaluatePaths(event, in.Describe(), in.Paths(), in.Write())
	case *hook.OpencodePatchInput:
		return evaluatePaths(event, in.Describe(), in.Paths(), true)
	case *hook.OpencodeMediaInput:
		if d := evaluatePaths(event, in.Describe(), in.ReadPaths(), false); d != nil {
			return d
		}
		return evaluatePaths(event, in.Describe(), opencodeMediaOutputs(eventCWD(event), in.WritePaths()), true)
	}

	path, write, governed := fsTarget(event)
	if !governed || path == "" {
		// Not a filesystem tool we govern, or no explicit path was supplied
		// (e.g. Glob/Grep without a path default to cwd, which is allowed).
		return nil
	}
	// The path Claude Code opens: it trims the path and expands a leading ~
	// before resolving it (see hook.ClaudeModelPath), so "~/.aws/credentials"
	// must be judged as the home directory's file, not <cwd>/~/.aws/....
	// The boundary checks below look at both spellings, the opened path
	// first so a denial names it; the .claude deferral looks only at what is
	// opened, so it can't be reached by a spelling that merely looks like a
	// .claude path. A path that trims to nothing opens the working directory.
	target := hook.ClaudeModelPath(path)
	if target == "" {
		target = "."
	}
	paths := []string{target}
	if path != target {
		paths = append(paths, path)
	}

	if isClaudeConfigTarget(target, eventCWD(event), write) {
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
	for _, p := range paths {
		if d := boundaryDenial(sb, cwd, what, p, write, event.FromGrok()); d != nil {
			return d
		}
	}
	if !write {
		return nil
	}
	for _, p := range paths {
		if d := agentConfigWriteDecision(event, cwd, what, p); d != nil {
			return d
		}
	}
	// fileWriteApproval gets the path as written: it approves only an
	// absolute path that Claude Code's clean-up leaves unchanged.
	return fileWriteApproval(event, sb, cwd, path)
}

// fileWriteApproval returns an allow decision for a Claude Code file-tool
// write (Edit/Write/NotebookEdit) that has passed every check above — inside
// the writable paths, not into .git, not into agent configuration — or nil to
// defer to Claude Code's normal permission flow.
//
// Without it, a write the hook has checked still prompts whenever Claude
// Code's own rules don't cover it: acceptEdits auto-approves only paths under
// the working directory and additionalDirectories, so a `paths allow
// <dir> --write` grant reached by sandboxed bash without a prompt still
// prompted for the agent's file tools. Allowing here keeps the two in step.
// It is meant to grant nothing sandboxed bash can't already do: the same
// writable boundary, and it defers wherever bash would be refused or Claude
// Code singles a path out:
//
//   - Only in allowlist and denylist mode, where the boundary is enforced. In
//     open mode a passing boundary check says nothing (it only audits).
//   - Only for Claude Code. Codex and Grok Build send no Edit/Write events
//     (and can't take an allow on a file tool), and pi's and opencode's file
//     tools are decided by lite-sandbox's extension and plugin for them.
//   - Not in plan mode, which is for reading: Claude Code ignores a hook's
//     allow on a write there anyway.
//   - Only for a path given absolute and without surrounding white space,
//     so that the path as written is the one Claude Code opens: it trims the
//     path and expands a leading ~ (hook.ClaudeModelPath). The checks above
//     judge both spellings, but an allow is kept to a path with only one.
//   - Not for a path sandboxed commands may not write or read
//     (hookWriteDenied): the config's deny lists, built-ins included, the
//     paths granted only to some commands, and the programs the host runs.
//   - Only under the project, a `paths` write grant, or the worktree parent:
//     not under the temp and scratchpad roots the boundary also admits. On
//     Linux the OS sandbox gives commands a private /tmp, so bash never
//     writes the host's, and /tmp/claude-<uid> is a name in a shared
//     directory that another user could have planted as a symlink.
//   - Only for a path of ASCII characters, as given and resolved. A
//     case-insensitive file system folds more than ASCII case (ſ for s),
//     and non-ASCII spellings can differ in Unicode normalization, so the
//     deny-list comparison below could miss the entry the file system
//     would open.
//   - Not through a symlink that doesn't resolve: ResolvePath stops at it, so
//     the checks would judge the link's own path rather than its target.
//   - Not for one of Claude Code's protected paths (claudeProtectedPath):
//     its docs don't say whether a hook's allow lifts the prompt it puts on
//     those, so the hook stays out of that decision. (The e2e suite's pinned
//     Claude Code keeps the prompt either way; this doesn't rely on that.)
func fileWriteApproval(event *hook.Event, sb *bash_sandboxed.Sandbox, cwd, path string) *hook.Decision {
	if event.FromGrok() || event.FromCodex() || event.FromPi() || event.FromOpencode() ||
		event.PermissionMode == hook.PermissionModePlan {
		return nil
	}
	if !filepath.IsAbs(path) || hook.ClaudeModelPath(path) != path {
		return nil
	}
	cfg, err := config.LoadForDirectory(cwd)
	if err != nil || cfg == nil {
		return nil
	}
	if mode := cfg.EffectiveMode(); mode != config.ModeAllowlist && mode != config.ModeDenylist {
		return nil
	}
	if !isASCII(path) {
		return nil
	}
	abs := filepath.Clean(path)
	if hasDanglingSymlink(abs) {
		return nil
	}
	resolved := bash_sandboxed.ResolvePath(abs, cwd)
	// The resolved path can spell what a symlink names, not what was asked.
	if !isASCII(resolved) {
		return nil
	}
	approvable := append([]string{cwd}, sb.ConfigWritePaths()...)
	if parent := sb.WorktreeParentPath(cwd); parent != "" {
		approvable = append(approvable, parent)
	}
	if !bash_sandboxed.IsUnderAllowedPaths(resolved, approvable) {
		return nil
	}
	if claudeProtectedPath(abs) || claudeProtectedPath(resolved) {
		return nil
	}
	if hookWriteDenied(cfg, cwd, abs, resolved) {
		return nil
	}
	return hook.NewDecision(hook.DecisionAllow, fmt.Sprintf(
		"Validated by lite-sandbox: %q is inside the sandbox's writable paths, the same ones sandboxed commands may write.",
		resolved))
}

// isASCII reports whether s holds only ASCII characters.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// hasDanglingSymlink reports whether a component of the absolute, clean path
// p that exists is a symlink whose target can't be resolved. Components after
// the first one that doesn't exist are not looked at: nothing is there yet.
func hasDanglingSymlink(p string) bool {
	cur := string(filepath.Separator)
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part == "" {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			return false
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if _, err := filepath.EvalSymlinks(cur); err != nil {
				return true
			}
		}
	}
	return false
}

// hookWriteDenied reports whether a file-tool write to abs (resolving to
// resolved) lands where sandboxed commands can't write, so the hook must not
// approve it: the config's effective write and read deny lists, the paths
// granted only to some commands (which the shared worker hides), the
// credential files the hidden home masks, the
// lite-sandbox binary, the directories on PATH up to lite-sandbox's and Go's
// install directory outside the project (config.HostProgramDirs, as
// bash_sandboxed's hostProgramDenies), and buildx's builder state. Paths are
// compared ignoring ASCII case, so a case-insensitive file system (macOS)
// can't spell its way past an entry (fileWriteApproval only gets this far
// with an ASCII path).
func hookWriteDenied(cfg *config.Config, cwd, abs, resolved string) bool {
	denied := append(cfg.EffectiveDeniedWritePaths(), cfg.EffectiveDeniedReadPaths()...)
	for _, d := range append(cfg.ScopedDeniedReadEntries(), cfg.HiddenHomeDeniedReadEntries()...) {
		denied = append(denied, d.Path)
	}
	denied = append(denied, config.ServerExecutable()...)
	for _, dir := range cfg.HostProgramDirs(os.Getenv("PATH")) {
		if !bash_sandboxed.IsUnderAllowedPaths(dir, []string{cwd}) {
			denied = append(denied, dir)
		}
	}
	if dir := config.BuildxConfigDir(); filepath.IsAbs(dir) {
		denied = append(denied, filepath.Join(dir, "instances"), filepath.Join(dir, "defaults"), filepath.Join(dir, "current"))
	}
	for _, d := range denied {
		// An entry that doesn't exist yet is resolved through its longest
		// existing prefix, so a symlinked $HOME or ~/.config still matches.
		forms := []string{filepath.Clean(d), bash_sandboxed.ResolvePath(filepath.Clean(d), string(filepath.Separator))}
		for _, f := range forms {
			lf := strings.ToLower(f)
			for _, p := range []string{abs, resolved} {
				lp := strings.ToLower(p)
				if lp == lf || strings.HasPrefix(lp, strings.TrimSuffix(lf, string(filepath.Separator))+string(filepath.Separator)) {
					return true
				}
			}
		}
	}
	return false
}

// claudeProtectedDirs and claudeProtectedFiles mirror the protected paths
// Claude Code prompts before writing in default and acceptEdits mode
// (https://code.claude.com/docs/en/permission-modes.md#protected-paths). The
// hook defers on them rather than allowing (see fileWriteApproval). Matching
// is by path component and case-insensitive, so it errs toward deferring.
var (
	claudeProtectedDirs = []string{
		".git", ".vscode", ".idea", ".husky", ".cargo", ".devcontainer", ".yarn", ".mvn", ".claude",
	}
	claudeProtectedFiles = []string{
		".gitconfig", ".gitmodules",
		".bashrc", ".bash_profile", ".bash_login", ".bash_aliases", ".bash_logout",
		".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".profile", ".envrc",
		".npmrc", ".yarnrc", ".yarnrc.yml", ".pnp.cjs", ".pnp.js", ".pnp.data.json", ".pnp.loader.mjs", ".pnpmfile.cjs",
		"bunfig.toml", ".bunfig.toml", ".bazelrc", ".bazelversion", ".bazeliskrc",
		".pre-commit-config.yaml", "gradle-wrapper.properties", "maven-wrapper.properties",
		".devcontainer.json", ".ripgreprc", "pyrightconfig.json",
		".mcp.json", ".claude.json", "remote-settings.json",
	}
)

// claudeProtectedPath reports whether path (absolute and clean) is one of
// Claude Code's protected paths, or lies inside a protected directory.
func claudeProtectedPath(path string) bool {
	parts := strings.Split(path, string(filepath.Separator))
	for i, p := range parts {
		// Claude Code's own worktrees are exempt, as in IsClaudeConfigPath.
		if strings.EqualFold(p, ".claude") && i+1 < len(parts) && strings.EqualFold(parts[i+1], "worktrees") {
			continue
		}
		for _, d := range claudeProtectedDirs {
			if strings.EqualFold(p, d) {
				return true
			}
		}
		// ~/.config/git (git's XDG config).
		if strings.EqualFold(p, ".config") && i+1 < len(parts) && strings.EqualFold(parts[i+1], "git") {
			return true
		}
	}
	base := strings.ToLower(filepath.Base(path))
	if slices.Contains(claudeProtectedFiles, base) {
		return true
	}
	// lefthook's config in all its spellings (lefthook.yml, .lefthook.yaml,
	// lefthook-local.yml, ...).
	if l := strings.TrimPrefix(base, "."); strings.HasPrefix(l, "lefthook") &&
		(strings.HasSuffix(l, ".yml") || strings.HasSuffix(l, ".yaml")) {
		return true
	}
	return false
}

// agentConfigWriteDecision returns the decision for a file tool's write to
// path when it lands in a coding agent's configuration
// (bash_sandboxed.AgentConfigWrite), or nil when it does not. Those paths are
// read-only to sandboxed commands, since the agents run or obey them outside
// the sandbox: .pi's extensions, .claude's hooks, opencode.json's
// permissions and .opencode's plugins, .grok's hooks, Crush's crushrc. The
// agents' file tools are held to the same rule. Codex and Grok Build can't put
// an "ask" to the user, and pi doesn't prompt before a tool call on its own,
// so their writes are denied, as are opencode's (whose `run --auto` approves
// every prompt unattended); Claude Code's are asked about, so the user
// decides, as Claude Code does itself for .claude (see isClaudeConfigTarget,
// which runs first) and .mcp.json. In open mode the finding is only audited.
func agentConfigWriteDecision(event *hook.Event, cwd, what, path string) *hook.Decision {
	match, resolved := bash_sandboxed.AgentConfigWrite(path, cwd)
	if match == "" {
		return nil
	}
	reason := fmt.Sprintf(
		"Blocked by lite-sandbox: %s\n"+
			"%q resolves to %q, which is %s: agent configuration, "+
			"which is read-only in the sandbox. Ask the user to make this change.",
		what, path, resolved, match,
	)
	if !auditHookFinding(cwd, what, resolved, reason) {
		return nil
	}
	if event.CanAsk() && !event.FromPi() && !event.FromOpencode() {
		return hook.NewDecision(hook.DecisionAsk, fmt.Sprintf(
			"lite-sandbox: %s writes %q, which is %s: a coding agent's configuration, which runs or "+
				"is obeyed outside the sandbox and is read-only to sandboxed commands.",
			what, resolved, match))
	}
	if event.FromGrok() {
		reason = fmt.Sprintf("Blocked by lite-sandbox: writing %s (agent configuration) is not allowed; ask the user to make this change. Path: %s", match, resolved)
	}
	return hook.NewDecision(hook.DecisionDeny, reason)
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
		if write {
			if d := agentConfigWriteDecision(event, cwd, what, p); d != nil {
				return d
			}
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
