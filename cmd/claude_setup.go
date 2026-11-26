package cmd

import (
	"encoding/json"
	"strings"

	"github.com/gartnera/lite-sandbox/internal/hook"
	"mvdan.cc/sh/v3/syntax"
)

// claudeOptions are the composable knobs that decide how Claude Code is
// configured to use the sandbox. `install claude` writes the result into
// Claude Code's config files; `launch claude` passes the same result as
// command-line flags for a single run. Both go through claudePlan so the two
// entry points can never drift apart.
type claudeOptions struct {
	// withToolHook confines the built-in filesystem tools (Read/Write/Edit/...)
	// to the sandbox's readable/writable paths with the PreToolUse hook.
	withToolHook bool
	// redirectBash lets the hook block the built-in Bash tool with a message
	// redirecting to the MCP tool, instead of denying it with a permission rule.
	// This is what `install --with-tool-hook` does: the deny would take
	// precedence over the hook and suppress the redirect. `launch` leaves it
	// off, so Bash stays denied outright (and is not even offered to the model)
	// while the hook still governs the filesystem tools.
	redirectBash bool
	// bashASTHookMode validates the built-in Bash tool's AST in the hook and
	// allows it when it passes, instead of configuring the MCP server.
	bashASTHookMode bool
	// alwaysLoad exempts the sandbox MCP tools from Tool Search deferral.
	alwaysLoad bool
	// permissionMode is Claude Code's permissions.defaultMode for the session
	// ("acceptEdits", ...). Empty leaves Claude Code's own default in place.
	// Only `launch` sets it: it configures one session, whereas `install`
	// writes settings that apply to every project the user opens.
	permissionMode string
}

// claudePlan is what a set of claudeOptions resolves to: the decisions both
// entry points act on, already reconciled with each other.
type claudePlan struct {
	// configMCP configures the MCP server (and with it the tool auto-allow and
	// the usage directive). It is off in --bash-ast-hook-mode, where Bash is
	// validated in place and nothing redirects to the MCP tool.
	configMCP bool
	// denyBash hard-denies the built-in Bash tool. Only in the default mode: a
	// permission deny takes precedence over a hook decision, so it would
	// suppress a hook that governs Bash.
	denyBash bool
	// alwaysLoad is the requested alwaysLoad, forced off when there is no MCP
	// server to apply it to.
	alwaysLoad bool
	// permissionMode is Claude Code's permissions.defaultMode, or "" to leave it
	// alone.
	permissionMode string
	// validateBash and governFS are the resolved hook behaviors, kept for the
	// install command's reporting.
	validateBash bool
	governFS     bool
	// hookCommand and hookMatcher are the PreToolUse hook to register. An empty
	// command means no hook.
	hookCommand string
	hookMatcher string
	// hookBlockOnFailure registers the PreToolUse hook with Claude Code's
	// "onFailure": "block", so a hook that can't start, times out, or exits
	// with an unexpected code blocks the call instead of letting it through.
	// It is set when the hook governs built-in tools (--with-tool-hook,
	// --bash-ast-hook-mode), where it is what stands between the model and an
	// unconfined Bash, Read or Write; a hook that only pre-approves the
	// sandbox's own MCP tools fails open, falling back to permissions.allow.
	hookBlockOnFailure bool
	// permissionHookCommand is the PermissionRequest hook to register for the
	// sandbox's MCP tools (matcher mcpToolMatcher), or "" for none. It
	// pre-approves them in plan mode, where Claude Code ignores both the
	// PreToolUse allow and permissions.allow (see evaluatePermissionRequest).
	permissionHookCommand string
}

// plan resolves the options for the lite-sandbox binary at binPath.
func (o claudeOptions) plan(binPath string) claudePlan {
	p := claudePlan{
		validateBash:   o.bashASTHookMode,
		governFS:       o.withToolHook,
		configMCP:      !o.bashASTHookMode,
		permissionMode: o.permissionMode,
	}
	wantHook := o.withToolHook || o.bashASTHookMode
	// Deny the built-in Bash tool unless something needs it to reach the hook:
	// the redirect (whose message a deny would suppress) or --bash-ast-hook-mode
	// (where the hook allows commands that pass validation). Denying it and
	// governing the filesystem tools with the hook is not a conflict — the two
	// branches of the hook are independent — so it is the strongest combination
	// and the one `launch` uses by default.
	p.denyBash = !(o.redirectBash || o.bashASTHookMode)
	p.alwaysLoad = o.alwaysLoad && p.configMCP
	p.hookCommand, p.hookMatcher = claudeHookPlan(binPath, wantHook, p.validateBash, p.governFS, p.configMCP)
	p.hookBlockOnFailure = wantHook
	if p.configMCP {
		// The same command as the PreToolUse hook, so both read the call with
		// the same flags (--config-requests in particular).
		p.permissionHookCommand = p.hookCommand
	}
	return p
}

// claudeHookPlan computes the PreToolUse hook command and matcher for the
// chosen mode. An empty command means no hook is registered. configMCP
// additionally extends the matcher to the sandbox's own MCP tools so the hook
// can pre-approve them in subagents and skills.
func claudeHookPlan(binPath string, wantHook, validateBash, governFS, configMCP bool) (command, matcher string) {
	// Claude Code runs a command hook through a shell, so the binary path is
	// quoted: unquoted, a path with a space splits into two words and the hook
	// never starts (blocking every tool it matches, or confining nothing on a
	// Claude Code without "onFailure").
	exe := shellQuotePath(binPath)
	if wantHook {
		if validateBash {
			command = exe + " hook --validate-bash"
		} else {
			command = exe + " hook"
		}
		// On its own, --bash-ast-hook-mode governs only Bash; with --with-tool-hook
		// it also confines the filesystem tools, so it matches all of them.
		matcher = hookToolMatcher
		if !governFS {
			matcher = bashValidateMatcher
		}
	}
	if configMCP {
		if command == "" {
			command = exe + " hook"
		}
		// The MCP server runs config requests (mcpServerEntry), which only the
		// hook can put before the user.
		command += " --config-requests"
		if matcher == "" {
			matcher = mcpToolMatcher
		} else {
			matcher += "|" + mcpToolMatcher
		}
	}
	return command, matcher
}

// shellQuotePath quotes a path as one word for a POSIX shell. A path that
// needs no quoting is returned unchanged, so the hook command of an ordinary
// install stays exactly as it was. syntax.Quote refuses a path it can only
// write with bash's $'...' (a control character or invalid UTF-8); single
// quotes keep every byte literal in any POSIX shell, so those fall back to
// them, with each single quote closed, escaped and reopened.
func shellQuotePath(path string) string {
	if q, err := syntax.Quote(path, syntax.LangPOSIX); err == nil {
		return q
	}
	return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'"
}

// claudeDirective is the usage directive that points Claude Code at the
// sandbox tool. `install` appends it to CLAUDE.md; `launch` passes it as
// --append-system-prompt.
const claudeDirective = `ALWAYS use the mcp__lite-sandbox__bash tool for running shell commands. The built-in Bash tool is denied and will not run. The sandboxed tool is pre-approved and requires no permission prompts.`

// claudeConfigRequestDirective tells Claude Code it can make config requests.
// It is a directive of its own, rather than part of claudeDirective, so an
// existing install's CLAUDE.md gains it without the first one being
// duplicated.
const claudeConfigRequestDirective = `If lite-sandbox blocks a command you need and its error names a ` + "`lite-sandbox config ...`" + ` fix, run that command with mcp__lite-sandbox__bash, as a command of its own: the user is asked to approve the change.`

// claudeDirectives are the usage directives, in the order they are added.
var claudeDirectives = []string{claudeDirective, claudeConfigRequestDirective}

// mcpServerEntry is the lite-sandbox MCP server entry: `<binPath> serve-mcp`.
// It is written into Claude Code's user config by `install` and passed to
// --mcp-config by `launch`.
func mcpServerEntry(binPath string, alwaysLoad bool) mcpServerConfig {
	return mcpServerConfig{
		Command: binPath,
		// Config requests are safe to run because the plan registers the hook
		// with --config-requests alongside every MCP server (claudeHookPlan).
		Args:       []string{"serve-mcp", "--config-requests"},
		AlwaysLoad: alwaysLoad,
	}
}

// claudePermissions is the permission set the plan calls for: the sandbox
// tools auto-allowed when the MCP server is configured, the built-in Bash tool
// denied when no hook governs it.
func (p claudePlan) claudePermissions() permissionsConfig {
	perms := permissionsConfig{DefaultMode: p.permissionMode}
	if p.configMCP {
		perms.Allow = append(perms.Allow, mcpToolPermissions...)
	}
	if p.denyBash {
		perms.Deny = append(perms.Deny, builtinBashPermission)
	}
	return perms
}

// settingsHooks is the plan's hooks (PreToolUse, and PermissionRequest for
// the MCP tools) as a settings.json "hooks" value, or nil when the plan
// registers none.
func (p claudePlan) settingsHooks() map[string]any {
	hooks := map[string]any{}
	group := func(matcher string, entry map[string]any) []any {
		return []any{map[string]any{
			"matcher": matcher,
			"hooks":   []any{entry},
		}}
	}
	if p.hookCommand != "" {
		hooks[string(hook.EventPreToolUse)] = group(p.hookMatcher, claudeHookEntry(p.hookCommand, p.hookBlockOnFailure))
	}
	if p.permissionHookCommand != "" {
		hooks[string(hook.EventPermissionRequest)] = group(mcpToolMatcher, claudeHookEntry(p.permissionHookCommand, false))
	}
	if len(hooks) == 0 {
		return nil
	}
	return hooks
}

// claudeHookEntry is one settings.json command hook entry running command.
// blockOnFailure adds "onFailure": "block" (Claude Code 2.1.295 and later),
// so a hook that can't run blocks the call rather than letting it through.
func claudeHookEntry(command string, blockOnFailure bool) map[string]any {
	entry := map[string]any{"type": "command", "command": command}
	if blockOnFailure {
		entry["onFailure"] = "block"
	}
	return entry
}

// claudeSettings is the subset of Claude Code's settings.json that lite-sandbox
// produces. `launch` marshals it for --settings; `install` merges the same
// values into the user's settings.json field by field.
type claudeSettings struct {
	Permissions permissionsConfig `json:"permissions"`
	Hooks       map[string]any    `json:"hooks,omitempty"`
}

// settingsJSON renders the plan as a settings JSON document.
func (p claudePlan) settingsJSON() (string, error) {
	data, err := json.Marshal(claudeSettings{
		Permissions: p.claudePermissions(),
		Hooks:       p.settingsHooks(),
	})
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// mcpConfigJSON renders the plan's MCP server as an --mcp-config document, or
// "" when the plan configures no MCP server.
func (p claudePlan) mcpConfigJSON(binPath string) (string, error) {
	if !p.configMCP {
		return "", nil
	}
	data, err := json.Marshal(map[string]any{
		"mcpServers": map[string]mcpServerConfig{"lite-sandbox": mcpServerEntry(binPath, p.alwaysLoad)},
	})
	if err != nil {
		return "", err
	}
	return string(data), nil
}
