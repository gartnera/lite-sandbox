package cmd

import "encoding/json"

// claudeOptions are the composable knobs that decide how Claude Code is
// configured to use the sandbox. `install claude` writes the result into
// Claude Code's config files; `launch claude` passes the same result as
// command-line flags for a single run. Both go through claudePlan so the two
// entry points can never drift apart.
type claudeOptions struct {
	// withToolHook governs the built-in tools with the PreToolUse hook instead
	// of the blunt Bash deny: Bash is redirected to the MCP tool and
	// Read/Write/Edit are confined to the sandbox's paths.
	withToolHook bool
	// bashASTHookMode validates the built-in Bash tool's AST in the hook and
	// allows it when it passes, instead of configuring the MCP server.
	bashASTHookMode bool
	// alwaysLoad exempts the sandbox MCP tools from Tool Search deferral.
	alwaysLoad bool
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
	// validateBash and governFS are the resolved hook behaviors, kept for the
	// install command's reporting.
	validateBash bool
	governFS     bool
	// hookCommand and hookMatcher are the PreToolUse hook to register. An empty
	// command means no hook.
	hookCommand string
	hookMatcher string
}

// plan resolves the options for the lite-sandbox binary at binPath.
func (o claudeOptions) plan(binPath string) claudePlan {
	p := claudePlan{
		validateBash: o.bashASTHookMode,
		governFS:     o.withToolHook,
		configMCP:    !o.bashASTHookMode,
	}
	wantHook := o.withToolHook || o.bashASTHookMode
	p.denyBash = !wantHook
	p.alwaysLoad = o.alwaysLoad && p.configMCP
	p.hookCommand, p.hookMatcher = claudeHookPlan(binPath, wantHook, p.validateBash, p.governFS, p.configMCP)
	return p
}

// claudeHookPlan computes the PreToolUse hook command and matcher for the
// chosen mode. An empty command means no hook is registered. configMCP
// additionally extends the matcher to the sandbox's own MCP tools so the hook
// can pre-approve them in subagents and skills.
func claudeHookPlan(binPath string, wantHook, validateBash, governFS, configMCP bool) (command, matcher string) {
	if wantHook {
		if validateBash {
			command = binPath + " hook --validate-bash"
		} else {
			command = binPath + " hook"
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
			command = binPath + " hook"
		}
		if matcher == "" {
			matcher = mcpToolMatcher
		} else {
			matcher += "|" + mcpToolMatcher
		}
	}
	return command, matcher
}

// claudeDirective is the usage directive that points Claude Code at the
// sandbox tool. `install` appends it to CLAUDE.md; `launch` passes it as
// --append-system-prompt.
const claudeDirective = `ALWAYS use the mcp__lite-sandbox__bash tool for running shell commands. The built-in Bash tool is denied and will not run. The sandboxed tool is pre-approved and requires no permission prompts.`

// mcpServerEntry is the lite-sandbox MCP server entry: `<binPath> serve-mcp`.
// It is written into Claude Code's user config by `install` and passed to
// --mcp-config by `launch`.
func mcpServerEntry(binPath string, alwaysLoad bool) mcpServerConfig {
	return mcpServerConfig{
		Command:    binPath,
		Args:       []string{"serve-mcp"},
		AlwaysLoad: alwaysLoad,
	}
}

// claudePermissions is the permission set the plan calls for: the sandbox
// tools auto-allowed when the MCP server is configured, the built-in Bash tool
// denied when no hook governs it.
func (p claudePlan) claudePermissions() permissionsConfig {
	var perms permissionsConfig
	if p.configMCP {
		perms.Allow = append(perms.Allow, mcpToolPermissions...)
	}
	if p.denyBash {
		perms.Deny = append(perms.Deny, builtinBashPermission)
	}
	return perms
}

// preToolUseHooks is the plan's PreToolUse hook as a settings.json "hooks"
// value, or nil when the plan registers no hook.
func (p claudePlan) preToolUseHooks() map[string]any {
	if p.hookCommand == "" {
		return nil
	}
	return map[string]any{
		"PreToolUse": []any{
			map[string]any{
				"matcher": p.hookMatcher,
				"hooks":   []any{map[string]any{"type": "command", "command": p.hookCommand}},
			},
		},
	}
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
		Hooks:       p.preToolUseHooks(),
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
