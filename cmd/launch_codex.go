package cmd

import (
	"os"
	"path/filepath"

	"github.com/pelletier/go-toml/v2"
)

// codexLaunchDirective is the usage directive `launch codex` passes as
// developer_instructions. Unlike the installed codexDirective, it can say the
// built-in shell is gone: launch removes it from the session.
const codexLaunchDirective = "ALWAYS use the `bash` tool from the `lite-sandbox` MCP server for running shell " +
	"commands. The built-in shell tool is disabled for this session. The sandboxed tool runs commands " +
	"through lite-sandbox's AST validation and filesystem path boundaries."

// codexLaunchSpec builds Codex's arguments for a sandboxed run. What `install
// codex` writes to config.toml and AGENTS.md is passed as -c overrides, which
// Codex layers over the user's config.toml for this invocation only:
//
//   - the [mcp_servers.lite-sandbox] table, keys as install writes them;
//   - developer_instructions carrying the usage directive (after the user's
//     own developer_instructions, which the override would otherwise replace);
//     their AGENTS.md files still load as usual;
//   - --disable shell_tool, which removes Codex's built-in shell (exec_command)
//     from the session. install has to block it with a hook instead, but
//     removing it is stronger and does not depend on the hook running;
//   - the PreToolUse hook, as a -c hooks.PreToolUse table, when the flags call
//     for one (--with-tool-hook: confine apply_patch and the file tools;
//     --bash-ast-hook-mode: AST-check the shell, which then stays enabled).
//     Codex only runs hooks the user has trusted in its /hooks screen, and
//     that trust is recorded in config.toml, so a hook launch passes would
//     silently never run. --dangerously-bypass-hook-trust is Codex's only
//     per-run way past that; it applies to every enabled hook in the session.
//
// Codex's root options carry over to its subcommands, so they go first and
// the user's arguments (`exec ...`, a prompt) follow.
func codexLaunchSpec(binPath string, agentArgs []string) (launchSpec, error) {
	validateBash := launchBashASTHookMode
	governFS := launchWithToolHook
	configMCP := !validateBash

	var spec launchSpec
	override := func(key, tomlValue string) {
		spec.args = append(spec.args, "-c", key+"="+tomlValue)
	}
	if configMCP {
		prefix := "mcp_servers." + codexServerName + "."
		override(prefix+"command", tomlString(binPath))
		override(prefix+"args", `["serve-mcp"]`)
		override(prefix+"default_tools_approval_mode", `"approve"`)
		if launchAlwaysLoad {
			override(prefix+"omit_tools_from", `["deferred"]`)
		}
		directive := codexLaunchDirective
		if own := codexUserDeveloperInstructions(); own != "" {
			directive = own + "\n\n" + directive
		}
		override("developer_instructions", tomlString(directive))
		spec.args = append(spec.args, "--disable", "shell_tool")
	}

	if validateBash || governFS {
		command := binPath + " hook"
		if validateBash {
			command += " --validate-bash"
		}
		matcher := bashValidateMatcher
		if governFS {
			matcher = hookToolMatcher
		}
		override("hooks.PreToolUse",
			`[{matcher = `+tomlString(matcher)+`, hooks = [{type = "command", command = `+tomlString(command)+`}]}]`)
		spec.args = append(spec.args, "--dangerously-bypass-hook-trust")
		spec.notes = append(spec.notes,
			"Codex runs only hooks trusted in /hooks, so this session passes --dangerously-bypass-hook-trust for the sandbox's hook;"+
				" your own enabled hooks run unreviewed too (--with-tool-hook=false avoids this)")
	}
	spec.args = append(spec.args, agentArgs...)
	return spec, nil
}

// codexUserDeveloperInstructions returns developer_instructions from the
// user's config.toml, or "" when it has none (or can't be read; Codex reports
// a broken config itself).
func codexUserDeveloperInstructions() string {
	dir, err := codexHome()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		return ""
	}
	var cfg struct {
		DeveloperInstructions string `toml:"developer_instructions"`
	}
	if toml.Unmarshal(data, &cfg) != nil {
		return ""
	}
	return cfg.DeveloperInstructions
}
