package bash_sandboxed

import (
	"fmt"
	"path/filepath"
	"strings"
)

// agentConfigDirs are the directories that hold a coding agent's own
// configuration — settings, permission rules, hooks, plugins, MCP servers,
// agent definitions, commands, skills — which the agent loads and runs, or
// obeys, outside the sandbox. A directory of one of these names, at any
// depth, is read-only to sandboxed commands, since the agents look for them
// in the working directory, its ancestors, and the home directory:
//
//   - .claude: Claude Code's settings, hooks, skills, agents, commands.
//   - .codex: Codex's project config.toml and hooks.json.
//   - .agents: the cross-agent skills directory (Codex, opencode v2, Crush).
//   - .opencode: opencode's project opencode.json(c), agents, modes,
//     commands and plugins (unsandboxed JavaScript).
//   - .crush: Crush's data directory, with its project commands and skills.
//   - .grok: Grok Build's project config.toml (MCP servers, plugins,
//     permission rules), hooks, rules, skills.
//   - .pi: pi's settings, extensions, MCP servers, skills, prompts and
//     system-prompt files, which pi loads into its own process.
//
// The value says whether the directory's worktrees subdirectory is exempt:
// Claude Code puts its git worktrees in .claude/worktrees and the Codex app in
// $CODEX_HOME/worktrees, so a session working in one must be able to write
// it. A config directory inside such a worktree is protected again.
var agentConfigDirs = map[string]bool{
	".claude":   true,
	".codex":    true,
	".agents":   false,
	".opencode": false,
	".crush":    false,
	".grok":     false,
	".pi":       false,
}

// agentConfigFiles are the agents' project config files that sit outside a
// config directory, found by walking up from the working directory:
//
//   - .mcp.json: Claude Code's project MCP servers.
//   - opencode.json(c): opencode's project config (permission rules, plugins,
//     MCP servers); tui.json(c) is its v1 TUI config, which loads plugins.
//   - crushrc, .crushrc: Crush's project config, a Bash script it executes;
//     crush.json, .crush.json: its JSON form.
var agentConfigFiles = map[string]bool{
	".mcp.json":      true,
	"opencode.json":  true,
	"opencode.jsonc": true,
	"tui.json":       true,
	"tui.jsonc":      true,
	"crushrc":        true,
	".crushrc":       true,
	"crush.json":     true,
	".crush.json":    true,
}

// AgentConfigMatch returns what makes the absolute path agent configuration
// (see agentConfigDirs and agentConfigFiles), phrased for an error message
// ("inside a .pi directory", "an opencode.json file"), or "" when it is not.
// Names are matched case-insensitively, since on a case-insensitive
// filesystem (macOS by default) .Claude is the same directory.
func AgentConfigMatch(path string) string {
	parts := strings.Split(path, string(filepath.Separator))
	for i, p := range parts {
		name := strings.ToLower(p)
		exemptWorktrees, ok := agentConfigDirs[name]
		if !ok {
			continue
		}
		if exemptWorktrees && i+1 < len(parts) && strings.EqualFold(parts[i+1], "worktrees") {
			continue
		}
		return "inside a " + name + " directory"
	}
	if base := strings.ToLower(parts[len(parts)-1]); agentConfigFiles[base] {
		article := "a "
		if strings.ContainsRune("aeiou", rune(base[0])) {
			article = "an "
		}
		return article + base + " file"
	}
	return ""
}

// IsAgentConfigPath reports whether the absolute path is a coding agent's
// own configuration (see agentConfigDirs and agentConfigFiles): something an
// agent loads and runs or obeys outside the sandbox, so sandboxed commands
// may read it but not write it. Otherwise a command could plant a hook or
// plugin, or re-enable an agent's built-in shell, that runs unsandboxed the
// next time the agent starts or reloads its config.
func IsAgentConfigPath(path string) bool {
	return AgentConfigMatch(path) != ""
}

// checkAgentConfigWrite rejects a write to agent configuration (see
// IsAgentConfigPath). Both the path as written and its symlink resolution are
// checked: a .claude that is itself a symlink resolves to a target without
// the name, and a link to .claude (or to opencode.json) resolves into it.
func checkAgentConfigWrite(orig, path, workDir string) error {
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(workDir, abs)
	}
	abs = filepath.Clean(abs)
	resolved := ResolvePath(abs, workDir)
	what := AgentConfigMatch(abs)
	if what == "" {
		what = AgentConfigMatch(resolved)
	}
	if what != "" {
		return tagRule(rulePathBoundary, resolved, fmt.Errorf("path %q is %s, a coding agent's configuration, which is read-only in the sandbox; ask the user to make this change", orig, what))
	}
	return nil
}

// validateAgentConfigWrites rejects a command that writes agent
// configuration. Only the arguments the command writes are checked (see
// writeTargets), so reading it stays possible — `sed -n 1p
// .claude/settings.json`, `cp opencode.json backup.json` — while
// `sort -o .claude/settings.json`, which the read/write split of
// writeCommands does not see as a write, is refused. A target is resolved
// against workDir, which at runtime is the shell's current directory, so a
// bare name written from inside .claude (cd .claude && touch x) is caught.
// Empty targets are non-literal words in the static pass, re-checked after
// expansion.
func validateAgentConfigWrites(cmdName string, args []string, workDir string, skip map[int]bool) error {
	for _, t := range writeTargets(cmdName, args, skip) {
		if t == "" || t == "-" {
			continue
		}
		if err := checkAgentConfigWrite(t, t, workDir); err != nil {
			return err
		}
	}
	return nil
}

// writeTargets returns the arguments of a command that name a file or
// directory it creates, modifies, or removes (its commandSpec's
// writeTargets). skip holds the indices that are not paths (sed's script).
// What a command writes without naming it (git checkout switching branches,
// tar extracting entries) is not refused: the OS sandbox does not mask agent
// configuration either, since git failing on a tracked .claude file midway
// through a checkout or rebase leaves the tree half switched.
func writeTargets(cmdName string, args []string, skip map[int]bool) []string {
	if f := lookupCommand(cmdName).writeTargets; f != nil {
		return f(args, skip)
	}
	return nil
}
