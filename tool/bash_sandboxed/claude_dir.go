package bash_sandboxed

import (
	"fmt"
	"path/filepath"
	"strings"
)

// IsClaudeConfigPath reports whether the absolute path is inside (or is) a
// .claude directory: the agent's own configuration — settings with hooks and
// permission rules, skills, agents, commands — which Claude Code runs or
// obeys outside the sandbox, so sandboxed commands may read it but not write
// it. Like Claude Code's own protected-path list, .claude/worktrees (where
// Claude Code puts its git worktrees) is not part of it; a .claude inside
// such a worktree is. The name is matched case-insensitively, since on a
// case-insensitive filesystem (macOS by default) .Claude is the same
// directory.
func IsClaudeConfigPath(path string) bool {
	parts := strings.Split(path, string(filepath.Separator))
	for i, p := range parts {
		if strings.EqualFold(p, ".claude") && (i+1 >= len(parts) || !strings.EqualFold(parts[i+1], "worktrees")) {
			return true
		}
	}
	return false
}

// IsPiConfigPath reports whether the absolute path is inside (or is) a .pi
// directory: pi's project configuration — settings, extensions, MCP servers,
// skills, prompts and system-prompt files — which pi loads into its own
// process, outside the sandbox, once the user has trusted the project. Like
// .claude, sandboxed commands may read it but not write it, so a command
// cannot plant an extension that runs the next time pi starts there. The
// name is matched case-insensitively, as for .claude.
func IsPiConfigPath(path string) bool {
	for _, p := range strings.Split(path, string(filepath.Separator)) {
		if strings.EqualFold(p, ".pi") {
			return true
		}
	}
	return false
}

// AgentConfigDir names the read-only agent configuration directory the path
// is inside (".claude" or ".pi"; see IsClaudeConfigPath and IsPiConfigPath),
// or "" when it is in neither.
func AgentConfigDir(path string) string {
	switch {
	case IsClaudeConfigPath(path):
		return ".claude"
	case IsPiConfigPath(path):
		return ".pi"
	}
	return ""
}

// checkAgentConfigDirWrite rejects a write to a path inside a .claude or .pi
// directory (see AgentConfigDir). Both the path as written and its symlink
// resolution are checked: a .claude that is itself a symlink resolves to a
// target without the name, and a link to .claude resolves into it.
func checkAgentConfigDirWrite(orig, path, workDir string) error {
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(workDir, abs)
	}
	abs = filepath.Clean(abs)
	resolved := ResolvePath(abs, workDir)
	dir := AgentConfigDir(abs)
	if dir == "" {
		dir = AgentConfigDir(resolved)
	}
	if dir != "" {
		return tagRule(rulePathBoundary, resolved, fmt.Errorf("path %q is inside a %s directory, which is read-only in the sandbox; ask the user to make this change", orig, dir))
	}
	return nil
}

// validateAgentConfigDirWrites rejects a command that writes inside a .claude
// directory. Only the arguments the command writes are checked (see
// writeTargets), so reading .claude stays possible — `sed -n 1p
// .claude/settings.json`, `cp .claude/settings.json backup.json` — while
// `sort -o .claude/settings.json`, which the read/write split of
// writeCommands does not see as a write, is refused. A target is resolved
// against workDir, which at runtime is the shell's current directory, so a
// bare name written from inside .claude (cd .claude && touch x) is caught.
// Empty targets are non-literal words in the static pass, re-checked after
// expansion.
func validateAgentConfigDirWrites(cmdName string, args []string, workDir string, skip map[int]bool) error {
	for _, t := range writeTargets(cmdName, args, skip) {
		if t == "" || t == "-" {
			continue
		}
		if err := checkAgentConfigDirWrite(t, t, workDir); err != nil {
			return err
		}
	}
	return nil
}

// writeTargets returns the arguments of a command that name a file or
// directory it creates, modifies, or removes (its commandSpec's
// writeTargets). skip holds the indices that are not paths (sed's script).
// What a command writes without naming it (git checkout switching branches,
// tar extracting entries) is not refused: the OS sandbox does not mask
// .claude either, since git failing on a tracked .claude file midway
// through a checkout or rebase leaves the tree half switched.
func writeTargets(cmdName string, args []string, skip map[int]bool) []string {
	if f := lookupCommand(cmdName).writeTargets; f != nil {
		return f(args, skip)
	}
	return nil
}
