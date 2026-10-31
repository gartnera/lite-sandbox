package bash_sandboxed

import (
	"path/filepath"
	"strings"
)

// IsClaudeConfigPath reports whether the absolute path is inside (or is) a
// .claude directory: Claude Code's own configuration, one of the agent
// configuration paths sandboxed commands may only read (see
// IsAgentConfigPath). The PreToolUse hook uses it to leave Claude Code's file
// tools on .claude to Claude Code's own protected-path prompt. Like Claude
// Code's protected-path list, .claude/worktrees (where Claude Code puts its
// git worktrees) is not part of it; a .claude inside such a worktree is. The
// name is matched case-insensitively, since on a case-insensitive filesystem
// (macOS by default) .Claude is the same directory.
func IsClaudeConfigPath(path string) bool {
	parts := strings.Split(path, string(filepath.Separator))
	for i, p := range parts {
		if strings.EqualFold(p, ".claude") && (i+1 >= len(parts) || !strings.EqualFold(parts[i+1], "worktrees")) {
			return true
		}
	}
	return false
}
