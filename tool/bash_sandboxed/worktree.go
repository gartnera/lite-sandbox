package bash_sandboxed

import (
	"github.com/gartnera/lite-sandbox/internal/gitworktree"
)

// WorktreeParentPath returns the absolute main-worktree path to grant access
// to when workDir is inside a linked git worktree and the config flag
// git.allow_worktree_parent is enabled. Returns "" otherwise.
//
// Detection forks git, so gitworktree memoizes it per directory; whether a
// directory is a linked worktree does not change over the lifetime of a session.
func (s *Sandbox) WorktreeParentPath(workDir string) string {
	if !s.getConfig().Git.AllowsWorktreeParent() {
		return ""
	}
	return gitworktree.MainWorktree(workDir)
}
