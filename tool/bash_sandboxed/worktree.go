package bash_sandboxed

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// detectWorktreeParent returns the absolute path to the main worktree when
// workDir is inside a linked git worktree. Returns "" when workDir is not in
// a git repo, is the main worktree itself, lives in a bare repo with no main
// worktree, or detection otherwise fails.
//
// Detection runs `git rev-parse --path-format=absolute --git-dir --git-common-dir`.
// If git-dir and git-common-dir differ, workDir is a linked worktree and the
// directory containing the common dir is the main worktree root.
func detectWorktreeParent(workDir string) string {
	if workDir == "" {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "-C", workDir, "rev-parse",
		"--path-format=absolute", "--git-dir", "--git-common-dir")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		return ""
	}
	gitDir := strings.TrimSpace(lines[0])
	commonDir := strings.TrimSpace(lines[1])
	if gitDir == "" || commonDir == "" || gitDir == commonDir {
		return ""
	}

	// The main worktree root is the parent of the common .git directory.
	// For a bare repo, common dir is the repo itself (no parent worktree);
	// skip when the common dir doesn't end in ".git".
	if filepath.Base(commonDir) != ".git" {
		return ""
	}
	return filepath.Dir(commonDir)
}

// WorktreeParentPath returns the absolute main-worktree path to grant access
// to when workDir is inside a linked git worktree and the config flag
// git.allow_worktree_parent is enabled. Returns "" otherwise.
//
// Detection forks git, so the result is memoized per workDir until the next
// UpdateConfig; whether a directory is a linked worktree does not change over
// the lifetime of a session.
func (s *Sandbox) WorktreeParentPath(workDir string) string {
	if !s.getConfig().Git.AllowsWorktreeParent() {
		return ""
	}

	s.mu.RLock()
	parent, ok := s.worktreeParentCache[workDir]
	s.mu.RUnlock()
	if ok {
		return parent
	}

	parent = detectWorktreeParent(workDir)

	s.mu.Lock()
	if s.worktreeParentCache == nil {
		s.worktreeParentCache = make(map[string]string)
	}
	s.worktreeParentCache[workDir] = parent
	s.mu.Unlock()
	return parent
}
