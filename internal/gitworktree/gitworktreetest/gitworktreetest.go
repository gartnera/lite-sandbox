// Package gitworktreetest builds throwaway git repositories and linked
// worktrees for tests that depend on worktree layout.
package gitworktreetest

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// InitRepo creates a fresh git repo in a temp dir with an initial commit, so
// that subsequent operations (like `git worktree add -b`) succeed. It returns
// the repo's main worktree path.
func InitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	Git(t, dir, "init", "-b", "main")
	Git(t, dir, "config", "user.email", "t@example.com")
	Git(t, dir, "config", "user.name", "Test")
	Git(t, dir, "commit", "--allow-empty", "-m", "init")
	return dir
}

// AddWorktree creates a linked worktree of repo on a new branch and returns its
// path. The worktree is placed in a temp dir of its own rather than under repo,
// mirroring the real layout where worktrees live in a container (e.g.
// ~/.superconductor/worktrees) far from the checkout they came from.
func AddWorktree(t *testing.T, repo, branch string) string {
	t.Helper()
	wt := filepath.Join(t.TempDir(), branch)
	Git(t, repo, "worktree", "add", "-b", branch, wt)
	return wt
}

// Git runs a git command in dir, failing the test if it errors.
func Git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
}
