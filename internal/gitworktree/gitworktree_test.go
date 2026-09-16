package gitworktree

import (
	"path/filepath"
	"testing"

	"github.com/gartnera/lite-sandbox/internal/gitworktree/gitworktreetest"
)

func TestMainWorktree_NotAGitRepo(t *testing.T) {
	tmp := t.TempDir()
	if got := MainWorktree(tmp); got != "" {
		t.Errorf("expected empty for non-git dir, got %q", got)
	}
}

func TestMainWorktree_Empty(t *testing.T) {
	if got := MainWorktree(""); got != "" {
		t.Errorf("expected empty for empty dir, got %q", got)
	}
}

func TestMainWorktree_MainWorktree(t *testing.T) {
	repo := gitworktreetest.InitRepo(t)
	if got := MainWorktree(repo); got != "" {
		t.Errorf("expected empty for main worktree, got %q", got)
	}
}

func TestMainWorktree_LinkedWorktree(t *testing.T) {
	repo := gitworktreetest.InitRepo(t)
	wt := gitworktreetest.AddWorktree(t, repo, "feature")

	got := MainWorktree(wt)
	wantResolved, _ := filepath.EvalSymlinks(repo)
	gotResolved, _ := filepath.EvalSymlinks(got)
	if gotResolved != wantResolved {
		t.Errorf("expected main worktree %q, got %q", wantResolved, gotResolved)
	}
}

// TestMainWorktree_Memoized checks the second lookup is served from the cache:
// the worktree is detached from disk between the two calls, so a second git
// invocation would report something different.
func TestMainWorktree_Memoized(t *testing.T) {
	repo := gitworktreetest.InitRepo(t)
	wt := gitworktreetest.AddWorktree(t, repo, "feature")

	first := MainWorktree(wt)
	if first == "" {
		t.Fatal("expected a main worktree on the first lookup")
	}
	gitworktreetest.Git(t, repo, "worktree", "remove", "--force", wt)
	if got := MainWorktree(wt); got != first {
		t.Errorf("expected memoized %q, got %q", first, got)
	}
}
