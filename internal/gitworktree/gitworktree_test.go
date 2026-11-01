package gitworktree

import (
	"os"
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

// TestMainWorktree_LinkedWorktreeSubdir checks a subdirectory of a linked
// worktree resolves to the main worktree too.
func TestMainWorktree_LinkedWorktreeSubdir(t *testing.T) {
	repo := gitworktreetest.InitRepo(t)
	wt := gitworktreetest.AddWorktree(t, repo, "feature")
	sub := filepath.Join(wt, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	wantResolved, _ := filepath.EvalSymlinks(repo)
	if gotResolved, _ := filepath.EvalSymlinks(MainWorktree(sub)); gotResolved != wantResolved {
		t.Errorf("expected main worktree %q, got %q", wantResolved, gotResolved)
	}
}

// TestMainWorktree_PlantedCommondir checks files a sandboxed command can
// write without touching a `.git` path — a bare repository's HEAD, objects/
// and refs/ plus a commondir file naming another repository's .git — do not
// make that repository the main worktree.
func TestMainWorktree_PlantedCommondir(t *testing.T) {
	victim := gitworktreetest.InitRepo(t)
	proj := t.TempDir()
	for _, d := range []string{"objects", "refs/heads"} {
		if err := os.MkdirAll(filepath.Join(proj, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"HEAD":      "ref: refs/heads/main\n",
		"commondir": filepath.Join(victim, ".git") + "\n",
	} {
		if err := os.WriteFile(filepath.Join(proj, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := MainWorktree(proj); got != "" {
		t.Errorf("planted commondir: MainWorktree = %q, want none", got)
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
