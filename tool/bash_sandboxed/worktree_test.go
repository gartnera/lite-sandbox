package bash_sandboxed

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

func TestDetectWorktreeParent_NotAGitRepo(t *testing.T) {
	tmp := t.TempDir()
	if got := detectWorktreeParent(tmp); got != "" {
		t.Errorf("expected empty for non-git dir, got %q", got)
	}
}

func TestDetectWorktreeParent_MainWorktree(t *testing.T) {
	repo := initRepo(t)
	if got := detectWorktreeParent(repo); got != "" {
		t.Errorf("expected empty for main worktree, got %q", got)
	}
}

func TestDetectWorktreeParent_LinkedWorktree(t *testing.T) {
	repo := initRepo(t)
	wt := filepath.Join(filepath.Dir(repo), "wt")
	run(t, repo, "git", "worktree", "add", "-b", "feature", wt)

	got := detectWorktreeParent(wt)
	wantResolved, _ := filepath.EvalSymlinks(repo)
	gotResolved, _ := filepath.EvalSymlinks(got)
	if gotResolved != wantResolved {
		t.Errorf("expected main worktree %q, got %q", wantResolved, gotResolved)
	}
}

func TestSandbox_WorktreeParentPath_FlagOff(t *testing.T) {
	repo := initRepo(t)
	wt := filepath.Join(filepath.Dir(repo), "wt")
	run(t, repo, "git", "worktree", "add", "-b", "feature", wt)

	s := NewSandbox() // flag defaults to false
	if got := s.WorktreeParentPath(wt); got != "" {
		t.Errorf("expected empty when flag is disabled, got %q", got)
	}
}

func TestSandbox_WorktreeParentPath_FlagOn(t *testing.T) {
	repo := initRepo(t)
	wt := filepath.Join(filepath.Dir(repo), "wt")
	run(t, repo, "git", "worktree", "add", "-b", "feature", wt)

	s := newTestSandboxWithGitConfig(&config.GitConfig{
		AllowWorktreeParent: boolPtr(true),
	})
	got := s.WorktreeParentPath(wt)
	wantResolved, _ := filepath.EvalSymlinks(repo)
	gotResolved, _ := filepath.EvalSymlinks(got)
	if gotResolved != wantResolved {
		t.Errorf("expected %q, got %q", wantResolved, gotResolved)
	}
}

// initRepo creates a fresh git repo in a temp dir with an initial commit so
// that subsequent operations (like `git worktree add -b`) succeed.
func initRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	run(t, dir, "git", "init", "-b", "main")
	run(t, dir, "git", "config", "user.email", "t@example.com")
	run(t, dir, "git", "config", "user.name", "Test")
	run(t, dir, "git", "commit", "--allow-empty", "-m", "init")
	return dir
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}
