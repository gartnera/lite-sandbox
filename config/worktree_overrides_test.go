package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gartnera/lite-sandbox/internal/gitworktree/gitworktreetest"
)

// A linked worktree lives wherever `git worktree add` put it, so it never
// matches the override written for the repository's path. It should still
// resolve to that repository's settings.
func TestForDirectory_WorktreeInheritsRepoOverride(t *testing.T) {
	repo := gitworktreetest.InitRepo(t)
	wt := gitworktreetest.AddWorktree(t, repo, "feature")

	cfg := &Config{
		Mode: string(ModeAllowlist),
		Overrides: []DirectoryOverride{
			{Path: repo, Config: Config{Mode: string(ModeDenylist)}},
		},
	}

	if got := cfg.ForDirectory(repo).EffectiveMode(); got != ModeDenylist {
		t.Fatalf("repo mode = %q, want %q", got, ModeDenylist)
	}
	if got := cfg.ForDirectory(wt).EffectiveMode(); got != ModeDenylist {
		t.Errorf("worktree mode = %q, want the repo's %q", got, ModeDenylist)
	}
	// A subdirectory of the worktree inherits it too.
	sub := filepath.Join(wt, "sub", "dir")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := cfg.ForDirectory(sub).EffectiveMode(); got != ModeDenylist {
		t.Errorf("worktree subdir mode = %q, want the repo's %q", got, ModeDenylist)
	}
}

// An override covering the repo's parent directory reaches the worktree the
// same way: the fallback re-runs the normal prefix match from the main worktree.
func TestForDirectory_WorktreeInheritsAncestorOverride(t *testing.T) {
	repo := gitworktreetest.InitRepo(t)
	wt := gitworktreetest.AddWorktree(t, repo, "feature")

	cfg := &Config{
		Overrides: []DirectoryOverride{
			{Path: filepath.Dir(repo), Config: Config{Mode: string(ModeOpen)}},
		},
	}
	if got := cfg.ForDirectory(wt).EffectiveMode(); got != ModeOpen {
		t.Errorf("worktree mode = %q, want the repo parent's %q", got, ModeOpen)
	}
}

// A directly matching override always wins over the inherited one, so a
// worktree (or the container holding several of them) can be configured
// separately from the repository it came from.
func TestForDirectory_WorktreeDirectMatchWins(t *testing.T) {
	repo := gitworktreetest.InitRepo(t)
	wt := gitworktreetest.AddWorktree(t, repo, "feature")

	cfg := &Config{
		Overrides: []DirectoryOverride{
			{Path: repo, Config: Config{Mode: string(ModeOpen)}},
			{Path: wt, Config: Config{Mode: string(ModeAllowlist)}},
		},
	}
	if got := cfg.ForDirectory(wt).EffectiveMode(); got != ModeAllowlist {
		t.Errorf("worktree mode = %q, want its own %q", got, ModeAllowlist)
	}
}

// The main worktree of the repo is not a linked worktree, so it never
// inherits from anywhere; and an unrelated directory stays on the base config.
func TestForDirectory_NoWorktreeInheritanceElsewhere(t *testing.T) {
	repo := gitworktreetest.InitRepo(t)
	_ = gitworktreetest.AddWorktree(t, repo, "feature")

	cfg := &Config{
		Mode: string(ModeAllowlist),
		Overrides: []DirectoryOverride{
			{Path: filepath.Join(repo, "sub"), Config: Config{Mode: string(ModeOpen)}},
		},
	}
	if got := cfg.ForDirectory(repo).EffectiveMode(); got != ModeAllowlist {
		t.Errorf("repo mode = %q, want base %q", got, ModeAllowlist)
	}
	if got := cfg.ForDirectory(t.TempDir()).EffectiveMode(); got != ModeAllowlist {
		t.Errorf("unrelated dir mode = %q, want base %q", got, ModeAllowlist)
	}
}

// Inheritance carries every section, not just the mode, and honours merge:true
// exactly as a direct match does.
func TestForDirectory_WorktreeInheritsAllSections(t *testing.T) {
	repo := gitworktreetest.InitRepo(t)
	wt := gitworktreetest.AddWorktree(t, repo, "feature")
	yes := true

	cfg := &Config{
		Docker: &DockerConfig{Enabled: &yes},
		Overrides: []DirectoryOverride{
			{
				Path:  repo,
				Merge: true,
				Config: Config{
					Docker: &DockerConfig{AllowPrivileged: &yes},
					Paths:  []PathEntry{{Path: filepath.Join(repo, "out"), Write: &yes}},
				},
			},
		},
	}

	got := cfg.ForDirectory(wt)
	if !got.Docker.DockerEnabled() {
		t.Error("docker.enabled = false, want the base value kept by the merge")
	}
	if !got.Docker.AllowsPrivileged() {
		t.Error("docker.allow_privileged = false, want the override's true")
	}
	if want := []string{filepath.Join(repo, "out")}; len(got.ExpandedWritablePaths()) != 1 || got.ExpandedWritablePaths()[0] != want[0] {
		t.Errorf("writable paths = %v, want %v", got.ExpandedWritablePaths(), want)
	}
}
