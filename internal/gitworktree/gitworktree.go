// Package gitworktree resolves a working directory to the main worktree of the
// git repository it belongs to. Linked worktrees (`git worktree add`) commonly
// live far away from the repository they were created from — under a container
// like ~/.superconductor/worktrees rather than next to the checkout — so the
// sandbox needs the link back to that repository to treat the two as one
// project (granting access to the main worktree, resolving per-directory
// config overrides, ...).
package gitworktree

import (
	"context"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// cache memoizes MainWorktree per directory for the lifetime of the process:
// detection forks git, and whether a directory is a linked worktree does not
// change over the lifetime of a session.
var cache sync.Map // map[string]string

// MainWorktree returns the absolute path to the main worktree when dir is
// inside a linked git worktree. Returns "" when dir is not in a git repo, is
// the main worktree itself, lives in a bare repo with no main worktree, or
// detection otherwise fails.
//
// Detection runs `git rev-parse --path-format=absolute --git-dir --git-common-dir`.
// If git-dir and git-common-dir differ, dir is a linked worktree and the
// directory containing the common dir is the main worktree root. The path git
// reports has symlinks resolved, which callers comparing it against
// user-configured paths need to account for.
func MainWorktree(dir string) string {
	if dir == "" {
		return ""
	}
	if parent, ok := cache.Load(dir); ok {
		return parent.(string)
	}
	parent := detect(dir)
	cache.Store(dir, parent)
	return parent
}

// Toplevel returns the root of the git working tree dir is in, spelled as an
// ancestor of dir (or dir itself) rather than with symlinks resolved as git
// reports it, so it matches paths derived from dir lexically. Returns "" when
// dir is not in a git working tree or detection fails.
func Toplevel(dir string) string {
	if dir == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return ""
	}
	top := filepath.Clean(strings.TrimSpace(string(out)))
	if top == "." || top == "" {
		return ""
	}
	resolvedTop, err := filepath.EvalSymlinks(top)
	if err != nil {
		return ""
	}
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if d == top {
			return d
		}
		if r, err := filepath.EvalSymlinks(d); err == nil && r == resolvedTop {
			return d
		}
		if parent := filepath.Dir(d); parent == d {
			return top
		}
	}
}

func detect(dir string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse",
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
