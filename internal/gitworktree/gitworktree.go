// Package gitworktree resolves a working directory to the main worktree of the
// git repository it belongs to. Linked worktrees (`git worktree add`) commonly
// live far away from the repository they were created from — under a container
// like ~/.superconductor/worktrees rather than next to the checkout — so the
// sandbox needs the link back to that repository to treat the two as one
// project (granting access to the main worktree, resolving per-directory
// config scopes, ...).
package gitworktree

import (
	"context"
	"os"
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

// Toplevel returns the root of the ordinary git repository dir is in: an
// ancestor of dir (or dir itself) holding a `.git` directory that git uses as
// the repository's git dir. It is spelled as that ancestor of dir rather than
// with symlinks resolved as git reports it, so it matches paths derived from
// dir lexically. Returns "" when dir is not in such a repository or detection
// fails.
//
// What git reports is only trusted that far because a sandboxed command can
// write files git reads as a repository without any `.git` in their path: a
// bare repository's HEAD, objects/, refs/ and config, whose core.worktree
// then names any directory as the toplevel. Requiring the toplevel to be an
// ancestor of dir whose `.git` directory is the git dir in use rules those
// out; `.git` itself is outside what sandboxed commands may write.
func Toplevel(dir string) string {
	if dir == "" {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse",
		"--path-format=absolute", "--show-toplevel", "--git-dir").Output()
	if err != nil {
		return ""
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		return ""
	}
	top, gitDir := filepath.Clean(strings.TrimSpace(lines[0])), filepath.Clean(strings.TrimSpace(lines[1]))
	if !filepath.IsAbs(top) || !filepath.IsAbs(gitDir) {
		return ""
	}
	resolvedTop, err := filepath.EvalSymlinks(top)
	if err != nil {
		return ""
	}
	resolvedGitDir, err := filepath.EvalSymlinks(gitDir)
	if err != nil || resolvedGitDir != filepath.Join(resolvedTop, ".git") {
		return ""
	}
	if fi, err := os.Lstat(resolvedGitDir); err != nil || !fi.IsDir() {
		return ""
	}
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if r, err := filepath.EvalSymlinks(d); err == nil && r == resolvedTop {
			return d
		}
		if parent := filepath.Dir(d); parent == d {
			return "" // not an ancestor of dir
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
	if !linkedWorktreeOf(dir, gitDir, commonDir) {
		return ""
	}
	return filepath.Dir(commonDir)
}

// linkedWorktreeOf reports whether dir is in a genuine linked worktree of the
// repository whose common git dir is commonDir: the git dir in use is
// <commonDir>/worktrees/<name>, and that entry's gitdir file names the `.git`
// file of an ancestor of dir (or dir itself). git takes the git-dir /
// common-dir pair from files a sandboxed command can write without touching a
// `.git` path — a bare repository planted as HEAD, objects/, refs/ and a
// commondir file, or a git dir moved out of `.git` — so the pair alone would
// let it name any repository on the host as "the main worktree". Both ends of
// the check here live under `.git` paths, which sandboxed commands cannot
// write.
func linkedWorktreeOf(dir, gitDir, commonDir string) bool {
	rGitDir, err1 := filepath.EvalSymlinks(gitDir)
	rCommon, err2 := filepath.EvalSymlinks(commonDir)
	if err1 != nil || err2 != nil || filepath.Dir(rGitDir) != filepath.Join(rCommon, "worktrees") {
		return false
	}
	back, err := os.ReadFile(filepath.Join(rGitDir, "gitdir"))
	if err != nil {
		return false
	}
	dotGit := filepath.Clean(strings.TrimSpace(string(back)))
	if !filepath.IsAbs(dotGit) || filepath.Base(dotGit) != ".git" {
		return false
	}
	if fi, err := os.Lstat(dotGit); err != nil || !fi.Mode().IsRegular() {
		return false
	}
	wt, err := filepath.EvalSymlinks(filepath.Dir(dotGit))
	if err != nil {
		return false
	}
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if r, err := filepath.EvalSymlinks(d); err == nil && r == wt {
			return true
		}
		if filepath.Dir(d) == d {
			return false
		}
	}
}
