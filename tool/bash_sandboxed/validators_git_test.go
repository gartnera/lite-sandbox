package bash_sandboxed

import (
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// TestValidate_AllowedGitSubcommands tests commands allowed with default config
// (local_read=true, local_write=true, remote_read=true, remote_write=false).
func TestValidate_AllowedGitSubcommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		// Local read
		{"git status", "git status"},
		{"git log", "git log"},
		{"git log oneline", "git log --oneline"},
		{"git log graph", "git log --oneline --graph --all"},
		{"git diff", "git diff"},
		{"git diff cached", "git diff --cached"},
		{"git diff staged", "git diff --staged"},
		{"git diff files", "git diff HEAD~1 HEAD"},
		{"git show", "git show"},
		{"git show commit", "git show HEAD"},
		{"git blame", "git blame file.go"},
		{"git branch list", "git branch"},
		{"git branch verbose", "git branch -v"},
		{"git branch all", "git branch -a"},
		{"git branch remote", "git branch -r"},
		{"git tag list", "git tag"},
		{"git tag list pattern", "git tag -l 'v*'"},
		{"git shortlog", "git shortlog"},
		{"git shortlog summary", "git shortlog -sn"},
		{"git describe", "git describe"},
		{"git describe tags", "git describe --tags"},
		{"git rev-parse HEAD", "git rev-parse HEAD"},
		{"git rev-parse branch", "git rev-parse --abbrev-ref HEAD"},
		{"git rev-list", "git rev-list HEAD"},
		{"git rev-list count", "git rev-list --count HEAD"},
		{"git ls-files", "git ls-files"},
		{"git ls-tree", "git ls-tree HEAD"},
		{"git cat-file", "git cat-file -p HEAD"},
		{"git name-rev", "git name-rev HEAD"},
		{"git config list", "git config --list"},
		{"git config get", "git config --get user.name"},
		{"git config get-all", "git config --get-all user.name"},
		{"git config get-regexp", "git config --get-regexp 'user.*'"},
		{"git config get-urlmatch", "git config --get-urlmatch http https://example.com"},
		{"git config -l", "git config -l"},
		{"git reflog", "git reflog"},
		{"git grep", "git grep -n foo"},
		{"git grep pathspec", `git grep -nE "claude-|opus|model" -- ':!*.lock'`},
		{"git grep -e dash pattern", "git grep -e -O"},
		{"git grep pattern after --", "git grep -e foo -- -Ofile"},
		{"git grep no pager", "git grep --no-open-files-in-pager foo"},
		{"bare git", "git"},
		{"git version", "git --version"},
		{"git help", "git --help"},
		{"git -C path status", "git -C /tmp status"},
		{"git for-each-ref", "git for-each-ref --format='%(refname:short)' refs/heads"},
		{"git for-each-ref sort", "git for-each-ref --sort=-committerdate refs/heads/"},
		{"git show-ref", "git show-ref --heads"},
		{"git symbolic-ref read", "git symbolic-ref --short HEAD"},
		{"git cherry", "git cherry -v main"},
		{"git range-diff", "git range-diff main...feature"},
		{"git diff-tree", "git diff-tree --no-commit-id --name-only -r HEAD"},
		{"git diff-index", "git diff-index --quiet HEAD --"},
		{"git diff-files", "git diff-files --name-only"},
		{"git whatchanged", "git whatchanged -n1"},
		{"git show-branch", "git show-branch --list"},
		{"git annotate", "git annotate file.go"},
		{"git count-objects", "git count-objects -v"},
		{"git fsck", "git fsck --no-dangling"},
		{"git verify-commit", "git verify-commit HEAD"},
		{"git verify-tag", "git verify-tag v1.0"},
		{"git merge-tree", "git merge-tree --write-tree main feature"},
		{"git check-ignore", "git check-ignore -v build/out.o"},
		{"git check-attr", "git check-attr -a file.go"},
		{"git check-ref-format", "git check-ref-format --branch feature"},
		{"git check-mailmap", "git check-mailmap 'A <a@b.c>'"},
		{"git var", "git var GIT_EDITOR"},
		{"git hash-object", "git hash-object file.go"},
		{"git hash-object stdin", "git hash-object --stdin"},
		{"git interpret-trailers", "git interpret-trailers --parse msg.txt"},
		{"git stripspace", "git stripspace -s"},
		{"git patch-id", "git patch-id --stable"},
		{"git format-patch", "git format-patch -1 HEAD"},
		{"git format-patch -o", "git format-patch -o patches main"},
		{"git archive", "git archive --format=tar -o out.tar HEAD"},
		{"git archive remote", "git archive --remote=origin HEAD"},
		{"git fast-export", "git fast-export --all"},
		{"git bundle create", "git bundle create repo.bundle --all"},
		{"git bundle verify", "git bundle verify repo.bundle"},
		{"git last-modified", "git last-modified -r"},
		{"git repo info", "git repo info layout.bare"},
		{"git refs list", "git refs list"},
		{"git reflog show", "git reflog show HEAD"},
		{"git stash list", "git stash list"},
		{"git worktree list", "git worktree list"},
		{"git notes show", "git notes show HEAD"},
		{"git help", "git help log"},
		{"git help all", "git help -a"},
		{"git version", "git version"},
		{"git config get action", "git config get user.name"},
		// Local write (allowed by default)
		{"git add", "git add file.go"},
		{"git commit", "git commit -m 'msg'"},
		{"git checkout", "git checkout main"},
		{"git switch", "git switch main"},
		{"git restore", "git restore file.go"},
		{"git reset", "git reset HEAD"},
		{"git stash", "git stash"},
		{"git merge", "git merge feature"},
		{"git rebase", "git rebase main"},
		{"git cherry-pick", "git cherry-pick abc123"},
		{"git rm", "git rm file.go"},
		{"git mv", "git mv old.go new.go"},
		{"git init", "git init"},
		{"git bisect", "git bisect start"},
		{"git clean", "git clean -fd"},
		{"git revert", "git revert HEAD"},
		{"git apply", "git apply patch.diff"},
		{"git update-index", "git update-index --assume-unchanged file.go"},
		{"git update-index refresh", "git update-index --refresh"},
		{"git update-ref", "git update-ref refs/heads/x HEAD"},
		{"git symbolic-ref write", "git symbolic-ref HEAD refs/heads/main"},
		{"git hash-object -w", "git hash-object -w file.go"},
		{"git reflog expire", "git reflog expire --expire=now --all"},
		{"git gc", "git gc --prune=now"},
		{"git maintenance run", "git maintenance run --task=gc"},
		{"git prune", "git prune"},
		{"git repack", "git repack -ad"},
		{"git pack-refs", "git pack-refs --all"},
		{"git sparse-checkout", "git sparse-checkout set src"},
		{"git replace", "git replace -d abc123"},
		{"git rerere", "git rerere forget file.go"},
		{"git read-tree", "git read-tree HEAD"},
		{"git write-tree", "git write-tree"},
		{"git commit-tree", "git commit-tree -m msg abc123"},
		{"git checkout-index", "git checkout-index -a -f"},
		{"git merge-file", "git merge-file cur.txt base.txt other.txt"},
		{"git fast-import", "git fast-import --quiet"},
		{"git refs migrate", "git refs migrate --ref-format=reftable"},
		{"git history", "git history reword HEAD~1"},
		{"git replay", "git replay --onto main topic~2..topic"},
		{"git commit-graph", "git commit-graph write --reachable"},
		{"git bundle unbundle", "git bundle unbundle repo.bundle"},
		{"git notes add", "git notes add -m note HEAD"},
		// Local write also unlocks branch/tag/config mutation
		{"git branch delete", "git branch -d feature"},
		{"git branch move", "git branch -m old new"},
		{"git tag create", "git tag -a v1.0 -m 'release'"},
		{"git tag delete", "git tag -d v1.0"},
		{"git config set", "git config user.name 'test'"},
		// Remote read (allowed by default)
		{"git fetch", "git fetch origin"},
		{"git pull", "git pull"},
		{"git clone", "git clone https://example.com/repo.git"},
		{"git ls-remote", "git ls-remote origin"},
		{"git backfill", "git backfill --sparse"},
		{"git request-pull", "git request-pull v1.0 https://example.com/repo.git"},
		{"git maintenance prefetch", "git maintenance run --task=prefetch"},
		// Remote subcommands (read ops)
		{"git remote", "git remote"},
		{"git remote show", "git remote show origin"},
		{"git submodule status", "git submodule status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

// TestValidate_BlockedGitSubcommands tests commands blocked with default config.
func TestValidate_BlockedGitSubcommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		// Remote write (blocked by default)
		{"git push", "git push origin main", `git subcommand "push" is not allowed`},
		// Always blocked
		{"git hook", "git hook run pre-commit", `git subcommand "hook" is not allowed`},
		{"git filter-branch", "git filter-branch --env-filter 'echo'", `git subcommand "filter-branch" is not allowed`},
		// git grep -O runs a pager command on the matching files
		{"git grep -O", "git grep -O foo", `git grep flag "-O" is not allowed`},
		// The porcelain transports take the program to run as upload-pack/receive-pack
		{"git fetch --upload-pack", "git fetch --upload-pack='touch x; git-upload-pack' .", `git fetch flag "--upload-pack=touch x; git-upload-pack" is not allowed`},
		{"git pull --upload-pack", "git pull --upload-pack x origin", `git pull flag "--upload-pack" is not allowed`},
		{"git clone -u", "git clone -u x . copy", `git clone flag "-u" is not allowed`},
		{"git clone -qu bundled", "git clone -qu x . copy", `git clone flag "-qu" is not allowed`},
		{"git ls-remote --upload-pack", "git ls-remote --upload=x .", `git ls-remote flag "--upload=x" is not allowed`},
		{"git ls-remote --exec", "git ls-remote --exec=x .", `git ls-remote flag "--exec=x" is not allowed`},
		{"git submodule foreach", "git submodule foreach 'touch x'", `git submodule foreach is not allowed: runs the shell command`},
		{"git grep -O attached", "git grep -Osh foo", `git grep flag "-Osh" is not allowed`},
		{"git grep -O bundled", "git grep -nOsh foo", `git grep flag "-nOsh" is not allowed`},
		{"git grep long", "git grep --open-files-in-pager=sh foo", `git grep flag "--open-files-in-pager=sh" is not allowed`},
		{"git grep long prefix", "git grep --open=sh foo", `git grep flag "--open=sh" is not allowed`},
		{"git grep after global flag", "git -C . grep -O foo", `git grep flag "-O" is not allowed`},
		// Never allowed: run a command named on the command line, launch
		// something outside the repository, or handle credentials
		{"git difftool", "git difftool -x 'sh -c id'", `git subcommand "difftool" is not allowed`},
		{"git mergetool", "git mergetool", `git subcommand "mergetool" is not allowed`},
		{"git merge-index", "git merge-index sh -a", `git subcommand "merge-index" is not allowed`},
		{"git for-each-repo", "git for-each-repo --config=maintenance.repo push", `git subcommand "for-each-repo" is not allowed`},
		{"git credential", "git credential fill", `git subcommand "credential" is not allowed`},
		{"git credential-store", "git credential-store get", `git subcommand "credential-store" is not allowed`},
		{"git send-email", "git send-email --to-cmd=id 0001.patch", `git subcommand "send-email" is not allowed`},
		{"git daemon", "git daemon --export-all", `git subcommand "daemon" is not allowed`},
		{"git instaweb", "git instaweb", `git subcommand "instaweb" is not allowed`},
		{"git upload-pack", "git upload-pack .", `git subcommand "upload-pack" is not allowed`},
		{"git gui", "git gui", `git subcommand "gui" is not allowed`},
		{"git svn", "git svn clone https://example.com/svn", `git subcommand "svn" is not allowed`},
		{"git maintenance start", "git maintenance start", "git maintenance start is not allowed: schedules background maintenance"},
		{"git maintenance register", "git maintenance register", "git maintenance register is not allowed"},
		{"git maintenance bare", "git maintenance", `git subcommand "maintenance" is not allowed`},
		{"unknown subcommand", "git frobnicate", `git subcommand "frobnicate" is not allowed`},
		{"alias", "git co main", `git subcommand "co" is not allowed`},
		// Flags that run a command or read files the sandbox can't check
		{"git archive --exec", "git archive --remote=. --exec='sh -c id' HEAD", `git archive flag "--exec=sh -c id" is not allowed`},
		{"git archive --exec abbreviated", "git archive --remote=. --ex=id HEAD", `git archive flag "--ex=id" is not allowed`},
		{"git fetch-pack --upload-pack", "git fetch-pack --upload-pack=id file:///tmp/r", `git fetch-pack flag "--upload-pack=id" is not allowed`},
		{"git hash-object --stdin-paths", "git hash-object -w --stdin-paths", `git hash-object flag "--stdin-paths" is not allowed`},
		{"git hash-object --stdin-p abbreviated", "git hash-object --stdin-p", `git hash-object flag "--stdin-p" is not allowed`},
		{"git fast-import unsafe", "git fast-import --allow-unsafe-features", `git fast-import flag "--allow-unsafe-features" is not allowed`},
		{"git help --web", "git help --web log", `git help flag "--web" is not allowed`},
		{"git help -w bundled", "git help -mw log", `git help flag "-mw" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked git subcommand")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// TestValidate_GitLocalReadOnly tests with only local_read enabled.
func TestValidate_GitLocalReadOnly(t *testing.T) {
	s := newTestSandboxWithGitConfig(&config.GitConfig{
		LocalRead:   boolPtr(true),
		LocalWrite:  boolPtr(false),
		RemoteRead:  boolPtr(false),
		RemoteWrite: boolPtr(false),
	})

	allowed := []struct {
		name    string
		command string
	}{
		{"git status", "git status"},
		{"git log", "git log --oneline"},
		{"git diff", "git diff"},
		{"git branch list", "git branch -v"},
		{"git tag list", "git tag -l 'v*'"},
		{"git config get", "git config --get user.name"},
		{"git config list", "git config --list"},
		{"git reflog", "git reflog"},
	}
	for _, tt := range allowed {
		t.Run("allowed/"+tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := s.validate(f); err != nil {
				t.Fatalf("expected allowed, got: %v", err)
			}
		})
	}

	blocked := []struct {
		name    string
		command string
		errMsg  string
	}{
		// branch/tag/config mutations blocked when local_write=false
		{"branch -d", "git branch -d feature", `git branch flag "-d" is not allowed`},
		{"branch -m", "git branch -m old new", `git branch flag "-m" is not allowed`},
		{"tag -a", "git tag -a v1.0 -m 'release'", `git tag flag "-a" is not allowed`},
		{"tag -d", "git tag -d v1.0", `git tag flag "-d" is not allowed`},
		{"config set", "git config user.name 'test'", "git config is only allowed with"},
		// Local write blocked
		{"git add", "git add file.go", "local_write is disabled"},
		{"git commit", "git commit -m 'msg'", "local_write is disabled"},
		{"git checkout", "git checkout main", "local_write is disabled"},
		{"git merge", "git merge feature", "local_write is disabled"},
		{"git reset", "git reset HEAD", "local_write is disabled"},
		{"git stash", "git stash", "local_write is disabled"},
		{"git update-index", "git update-index --skip-worktree file.go", "local_write is disabled"},
		// Remote read blocked
		{"git fetch", "git fetch origin", "remote_read is disabled"},
		{"git pull", "git pull", "remote_read is disabled"},
		{"git clone", "git clone https://example.com/repo.git", "remote_read is disabled"},
		// Remote write blocked
		{"git push", "git push origin main", "remote_write is disabled"},
	}
	for _, tt := range blocked {
		t.Run("blocked/"+tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = s.validate(f)
			if err == nil {
				t.Fatalf("expected error for %q", tt.command)
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// TestValidate_GitAllDisabled tests with all git permissions disabled.
func TestValidate_GitAllDisabled(t *testing.T) {
	s := newTestSandboxWithGitConfig(&config.GitConfig{
		LocalRead:   boolPtr(false),
		LocalWrite:  boolPtr(false),
		RemoteRead:  boolPtr(false),
		RemoteWrite: boolPtr(false),
	})

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"git status", "git status", "local_read is disabled"},
		{"git log", "git log", "local_read is disabled"},
		{"git add", "git add file.go", "local_write is disabled"},
		{"git fetch", "git fetch origin", "remote_read is disabled"},
		{"git push", "git push origin main", "remote_write is disabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = s.validate(f)
			if err == nil {
				t.Fatalf("expected error for %q", tt.command)
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}

	// bare git, --version, and help should still work
	for _, cmd := range []string{"git", "git --version", "git --help", "git version", "git help log", "git help -a"} {
		t.Run("always_allowed/"+cmd, func(t *testing.T) {
			f, err := ParseBash(cmd)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := s.validate(f); err != nil {
				t.Fatalf("expected %q allowed, got: %v", cmd, err)
			}
		})
	}
}

// TestValidate_GitAllEnabled tests with all permissions enabled including remote_write.
func TestValidate_GitAllEnabled(t *testing.T) {
	s := newTestSandboxWithGitConfig(&config.GitConfig{
		LocalRead:   boolPtr(true),
		LocalWrite:  boolPtr(true),
		RemoteRead:  boolPtr(true),
		RemoteWrite: boolPtr(true),
	})

	tests := []struct {
		name    string
		command string
	}{
		{"git push", "git push origin main"},
		{"git push force", "git push --force origin main"},
		{"git send-pack", "git send-pack origin main"},
		{"git status", "git status"},
		{"git add", "git add file.go"},
		{"git fetch", "git fetch origin"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := s.validate(f); err != nil {
				t.Fatalf("expected allowed, got: %v", err)
			}
		})
	}

	// commands that run a command line or reach outside the repository are still blocked
	for _, cmd := range []string{
		"git hook run pre-commit",
		"git filter-branch --env-filter 'echo'",
		"git send-pack --receive-pack=id origin main",
		"git difftool -x cat",
		"git maintenance start",
		"git credential fill",
	} {
		t.Run("always_blocked/"+cmd, func(t *testing.T) {
			f, err := ParseBash(cmd)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := s.validate(f); err == nil {
				t.Fatalf("expected %q to be blocked", cmd)
			}
		})
	}
}

// TestValidate_BlockedGitBranchFlags tests branch mutation flags when local_write is disabled.
func TestValidate_BlockedGitBranchFlags(t *testing.T) {
	s := newTestSandboxWithGitConfig(&config.GitConfig{
		LocalRead:  boolPtr(true),
		LocalWrite: boolPtr(false),
	})

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"branch -d", "git branch -d feature", `git branch flag "-d" is not allowed`},
		{"branch -D", "git branch -D feature", `git branch flag "-D" is not allowed`},
		{"branch --delete", "git branch --delete feature", `git branch flag "--delete" is not allowed`},
		{"branch -m", "git branch -m old new", `git branch flag "-m" is not allowed`},
		{"branch -M", "git branch -M old new", `git branch flag "-M" is not allowed`},
		{"branch --move", "git branch --move old new", `git branch flag "--move" is not allowed`},
		{"branch -c", "git branch -c old new", `git branch flag "-c" is not allowed`},
		{"branch -C", "git branch -C old new", `git branch flag "-C" is not allowed`},
		{"branch --copy", "git branch --copy old new", `git branch flag "--copy" is not allowed`},
		{"branch --edit-description", "git branch --edit-description", `git branch flag "--edit-description" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = s.validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked git branch flag")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// TestValidate_BlockedGitTagFlags tests tag mutation flags when local_write is disabled.
func TestValidate_BlockedGitTagFlags(t *testing.T) {
	s := newTestSandboxWithGitConfig(&config.GitConfig{
		LocalRead:  boolPtr(true),
		LocalWrite: boolPtr(false),
	})

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"tag -a", "git tag -a v1.0 -m 'release'", `git tag flag "-a" is not allowed`},
		{"tag --annotate", "git tag --annotate v1.0", `git tag flag "--annotate" is not allowed`},
		{"tag -d", "git tag -d v1.0", `git tag flag "-d" is not allowed`},
		{"tag --delete", "git tag --delete v1.0", `git tag flag "--delete" is not allowed`},
		{"tag -s", "git tag -s v1.0", `git tag flag "-s" is not allowed`},
		{"tag --sign", "git tag --sign v1.0", `git tag flag "--sign" is not allowed`},
		{"tag -f", "git tag -f v1.0", `git tag flag "-f" is not allowed`},
		{"tag --force", "git tag --force v1.0", `git tag flag "--force" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = s.validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked git tag flag")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// TestValidate_BlockedGitConfig tests config mutation when local_write is disabled.
func TestValidate_BlockedGitConfig(t *testing.T) {
	s := newTestSandboxWithGitConfig(&config.GitConfig{
		LocalRead:  boolPtr(true),
		LocalWrite: boolPtr(false),
	})

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"config set value", "git config user.name 'test'", "git config is only allowed with"},
		{"config unset", "git config --unset user.name", "git config is only allowed with"},
		{"config bare", "git config", "git config is only allowed with"},
		{"config edit", "git config --edit", "git config is only allowed with"},
		{"config global set", "git config --global user.email 'a@b.com'", "git config is only allowed with"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = s.validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked git config usage")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// TestValidate_GitRemoteSubcommand tests remote/submodule permission handling.
func TestValidate_GitRemoteSubcommand(t *testing.T) {
	// With remote_read but no local_write
	s := newTestSandboxWithGitConfig(&config.GitConfig{
		LocalRead:   boolPtr(true),
		LocalWrite:  boolPtr(false),
		RemoteRead:  boolPtr(true),
		RemoteWrite: boolPtr(false),
	})

	allowed := []string{
		"git remote",
		"git remote show origin",
		"git submodule status",
		"git submodule summary",
	}
	for _, cmd := range allowed {
		t.Run("allowed/"+cmd, func(t *testing.T) {
			f, err := ParseBash(cmd)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := s.validate(f); err != nil {
				t.Fatalf("expected allowed, got: %v", err)
			}
		})
	}

	blocked := []struct {
		command string
		errMsg  string
	}{
		{"git remote add origin url", "local_write is disabled"},
		{"git remote remove origin", "local_write is disabled"},
		{"git submodule add https://example.com/repo", "local_write is disabled"},
		{"git submodule init", "local_write is disabled"},
	}
	for _, tt := range blocked {
		t.Run("blocked/"+tt.command, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = s.validate(f)
			if err == nil {
				t.Fatalf("expected error for %q", tt.command)
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// git grep really runs, and a -O that only appears after expansion is still
// caught at runtime, where the static validator saw nothing but a parameter.
func TestExecute_GitGrep(t *testing.T) {
	dir := t.TempDir()
	s := newTestSandbox()
	if _, err := executeInDirWithSandbox(t, s, dir, "git init -q && echo 'model: opus' > f.txt && git add f.txt"); err != nil {
		t.Fatalf("setup: %v", err)
	}
	out, err := executeInDirWithSandbox(t, s, dir, `git grep -nE "claude-|opus" -- ':!*.lock'`)
	if err != nil {
		t.Fatalf("git grep: %v", err)
	}
	if !strings.Contains(out, "f.txt:1:model: opus") {
		t.Errorf("unexpected git grep output: %q", out)
	}

	_, err = executeInDirWithSandbox(t, s, dir, `O=-Osh; git grep $O opus`)
	if err == nil || !strings.Contains(err.Error(), `git grep flag "-Osh" is not allowed`) {
		t.Fatalf("expected expanded -O to be rejected, got %v", err)
	}
}

// TestValidate_GitReadActions tests the read-only forms of mixed subcommands
// (actions, flags, operand counts) with only local_read enabled.
func TestValidate_GitReadActions(t *testing.T) {
	s := newTestSandboxWithGitConfig(&config.GitConfig{
		LocalRead:   boolPtr(true),
		LocalWrite:  boolPtr(false),
		RemoteRead:  boolPtr(false),
		RemoteWrite: boolPtr(false),
	})

	allowed := []string{
		"git for-each-ref refs/heads",
		"git stash list",
		"git stash show -p stash@{0}",
		"git worktree list --porcelain",
		"git notes",
		"git notes list",
		"git notes show HEAD",
		"git reflog",
		"git reflog show HEAD",
		"git reflog main",
		"git reflog exists main",
		"git refs list",
		"git refs exists refs/heads/main",
		"git rerere status",
		"git sparse-checkout list",
		"git commit-graph verify",
		"git multi-pack-index verify",
		"git bundle create repo.bundle --all",
		"git bundle list-heads repo.bundle",
		"git maintenance is-needed",
		"git symbolic-ref HEAD",
		"git symbolic-ref --short HEAD",
		"git hash-object file.go",
		"git hash-object --stdin",
		"git fsck",
		"git interpret-trailers --parse msg.txt",
		"git archive -o out.zip HEAD",
		"git config get user.name",
		"git config list",
		"git config --get-color color.diff.new",
		// A global -C is not git branch's -C (force copy)
		"git -C . branch",
		"git -C . branch -v",
	}
	for _, cmd := range allowed {
		t.Run("allowed/"+cmd, func(t *testing.T) {
			f, err := ParseBash(cmd)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := s.validate(f); err != nil {
				t.Fatalf("expected allowed, got: %v", err)
			}
		})
	}

	blocked := []struct {
		command string
		errMsg  string
	}{
		{"git stash", "git subcommand \"stash\" is not allowed (local_write is disabled)"},
		{"git stash pop", "local_write is disabled"},
		{"git worktree add ../wt", "local_write is disabled"},
		{"git notes add -m x", "local_write is disabled"},
		{"git reflog expire --expire=now --all", "git reflog expire is not allowed (local_write is disabled)"},
		{"git reflog delete HEAD@{1}", "git reflog delete is not allowed (local_write is disabled)"},
		{"git refs delete refs/heads/x", "local_write is disabled"},
		{"git rerere forget file.go", "local_write is disabled"},
		{"git sparse-checkout set src", "local_write is disabled"},
		{"git commit-graph write", "local_write is disabled"},
		{"git bundle unbundle repo.bundle", "git bundle unbundle is not allowed (local_write is disabled)"},
		{"git maintenance run", "git maintenance run is not allowed (local_write is disabled)"},
		{"git gc", "local_write is disabled"},
		{"git update-ref refs/heads/x HEAD", "local_write is disabled"},
		{"git history reword HEAD", "local_write is disabled"},
		{"git replay --onto main topic~2..topic", "local_write is disabled"},
		{"git symbolic-ref HEAD refs/heads/x", "git symbolic-ref with a target is not allowed"},
		{"git symbolic-ref -d HEAD", `git symbolic-ref flag "-d" is not allowed`},
		{"git hash-object -w file.go", `git hash-object flag "-w" is not allowed: writes the object into the repository (local_write is disabled)`},
		{"git fsck --lost-found", `git fsck flag "--lost-found" is not allowed`},
		{"git interpret-trailers --in-place msg.txt", `git interpret-trailers flag "--in-place" is not allowed`},
		{"git config set user.name x", "git config is only allowed with"},
		// Long flags match by the prefixes git expands
		{"git branch --del feature", `git branch flag "--del" is not allowed`},
		{"git branch --delete=feature", `git branch flag "--delete=feature" is not allowed`},
		{"git tag --ann v1", `git tag flag "--ann" is not allowed`},
		// Short flags match inside a bundle
		{"git branch -qd feature", `git branch flag "-qd" is not allowed`},
		{"git tag -fa v1", `git tag flag "-fa" is not allowed`},
		{"git symbolic-ref -qd HEAD", `git symbolic-ref flag "-qd" is not allowed`},
		// Global config can name a program git runs
		{"git -c core.pager=cat log", `git option "-c" is not allowed`},
		{"git --config-env=core.pager=P log", `git option "--config-env=core.pager=P" is not allowed`},
		// Remote reads stay remote reads
		{"git archive --remote=origin HEAD", `git archive flag "--remote=origin" is not allowed: fetches the archive from a remote (remote_read is disabled)`},
		{"git backfill", "remote_read is disabled"},
		{"git request-pull v1 origin", "remote_read is disabled"},
		{"git fetch-pack origin", "remote_read is disabled"},
		{"git send-pack origin main", "remote_write is disabled"},
	}
	for _, tt := range blocked {
		t.Run("blocked/"+tt.command, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = s.validate(f)
			if err == nil {
				t.Fatalf("expected error for %q", tt.command)
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

// git maintenance run's prefetch task fetches from every remote, so it needs
// remote_read on top of local_write.
func TestValidate_GitMaintenancePrefetch(t *testing.T) {
	s := newTestSandboxWithGitConfig(&config.GitConfig{
		LocalRead:  boolPtr(true),
		LocalWrite: boolPtr(true),
		RemoteRead: boolPtr(false),
	})
	for _, cmd := range []string{"git maintenance run --task=prefetch", "git maintenance run --task prefetch", "git maintenance run --ta=prefetch", "git maintenance run --tas prefetch"} {
		f, err := ParseBash(cmd)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := s.validate(f); err == nil || !strings.Contains(err.Error(), "remote_read is disabled") {
			t.Fatalf("%s: expected remote_read error, got %v", cmd, err)
		}
	}
	f, err := ParseBash("git maintenance run --task=gc")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if err := s.validate(f); err != nil {
		t.Fatalf("expected gc task allowed, got %v", err)
	}
}

// The newly classified plumbing really runs: git for-each-ref, show-ref,
// symbolic-ref, and a few more, against a real repository. A blocked flag
// that only appears after expansion is still caught at runtime.
func TestExecute_GitPlumbing(t *testing.T) {
	dir := t.TempDir()
	s := newTestSandbox()
	setup := "git init -q -b main && git -c user.name=t -c user.email=t@t commit -q --allow-empty -m init && git tag v1"
	if _, err := executeInDirWithSandbox(t, s, dir, setup); err != nil {
		t.Fatalf("setup: %v", err)
	}
	for _, tt := range []struct{ cmd, want string }{
		{"git for-each-ref --format='%(refname)'", "refs/heads/main\nrefs/tags/v1\n"},
		{"git show-ref --heads -s | wc -l", "1\n"},
		{"git symbolic-ref --short HEAD", "main\n"},
		{"git cherry main main | wc -l", "0\n"},
		{"git stash list | wc -l", "0\n"},
		{"git version | cut -d' ' -f1-2", "git version\n"},
	} {
		out, err := executeInDirWithSandbox(t, s, dir, tt.cmd)
		if err != nil {
			t.Fatalf("%s: %v", tt.cmd, err)
		}
		if out != tt.want {
			t.Errorf("%s: got %q, want %q", tt.cmd, out, tt.want)
		}
	}

	_, err := executeInDirWithSandbox(t, s, dir, `F=--stdin-paths; echo file.go | git hash-object $F`)
	if err == nil || !strings.Contains(err.Error(), `git hash-object flag "--stdin-paths" is not allowed`) {
		t.Fatalf("expected expanded --stdin-paths to be rejected, got %v", err)
	}
}
