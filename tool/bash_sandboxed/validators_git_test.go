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
		{"git grep -O attached", "git grep -Osh foo", `git grep flag "-Osh" is not allowed`},
		{"git grep -O bundled", "git grep -nOsh foo", `git grep flag "-nOsh" is not allowed`},
		{"git grep long", "git grep --open-files-in-pager=sh foo", `git grep flag "--open-files-in-pager=sh" is not allowed`},
		{"git grep long prefix", "git grep --open=sh foo", `git grep flag "--open=sh" is not allowed`},
		{"git grep after global flag", "git -C . grep -O foo", `git grep flag "-O" is not allowed`},
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

	// bare git and --version should still work
	for _, cmd := range []string{"git", "git --version", "git --help"} {
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

	// hook and filter-branch should still be blocked
	for _, cmd := range []string{"git hook run pre-commit", "git filter-branch --env-filter 'echo'"} {
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
