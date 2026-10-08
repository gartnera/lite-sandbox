package bash_sandboxed

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsClaudeConfigPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/repo/.claude", true},
		{"/repo/.claude/settings.json", true},
		{"/home/u/.claude/skills/x/SKILL.md", true},
		{"/repo/.claude/worktrees", false},
		{"/repo/.claude/worktrees/feat/main.go", false},
		{"/repo/.claude/worktrees/feat/.claude/settings.json", true},
		{"/home/u/.claude.json", false},
		{"/repo/claude/settings.json", false},
		{"/repo/src/main.go", false},
		{"/repo/.Claude/settings.json", true},
		{"/repo/.CLAUDE/Worktrees/feat/a.go", false},
	}
	for _, tt := range tests {
		if got := IsClaudeConfigPath(tt.path); got != tt.want {
			t.Errorf("IsClaudeConfigPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// TestBashSandboxed_ClaudeDirReadOnly checks that .claude can be read but not
// written, through every path check: write-command arguments (bare and
// path-like), redirections, expanded variables, and a cd into the directory.
func TestBashSandboxed_ClaudeDirReadOnly(t *testing.T) {
	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, ".claude", "worktrees", "feat"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, ".claude", "settings.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "a.txt"), []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".claude", filepath.Join(workDir, "link")); err != nil {
		t.Fatal(err)
	}

	allowed := []struct {
		name, command string
	}{
		{"cat", "cat .claude/settings.json"},
		{"ls", "ls .claude"},
		{"cd and cat", "cd .claude && cat settings.json"},
		{"input redirect", "cat < .claude/settings.json"},
		{"write into worktrees", "touch .claude/worktrees/feat/a.txt"},
		{"write elsewhere", "touch a.txt"},
		{"sed without -i reads", "sed -n 1p .claude/settings.json"},
		{"cp from .claude", "cp .claude/settings.json backup.json"},
		{"sort reads", "sort .claude/settings.json"},
		{"sort -o elsewhere", "sort -o sorted.txt .claude/settings.json"},
		{"uniq to elsewhere", "uniq .claude/settings.json uniq.txt"},
		{"ln to .claude", "ln -s .claude/settings.json link2"},
		{"chmod outside", "chmod 644 a.txt"},
		{"chmod dash mode outside", "chmod -x a.txt"},
		{"git merge-file -p reads", "git merge-file -p .claude/settings.json a.txt a.txt"},
	}
	for _, tt := range allowed {
		t.Run("allowed/"+tt.name, func(t *testing.T) {
			if _, err := NewSandbox().Execute(context.Background(), tt.command, workDir, []string{workDir}, []string{workDir}); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}

	blocked := []struct {
		name, command string
	}{
		{"touch file", "touch .claude/settings.local.json"},
		{"rm dir", "rm -rf .claude"},
		{"mkdir", "mkdir .claude/skills"},
		{"cp into", "cp a.txt .claude/"},
		{"mv out", "mv .claude/settings.json x.json"},
		{"sed -i", "sed -i s/a/b/ .claude/settings.json"},
		{"redirect", "echo '{}' > .claude/settings.json"},
		{"append redirect", "echo x >> .claude/settings.json"},
		{"tee", "echo x | tee .claude/settings.json"},
		{"absolute", "touch " + filepath.Join(workDir, ".claude", "x")},
		{"variable", "D=.claude; touch $D/x"},
		{"variable redirect", "F=.claude/settings.json; echo x > $F"},
		{"cd then touch", "cd .claude && touch x"},
		{"cd then redirect", "cd .claude && echo x > settings.json"},
		{"through symlink", "touch link/x"},
		{"symlinked dir itself", "rm link/settings.json"},
		{"nested worktree .claude", "touch .claude/worktrees/feat/.claude"},
		{"other case", "touch .Claude/x"},
		{"sort -o", "sort -o .claude/settings.json a.txt"},
		{"sort --output=", "sort --output=.claude/settings.json a.txt"},
		{"sort clustered -o", "sort -uo.claude/settings.json a.txt"},
		{"uniq output", "uniq a.txt .claude/settings.local.json"},
		{"uniq output after value flag", "uniq -f 1 a.txt .claude/settings.local.json"},
		{"sed -i", "sed -i s/a/b/ .claude/settings.json"},
		{"sed -ni", "sed -ni s/a/b/p .claude/settings.json"},
		{"sed --in-place", "sed --in-place=.bak s/a/b/ .claude/settings.json"},
		{"cp -t", "cp -t .claude a.txt"},
		{"ln link inside", "ln -s a.txt .claude/x"},
		{"cd then ln", "cd .claude && ln -s /dev/null"},
		{"cd then chmod", "cd .claude && chmod 644 settings.json"},
		{"chmod dash mode", "chmod -w .claude/settings.json"},
		{"iconv -o", "iconv -f utf-8 -t ascii -o .claude/x a.txt"},
		{"mktemp -p", "mktemp -p .claude XXXXXX"},
		{"mktemp template", "mktemp .claude/XXXXXX"},
		{"yq -i", "yq -i '.a = 1' .claude/settings.json"},
		{"git mv", "git mv a.txt .claude/settings.json"},
		{"git checkout path", "git checkout -- .claude/settings.json"},
		{"git -C restore", "git -C .claude restore settings.json"},
		{"git checkout-index", "git checkout-index -f .claude/settings.json"},
		{"git merge-file", "git merge-file .claude/settings.json a.txt a.txt"},
		{"git interpret-trailers --in-place", "git interpret-trailers --in-place --trailer 'A: b' .claude/settings.json"},
		{"git diff --output", "git diff --output=.claude/settings.json"},
		{"git archive -o", "git archive -o .claude/x.tar HEAD"},
		{"git archive --output", "git archive --output .claude/x.tar HEAD"},
		{"git format-patch -o", "git format-patch -o .claude/skills HEAD~1"},
		{"git format-patch in .claude", "cd .claude && git format-patch HEAD~1"},
		{"git bundle create", "git bundle create .claude/x.bundle HEAD"},
		{"git fast-export marks", "git fast-export --export-marks=.claude/marks HEAD"},
		{"git read-tree --index-output", "git read-tree --index-output=.claude/idx HEAD"},
		{"git unpack-file in .claude", "cd .claude && git unpack-file abc123"},
		{"git diff --output separate", "git diff --output .claude/settings.json"},
		{"git interpret-trailers --in", "git interpret-trailers --in --trailer 'A: b' .claude/settings.json"},
		{"git merge-file --marker-size", "git merge-file --marker-size 7 .claude/settings.json a.txt a.txt"},
		{"git bundle create --version", "git bundle create --version 3 .claude/x.bundle HEAD"},
		{"git pack-objects --window", "git pack-objects --window 10 .claude/pack"},
		{"git --work-tree checkout", "git --work-tree .claude checkout HEAD -- settings.json"},
		{"git --work-tree= checkout", "git --work-tree=.claude checkout HEAD -- settings.json"},
		{"git init", "git init .claude/skills/repo"},
		{"git clone", "git clone -q . .claude/skills/repo"},
		{"git clone in .claude", "cd .claude && git clone https://example.invalid/repo.git"},
		{"git worktree add", "git worktree add -b x .claude/skills/wt"},
		{"sort --out abbreviated", "sort --out .claude/settings.json a.txt"},
	}
	for _, tt := range blocked {
		t.Run("blocked/"+tt.name, func(t *testing.T) {
			_, err := NewSandbox().Execute(context.Background(), tt.command, workDir, []string{workDir}, []string{workDir})
			if err == nil {
				t.Fatal("expected .claude write to be blocked")
			}
			if !strings.Contains(err.Error(), ".claude directory") {
				t.Fatalf("expected .claude error, got %q", err.Error())
			}
		})
	}

	got, err := os.ReadFile(filepath.Join(workDir, ".claude", "settings.json"))
	if err != nil || string(got) != "{}\n" {
		t.Fatalf("settings.json changed: %q, %v", got, err)
	}
}

// TestOSSandboxGitCheckoutTrackedClaudeDir checks that the OS sandbox does
// not mask .claude: switching branches across a change to a tracked .claude
// file succeeds instead of failing midway with a half-switched tree.
func TestOSSandboxGitCheckoutTrackedClaudeDir(t *testing.T) {
	requireOSSandbox(t)
	workDir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"}, args...)...)
		cmd.Dir = workDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	skill := filepath.Join(workDir, ".claude", "skills", "s", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(skill), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(skill, []byte("main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("init", "-q", "-b", "main")
	git("add", ".")
	git("commit", "-q", "-m", "main")
	git("checkout", "-q", "-b", "other")
	if err := os.WriteFile(skill, []byte("other\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git("commit", "-q", "-am", "other")
	git("checkout", "-q", "main")

	s := newOSSandboxForTest(t, workDir)
	if out, err := s.Execute(context.Background(), "git checkout -q other", workDir, []string{workDir}, []string{workDir}); err != nil {
		t.Fatalf("git checkout failed: %q, %v", out, err)
	}
	if got, err := os.ReadFile(skill); err != nil || string(got) != "other\n" {
		t.Fatalf("SKILL.md not checked out: %q, %v", got, err)
	}
}
