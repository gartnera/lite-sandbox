package bash_sandboxed

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRedirectPaths_Allowed(t *testing.T) {
	workDir := t.TempDir()
	os.WriteFile(filepath.Join(workDir, "input.txt"), []byte("hello"), 0o644)

	tests := []struct {
		name    string
		command string
	}{
		{"input redirect from local file", "cat < input.txt"},
		{"input redirect absolute allowed", "cat < " + workDir + "/input.txt"},
		{"heredoc no path", "cat <<EOF\nhello\nEOF"},
		{"output to /dev/null", "echo hello > /dev/null"},
		{"output redirect to local file", "echo hello > output.txt"},
		{"append redirect to local file", "echo hello >> output.txt"},
		{"output redirect absolute allowed", "echo hello > " + workDir + "/output.txt"},
		{"clobber to local file", "echo hello >| output.txt"},
		{"all to local file", "echo hello &> output.txt"},
		{"append all to local file", "echo hello &>> output.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := validateRedirectPaths(f, workDir, []string{workDir}, []string{workDir}); err != nil {
				t.Fatalf("expected redirect path to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidateRedirectPaths_Blocked(t *testing.T) {
	workDir := t.TempDir()

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"input redirect outside", "cat < /etc/passwd", "outside allowed directories"},
		{"input redirect traversal", "cat < ../../../etc/passwd", "outside allowed directories"},
		{"output redirect outside", "echo hello > /etc/evil", "outside allowed directories"},
		{"append redirect outside", "echo hello >> /tmp/evil", "outside allowed directories"},
		{"output redirect traversal", "echo hello > ../../../tmp/evil", "outside allowed directories"},
		{"all redirect outside", "echo hello &> /tmp/evil", "outside allowed directories"},
		{"output redirect to .git", "echo hello > .git/config", "accesses .git directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validateRedirectPaths(f, workDir, []string{workDir}, []string{workDir})
			if err == nil {
				t.Fatal("expected redirect path validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestBashSandboxed_RedirectAllowed(t *testing.T) {
	workDir := t.TempDir()
	os.WriteFile(filepath.Join(workDir, "input.txt"), []byte("hello\n"), 0o644)

	// Input redirect from file in allowed dir
	out, err := NewSandbox().Execute(context.Background(), "cat < "+workDir+"/input.txt", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", out)
	}

	// Heredoc
	out, err = NewSandbox().Execute(context.Background(), "cat <<EOF\nworld\nEOF", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "world\n" {
		t.Fatalf("expected 'world\\n', got %q", out)
	}

	// /dev/null output
	out, err = NewSandbox().Execute(context.Background(), "echo hello > /dev/null", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "" {
		t.Fatalf("expected empty output, got %q", out)
	}

	// Output redirect to file in allowed dir
	_, err = NewSandbox().Execute(context.Background(), "echo hello > "+workDir+"/output.txt", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	content, _ := os.ReadFile(filepath.Join(workDir, "output.txt"))
	if string(content) != "hello\n" {
		t.Fatalf("expected 'hello\\n' in output.txt, got %q", string(content))
	}

	// Append redirect to file in allowed dir
	_, err = NewSandbox().Execute(context.Background(), "echo world >> "+workDir+"/output.txt", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	content, _ = os.ReadFile(filepath.Join(workDir, "output.txt"))
	if string(content) != "hello\nworld\n" {
		t.Fatalf("expected 'hello\\nworld\\n' in output.txt, got %q", string(content))
	}
}

func TestBashSandboxed_RedirectPathBlocked(t *testing.T) {
	workDir := t.TempDir()
	_, err := NewSandbox().Execute(context.Background(), "cat < /etc/passwd", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected error for redirect path outside allowed dirs")
	}
	if !strings.Contains(err.Error(), "outside allowed directories") {
		t.Fatalf("expected outside allowed directories error, got %q", err.Error())
	}
}

func TestExtractPathFromFlag(t *testing.T) {
	tests := []struct {
		flag     string
		expected string
	}{
		// Short flags with embedded paths
		{"-f/etc/passwd", "/etc/passwd"},
		{"-I../include", "../include"},
		{"-L/usr/lib", "/usr/lib"},
		// Long flags with = separator
		{"--file=/etc/passwd", "/etc/passwd"},
		{"--output=/tmp/out", "/tmp/out"},
		// No embedded path
		{"-l", ""},
		{"-la", "a"}, // single-char flag 'l', value 'a'; looksLikePath filters it
		{"--verbose", ""},
		{"--count", ""},
		{"-n", ""},
		// Long flag without =
		{"--file", ""},
	}
	for _, tt := range tests {
		t.Run(tt.flag, func(t *testing.T) {
			got := extractPathFromFlag(tt.flag)
			if got != tt.expected {
				t.Fatalf("extractPathFromFlag(%q) = %q, want %q", tt.flag, got, tt.expected)
			}
		})
	}
}

func TestValidatePaths_Allowed(t *testing.T) {
	workDir := t.TempDir()

	// Create a subdirectory and file for testing
	subDir := filepath.Join(workDir, "subdir")
	os.MkdirAll(subDir, 0o755)
	os.WriteFile(filepath.Join(workDir, "file.txt"), []byte("hello"), 0o644)
	os.WriteFile(filepath.Join(subDir, "nested.txt"), []byte("nested"), 0o644)

	tests := []struct {
		name    string
		command string
	}{
		{"cut -d/ delimiter", "cut -d/ -f1-2 file.txt"},
		{"sort -t/ separator", "sort -t/ -k1 file.txt"},
		{"sed address range expr", "sed -n '/UpgradeOldLoadoutMessage/,/^}/p' file.go"},
		{"sed inline expr", "sed '/pattern/d' file.txt"},
		{"sed substitute expr", "sed 's/old/new/' file.txt"},
		{"sed -e expr outside", "sed -e '/StartsWith//,/^}/p' -e 's/a/b/' file.go"},
		{"git -C outside sandbox", "git -C /tmp status"},
		{"git -C absolute allowed", "git -C " + workDir + " status"},
		{"git --git-dir outside sandbox", "git --git-dir /tmp/.git status"},
		{"git --work-tree outside sandbox", "git --work-tree /tmp status"},
		{"simple filename", "cat file.txt"},
		{"dot path", "ls ."},
		{"dot slash", "cat ./file.txt"},
		{"subdirectory", "cat subdir/nested.txt"},
		{"dot slash subdir", "cat ./subdir/nested.txt"},
		{"find dot", "find . -name '*.txt'"},
		{"no path args", "echo hello"},
		{"flags only", "ls -la"},
		{"workdir absolute", "cat " + workDir + "/file.txt"},
		{"non-path args", "echo hello world"},
		{"grep with pattern", "grep pattern file.txt"},
		{"short flag no value", "ls -la"},
		{"long flag no value", "grep --count pattern"},
		{"long flag with eq local path", "grep --file=" + workDir + "/file.txt pattern"},
		{"short flag with local path", "cat -n ./file.txt"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := validatePaths(f, workDir, []string{workDir}, []string{workDir}); err != nil {
				t.Fatalf("expected path to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidatePaths_Blocked(t *testing.T) {
	workDir := t.TempDir()

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"absolute etc", "cat /etc/passwd", "outside allowed directories"},
		{"absolute root", "find /", "outside allowed directories"},
		{"dot dot traversal", "cat ../../../etc/passwd", "outside allowed directories"},
		{"dot dot simple", "cat ../outside", "outside allowed directories"},
		{"absolute tmp", "ls /tmp", "outside allowed directories"},
		{"absolute bin", "strings /bin/ls", "outside allowed directories"},
		{"stat outside", "stat /etc/hostname", "outside allowed directories"},
		{"head outside", "head -5 /etc/hostname", "outside allowed directories"},
		{"du outside", "du -sh /tmp", "outside allowed directories"},
		{"diff outside", "diff /dev/null /dev/null", "outside allowed directories"},
		{"short flag embedded path", "grep -f/etc/passwd pattern", "outside allowed directories"},
		{"long flag embedded path", "grep --file=/etc/passwd pattern", "outside allowed directories"},
		{"short flag dot dot", "grep -f../../etc/passwd pattern", "outside allowed directories"},
		{"cd outside absolute", "cd /tmp", "outside allowed directories"},
		{"cd outside traversal", "cd ../../", "outside allowed directories"},
		{"mkdir outside absolute", "mkdir /tmp/evil", "outside allowed directories"},
		{"mkdir outside traversal", "mkdir ../evil", "outside allowed directories"},
		{"mkdir -p outside", "mkdir -p /tmp/a/b/c", "outside allowed directories"},
		// Write commands blocked outside allowedPaths
		{"cp outside dest", "cp file.txt /tmp/evil", "outside allowed directories"},
		{"cp outside src", "cp /etc/passwd file.txt", "outside allowed directories"},
		{"mv outside dest", "mv file.txt /tmp/evil", "outside allowed directories"},
		{"mv outside src", "mv /etc/passwd file.txt", "outside allowed directories"},
		{"rm outside", "rm /etc/passwd", "outside allowed directories"},
		{"rm -rf outside", "rm -rf /tmp/evil", "outside allowed directories"},
		{"touch outside", "touch /tmp/evil", "outside allowed directories"},
		{"chmod outside", "chmod 777 /etc/passwd", "outside allowed directories"},
		{"ln outside target", "ln -s /etc/passwd link", "outside allowed directories"},
		{"ln outside link", "ln -s target /tmp/link", "outside allowed directories"},
		{"sed outside", "sed -i 's/a/b/' /etc/passwd", "outside allowed directories"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validatePaths(f, workDir, []string{workDir}, []string{workDir})
			if err == nil {
				t.Fatal("expected path validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidatePaths_GitDirectoryBlocked(t *testing.T) {
	workDir := t.TempDir()

	// Create a .git directory structure
	os.MkdirAll(filepath.Join(workDir, ".git", "hooks"), 0o755)
	os.WriteFile(filepath.Join(workDir, ".git", "config"), []byte("[core]"), 0o644)
	os.WriteFile(filepath.Join(workDir, ".git", "hooks", "pre-commit"), []byte("#!/bin/sh"), 0o755)

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"cat .git/config", "cat .git/config", "accesses .git directory"},
		{"cat .git/hooks/pre-commit", "cat .git/hooks/pre-commit", "accesses .git directory"},
		{"ls .git", "ls .git", "accesses .git directory"},
		{"ls .git/hooks", "ls .git/hooks", "accesses .git directory"},
		{"find .git", "find .git -name '*.sample'", "accesses .git directory"},
		{"absolute .git", "cat " + workDir + "/.git/config", "accesses .git directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validatePaths(f, workDir, []string{workDir}, []string{workDir})
			if err == nil {
				t.Fatal("expected path validation error for .git access")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidatePaths_SymlinkEscape(t *testing.T) {
	workDir := t.TempDir()

	// Create a symlink inside workDir that points outside
	symlink := filepath.Join(workDir, "escape")
	os.Symlink("/etc", symlink)

	f, err := ParseBash("cat escape/passwd")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = validatePaths(f, workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected path validation error for symlink escape")
	}
	if !strings.Contains(err.Error(), "outside allowed directories") {
		t.Fatalf("expected outside allowed directories error, got %q", err.Error())
	}
}

func TestValidatePaths_MultipleAllowedPaths(t *testing.T) {
	workDir := t.TempDir()
	extraDir := t.TempDir()

	os.WriteFile(filepath.Join(extraDir, "allowed.txt"), []byte("ok"), 0o644)

	f, err := ParseBash("cat " + extraDir + "/allowed.txt")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	// Should be blocked with only workDir allowed
	err = validatePaths(f, workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected error when extra dir not in allowed paths")
	}

	// Should be allowed with both dirs
	err = validatePaths(f, workDir, []string{workDir, extraDir}, []string{workDir, extraDir})
	if err != nil {
		t.Fatalf("expected path to be allowed with multiple allowed paths, got: %v", err)
	}
}

func TestValidatePaths_InSubshellAndPipeline(t *testing.T) {
	workDir := t.TempDir()

	tests := []struct {
		name    string
		command string
	}{
		{"subshell", "(cat /etc/passwd)"},
		{"pipeline", "cat /etc/passwd | grep root"},
		{"and chain", "true && cat /etc/passwd"},
		{"command substitution", "echo $(cat /etc/passwd)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validatePaths(f, workDir, []string{workDir}, []string{workDir})
			if err == nil {
				t.Fatal("expected path validation error")
			}
		})
	}
}

func TestBashSandboxed_PathBlocked(t *testing.T) {
	workDir := t.TempDir()
	_, err := NewSandbox().Execute(context.Background(), "cat /etc/passwd", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected error for path outside allowed dirs")
	}
	if !strings.Contains(err.Error(), "outside allowed directories") {
		t.Fatalf("expected outside allowed directories error, got %q", err.Error())
	}
}

func TestBashSandboxed_VariableExpansionPathBlocked(t *testing.T) {
	workDir := t.TempDir()

	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"cat HOME var", `cat $HOME/secret`, "outside allowed directories"},
		{"cat HOME braces", `cat ${HOME}/secret`, "outside allowed directories"},
		{"cat env var absolute", `HOME=/etc cat $HOME/passwd`, "outside allowed directories"},
		{"head HOME var", `head $HOME/secret`, "outside allowed directories"},
		{"redirect input var", `cat < $HOME/secret`, "outside allowed directories"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewSandbox().Execute(context.Background(), tt.command, workDir, []string{workDir}, []string{workDir})
			if err == nil {
				t.Fatal("expected error for variable expansion path outside allowed dirs")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestBashSandboxed_VariableExpansionAllowed(t *testing.T) {
	workDir := t.TempDir()
	os.WriteFile(filepath.Join(workDir, "hello.txt"), []byte("hello\n"), 0o644)

	tests := []struct {
		name    string
		command string
		want    string
	}{
		{"echo var", `FOO=world echo $FOO`, ""},
		{"echo with expansion", `echo hello`, "hello\n"},
		{"var in local path", fmt.Sprintf(`DIR=%s; cat $DIR/hello.txt`, workDir), "hello\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := NewSandbox().Execute(context.Background(), tt.command, workDir, []string{workDir}, []string{workDir})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.want != "" && out != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, out)
			}
		})
	}
}

func TestValidatePaths_ReadWriteSeparation(t *testing.T) {
	workDir := t.TempDir()
	extraReadDir := t.TempDir()

	os.WriteFile(filepath.Join(extraReadDir, "data.txt"), []byte("hello"), 0o644)

	readPaths := []string{workDir, extraReadDir}
	writePaths := []string{workDir}

	t.Run("read command allowed on read-only path", func(t *testing.T) {
		f, err := ParseBash("cat " + extraReadDir + "/data.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := validatePaths(f, workDir, readPaths, writePaths); err != nil {
			t.Fatalf("expected read to be allowed on read-only path, got: %v", err)
		}
	})

	t.Run("grep allowed on read-only path", func(t *testing.T) {
		f, err := ParseBash("grep hello " + extraReadDir + "/data.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := validatePaths(f, workDir, readPaths, writePaths); err != nil {
			t.Fatalf("expected grep to be allowed on read-only path, got: %v", err)
		}
	})

	t.Run("write command blocked on read-only path", func(t *testing.T) {
		f, err := ParseBash("cp file.txt " + extraReadDir + "/evil.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		err = validatePaths(f, workDir, readPaths, writePaths)
		if err == nil {
			t.Fatal("expected write command to be blocked on read-only path")
		}
		if !strings.Contains(err.Error(), "outside allowed directories") {
			t.Fatalf("expected outside allowed directories error, got %q", err.Error())
		}
	})

	t.Run("touch blocked on read-only path", func(t *testing.T) {
		f, err := ParseBash("touch " + extraReadDir + "/evil.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		err = validatePaths(f, workDir, readPaths, writePaths)
		if err == nil {
			t.Fatal("expected touch to be blocked on read-only path")
		}
	})

	t.Run("rm blocked on read-only path", func(t *testing.T) {
		f, err := ParseBash("rm " + extraReadDir + "/data.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		err = validatePaths(f, workDir, readPaths, writePaths)
		if err == nil {
			t.Fatal("expected rm to be blocked on read-only path")
		}
	})

	t.Run("mv blocked on read-only path", func(t *testing.T) {
		f, err := ParseBash("mv " + extraReadDir + "/data.txt file.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		err = validatePaths(f, workDir, readPaths, writePaths)
		if err == nil {
			t.Fatal("expected mv to be blocked on read-only path")
		}
	})

	t.Run("write command allowed in write path", func(t *testing.T) {
		f, err := ParseBash("touch " + workDir + "/newfile.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := validatePaths(f, workDir, readPaths, writePaths); err != nil {
			t.Fatalf("expected write command in write path to be allowed, got: %v", err)
		}
	})
}

func TestValidateRedirectPaths_ReadWriteSeparation(t *testing.T) {
	workDir := t.TempDir()
	extraReadDir := t.TempDir()

	os.WriteFile(filepath.Join(extraReadDir, "input.txt"), []byte("hello"), 0o644)

	readPaths := []string{workDir, extraReadDir}
	writePaths := []string{workDir}

	t.Run("input redirect from read-only path allowed", func(t *testing.T) {
		f, err := ParseBash("cat < " + extraReadDir + "/input.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := validateRedirectPaths(f, workDir, readPaths, writePaths); err != nil {
			t.Fatalf("expected input redirect from read-only path to be allowed, got: %v", err)
		}
	})

	t.Run("output redirect to read-only path blocked", func(t *testing.T) {
		f, err := ParseBash("echo hello > " + extraReadDir + "/evil.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		err = validateRedirectPaths(f, workDir, readPaths, writePaths)
		if err == nil {
			t.Fatal("expected output redirect to read-only path to be blocked")
		}
		if !strings.Contains(err.Error(), "outside allowed directories") {
			t.Fatalf("expected outside allowed directories error, got %q", err.Error())
		}
	})

	t.Run("append redirect to read-only path blocked", func(t *testing.T) {
		f, err := ParseBash("echo hello >> " + extraReadDir + "/evil.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		err = validateRedirectPaths(f, workDir, readPaths, writePaths)
		if err == nil {
			t.Fatal("expected append redirect to read-only path to be blocked")
		}
	})

	t.Run("output redirect to write path allowed", func(t *testing.T) {
		f, err := ParseBash("echo hello > " + workDir + "/output.txt")
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := validateRedirectPaths(f, workDir, readPaths, writePaths); err != nil {
			t.Fatalf("expected output redirect to write path to be allowed, got: %v", err)
		}
	})
}

func TestBashSandboxed_ReadWriteSeparation_Integration(t *testing.T) {
	workDir := t.TempDir()
	extraReadDir := t.TempDir()

	os.WriteFile(filepath.Join(extraReadDir, "readable.txt"), []byte("hello\n"), 0o644)

	readPaths := []string{workDir, extraReadDir}
	writePaths := []string{workDir}

	s := NewSandbox()

	t.Run("cat file in read-only path", func(t *testing.T) {
		out, err := s.Execute(context.Background(), "cat "+extraReadDir+"/readable.txt", workDir, readPaths, writePaths)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != "hello\n" {
			t.Fatalf("expected 'hello\\n', got %q", out)
		}
	})

	t.Run("grep in read-only path", func(t *testing.T) {
		out, err := s.Execute(context.Background(), "grep hello "+extraReadDir+"/readable.txt", workDir, readPaths, writePaths)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(out, "hello") {
			t.Fatalf("expected output to contain 'hello', got %q", out)
		}
	})

	t.Run("cp to read-only path blocked", func(t *testing.T) {
		os.WriteFile(filepath.Join(workDir, "src.txt"), []byte("data"), 0o644)
		_, err := s.Execute(context.Background(), "cp "+workDir+"/src.txt "+extraReadDir+"/evil.txt", workDir, readPaths, writePaths)
		if err == nil {
			t.Fatal("expected error for cp targeting read-only path")
		}
		if !strings.Contains(err.Error(), "outside allowed directories") {
			t.Fatalf("expected outside allowed directories error, got %q", err.Error())
		}
	})

	t.Run("touch in read-only path blocked", func(t *testing.T) {
		_, err := s.Execute(context.Background(), "touch "+extraReadDir+"/evil.txt", workDir, readPaths, writePaths)
		if err == nil {
			t.Fatal("expected error for touch targeting read-only path")
		}
	})

	t.Run("input redirect from read-only path allowed", func(t *testing.T) {
		out, err := s.Execute(context.Background(), "cat < "+extraReadDir+"/readable.txt", workDir, readPaths, writePaths)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if out != "hello\n" {
			t.Fatalf("expected 'hello\\n', got %q", out)
		}
	})

	t.Run("output redirect to read-only path blocked", func(t *testing.T) {
		_, err := s.Execute(context.Background(), "echo evil > "+extraReadDir+"/evil.txt", workDir, readPaths, writePaths)
		if err == nil {
			t.Fatal("expected error for output redirect to read-only path")
		}
	})
}

func TestValidateExpandedPaths_GrepPatternNotPath(t *testing.T) {
	workDir := t.TempDir()
	os.MkdirAll(filepath.Join(workDir, ".git"), 0o755)

	tests := []struct {
		name    string
		args    []string
		wantErr bool
		errMsg  string
	}{
		// Grep pattern args should NOT trigger .git path checks
		{"grep -v .git/ pattern", []string{"grep", "-v", ".git/"}, false, ""},
		{"grep -v .git pattern", []string{"grep", "-v", ".git"}, false, ""},
		{"grep pattern from stdin", []string{"grep", ".git/config"}, false, ""},
		{"grep -e pattern", []string{"grep", "-e", ".git/config"}, false, ""},
		// File args for grep SHOULD be path-checked
		{"grep pattern .git/config blocked", []string{"grep", "pattern", ".git/config"}, true, "accesses .git directory"},
		{"grep -e pat .git/config blocked", []string{"grep", "-e", "pat", ".git/config"}, true, "accesses .git directory"},
		// Non-grep commands still block .git/ args
		{"cat .git/ blocked", []string{"cat", ".git/"}, true, "accesses .git directory"},
		{"ls .git blocked", []string{"ls", ".git"}, true, "accesses .git directory"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExpandedPaths(tt.args, workDir, []string{workDir}, []string{workDir})
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}
