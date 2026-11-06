package bash_sandboxed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidate_AllowedRedirections(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"heredoc", "cat <<EOF\nhello\nEOF"},
		{"heredoc dash", "cat <<-EOF\n\thello\nEOF"},
		{"herestring", "cat <<< 'hello'"},
		{"fd dup stderr to stdout", "echo hello 2>&1"},
		{"fd dup close", "echo hello 2>&-"},
		{"output to /dev/null", "echo hello > /dev/null"},
		{"append to /dev/null", "echo hello >> /dev/null"},
		{"clobber to /dev/null", "echo hello >| /dev/null"},
		{"all to /dev/null", "echo hello &> /dev/null"},
		{"append all to /dev/null", "echo hello &>> /dev/null"},
		{"stderr to /dev/null", "echo hello 2> /dev/null"},
		{"input redirect", "cat < file.txt"},
		{"input fd dup", "cat 0<&3"},
		{"combined stderr and devnull", "echo hello 2>&1 > /dev/null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected redirection to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidate_AllowedOutputRedirections(t *testing.T) {
	// Output redirects to files are now allowed by validate() — path checking
	// is done separately by validateRedirectPaths.
	tests := []struct {
		name    string
		command string
	}{
		{"output redirect to file", "echo hello > file.txt"},
		{"append redirect to file", "echo hello >> file.txt"},
		{"output in pipe to file", "echo hello | grep hello > file.txt"},
		{"clobber to file", "echo hello >| file.txt"},
		{"all to file", "echo hello &> file.txt"},
		{"append all to file", "echo hello &>> file.txt"},
		// `>&word` with no fd number is bash's other spelling of `&>word`.
		{"fd dup form of all to file", "echo hello >& file.txt"},
		{"fd dup form of all to /dev/null", "ls >&/dev/null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected redirection to be allowed, got: %v", err)
			}
		})
	}
}

// TestExecute_DupOutToFile runs `>&file`, which bash treats as `&>file`: both
// streams go to the file, and the file is held to the path boundary like any
// other output redirect.
func TestExecute_DupOutToFile(t *testing.T) {
	dir := t.TempDir()
	s := newTestSandbox()
	if _, err := executeInDirWithSandbox(t, s, dir, `ls >&/dev/null`); err != nil {
		t.Fatalf("ls >&/dev/null: %v", err)
	}
	if _, err := executeInDirWithSandbox(t, s, dir, `{ echo out; echo err >&2; } >&out.txt`); err != nil {
		t.Fatalf("redirect to file: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "out\nerr\n" {
		t.Fatalf("out.txt = %q, want both streams", got)
	}
	outside := filepath.Join(t.TempDir(), "x.txt")
	if _, err := executeInDirWithSandbox(t, s, dir, `echo hi >&`+outside); err == nil {
		t.Fatal("expected a >& target outside the boundary to be refused")
	}
	if _, err := os.Stat(outside); err == nil {
		t.Fatal("file outside the boundary was written")
	}
}

func TestValidate_BlockedRedirections(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"read-write redirect", "echo hello <> file.txt", "read-write redirection"},
		// With a fd number, bash refuses a file target ("ambiguous redirect").
		{"numbered fd dup to filename", "echo hello 2>& file.txt", "output fd duplication"},
		{"dynamic fd dup target", "echo hello >& $F", "dynamic targets"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for redirection")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}
