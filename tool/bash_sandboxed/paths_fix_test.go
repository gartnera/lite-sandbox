package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPathBoundaryErrorNamesFix checks that a path-boundary denial names the
// `lite-sandbox config paths allow` command that would lift it, for the real
// path, with --write exactly when the path is written, and that the .git
// refusal, which no config change lifts, names none.
func TestPathBoundaryErrorNamesFix(t *testing.T) {
	workDir := t.TempDir()
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(workDir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(outside, "secret.txt")
	allow := "lite-sandbox config paths allow "

	tests := []struct {
		name    string
		command string
		want    string // the fix, as it must appear in backticks; "" for none
	}{
		{"read argument", "cat " + secret, allow + secret},
		{"write argument", "mkdir -p " + outside + "/a/b", allow + outside + "/a/b --write"},
		{"write argument after expansion", "D=" + outside + "; mkdir $D/c", allow + outside + "/c --write"},
		{"input redirect", "cat < " + secret, allow + secret},
		{"output redirect", "echo hi > " + outside + "/out", allow + outside + "/out --write"},
		{"append redirect", "echo hi >> " + outside + "/out", allow + outside + "/out --write"},
		{"traversal names the real path", "cat ../" + filepath.Base(outside) + "/secret.txt", allow + secret},
		{"path with a space is quoted", "mkdir '" + outside + "/a b'", allow + "'" + outside + "/a b' --write"},
		{"python read", `python3 -c "print(open('` + secret + `').read())"`, allow + secret},
		{"python write", `python3 -c "open('` + outside + `/py.txt', 'w').write('x')"`, allow + outside + "/py.txt --write"},
		{".git has no fix", "cat .git/config", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSandbox()
			defer s.Close()
			_, err := s.Execute(context.Background(), tt.command, workDir, []string{workDir}, []string{workDir})
			if err == nil {
				t.Fatalf("expected a boundary denial for %q", tt.command)
			}
			msg := err.Error()
			switch {
			case tt.name == ".git has no fix":
				if strings.Contains(msg, "lite-sandbox config") {
					t.Fatalf(".git denial names a config fix: %q", msg)
				}
			default:
				if !strings.Contains(msg, "`"+tt.want+"`") {
					t.Fatalf("expected fix `%s` in %q", tt.want, msg)
				}
			}
		})
	}
}

func TestConfigWord(t *testing.T) {
	for in, want := range map[string]string{
		"/home/u/tmp":     "/home/u/tmp",
		"/home/u/a b":     "'/home/u/a b'",
		"/home/u/it's":    `'/home/u/it'\''s'`,
		"/home/u/$HOME":   "'/home/u/$HOME'",
		"/home/u/x+y,z=w": "/home/u/x+y,z=w",
		"/home/u/~x":      "'/home/u/~x'",
		"":                "''",
	} {
		if got := configWord(in); got != want {
			t.Errorf("configWord(%q) = %q, want %q", in, got, want)
		}
	}
}
