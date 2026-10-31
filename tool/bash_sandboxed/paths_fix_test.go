package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/configrequest"
)

// fixPattern pulls the config fix out of a boundary refusal.
var fixPattern = regexp.MustCompile("the user can allow it with `([^`]*)`")

// TestPathBoundaryErrorNamesFix checks that a path-boundary refusal names the
// `lite-sandbox config paths allow` command that would lift it — for the real
// path on a read, for the directory holding it on a write — and that a
// refusal no config entry should lift names none.
func TestPathBoundaryErrorNamesFix(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	workDir := filepath.Join(home, "project")
	outside := filepath.Join(home, "outside")
	for _, d := range []string{
		filepath.Join(workDir, ".git"),
		filepath.Join(outside, "existing"),
		filepath.Join(outside, "it's"),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".claude"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(outside, "secret.txt")
	for _, f := range []string{secret, filepath.Join(home, ".ssh", "id_ed25519")} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	allow := "lite-sandbox config paths allow "

	tests := []struct {
		name    string
		command string
		want    string // the fix the refusal names; "" for none
	}{
		{"read argument", "cat " + secret, allow + secret},
		{"read via traversal names the real path", "cat ../outside/secret.txt", allow + secret},
		{"input redirect", "cat < " + secret, allow + secret},
		{"write names the directory holding it", "echo hi > " + outside + "/out", allow + outside + " --write"},
		{"append redirect", "echo hi >> " + outside + "/out", allow + outside + " --write"},
		{"new directory names its parent", "mkdir -p " + outside + "/a/b", allow + outside + "/a --write"},
		{"write after expansion", "D=" + outside + "; mkdir $D/c", allow + outside + " --write"},
		{"existing directory names itself", "touch " + outside + "/existing", allow + outside + "/existing --write"},
		{"source of a write command is checked as a write", "cp " + secret + " x", allow + outside + " --write"},
		{"path with a space is single-quoted", "mkdir -p '" + outside + "/a b/c'", allow + "'" + outside + "/a b' --write"},
		{"path with a quote is double-quoted", `echo hi > "` + outside + `/it's/x"`, allow + `"` + outside + `/it's" --write`},
		{"python read", `python3 -c "print(open('` + secret + `').read())"`, allow + secret},
		{"python write", `python3 -c "open('` + outside + `/py.txt', 'w').write('x')"`, allow + outside + " --write"},
		{".git", "cat .git/config", ""},
		{"home directory itself", "ls " + home, ""},
		{"deny-listed credentials", "cat " + home + "/.ssh/id_ed25519", ""},
		{"agent configuration", "echo x > " + home + "/.claude/settings.json", ""},
		{"system root", "cat /etc/hosts", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSandboxWithConfig(&config.Config{})
			defer s.Close()
			_, err := s.Execute(context.Background(), tt.command, workDir, []string{workDir}, []string{workDir})
			if err == nil {
				t.Fatalf("expected a refusal for %q", tt.command)
			}
			msg := err.Error()
			m := fixPattern.FindStringSubmatch(msg)
			if tt.want == "" {
				if m != nil || strings.Contains(msg, "lite-sandbox config") {
					t.Fatalf("expected no config fix, got %q", msg)
				}
				return
			}
			if m == nil || m[1] != tt.want {
				t.Fatalf("expected fix `%s`, got %q", tt.want, msg)
			}
			// The fix must work as a config request: one literal command
			// whose path argument is the path itself.
			req, ok := configrequest.Parse(m[1])
			if !ok {
				t.Fatalf("fix %q does not parse as a config request", m[1])
			}
			if len(req.Args) < 3 || !slices.Equal(req.Args[:2], []string{"paths", "allow"}) {
				t.Fatalf("fix %q parsed to %q", m[1], req.Args)
			}
			if !strings.Contains(msg, "outside allowed directories") {
				t.Fatalf("expected a boundary refusal, got %q", msg)
			}
		})
	}
}

func TestConfigWord(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"/home/u/tmp", "/home/u/tmp"},
		{"/home/u/x+y,z=w", "/home/u/x+y,z=w"},
		{"/home/u/a b", "'/home/u/a b'"},
		{"/home/u/~x", "'/home/u/~x'"},
		{"/home/u/$HOME", "'/home/u/$HOME'"},
		{"/home/u/it's", `"/home/u/it's"`},
		{`/home/u/it's$x`, ""},
		{`/home/u/it's\x`, ""},
	} {
		got, ok := configWord(tt.in)
		if !ok {
			got = ""
		}
		if got != tt.want {
			t.Errorf("configWord(%q) = %q, want %q", tt.in, got, tt.want)
			continue
		}
		if got == "" {
			continue
		}
		req, ok := configrequest.Parse("lite-sandbox config paths allow " + got)
		if !ok || len(req.Args) != 3 || req.Args[2] != tt.in {
			t.Errorf("configWord(%q) = %q does not parse back (ok=%v, args=%q)", tt.in, got, ok, req.Args)
		}
	}
}
