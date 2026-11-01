package configrequest

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/internal/gitworktree/gitworktreetest"
)

// TestDefaultDir checks a config command from a linked worktree is scoped to
// the main worktree, and from anywhere else to the working directory.
func TestDefaultDir(t *testing.T) {
	repo := gitworktreetest.InitRepo(t)
	wt := gitworktreetest.AddWorktree(t, repo, "feature")
	wantMain, _ := filepath.EvalSymlinks(repo)
	if got, _ := filepath.EvalSymlinks(DefaultDir(wt)); got != wantMain {
		t.Errorf("DefaultDir(linked worktree) = %q, want the main worktree %q", got, wantMain)
	}
	if got := DefaultDir(repo); got != filepath.Clean(repo) {
		t.Errorf("DefaultDir(main worktree) = %q, want %q", got, repo)
	}
	// A subdirectory is scoped to the repository root, spelled as the
	// subdirectory's ancestor.
	sub := filepath.Join(repo, "a", "b")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DefaultDir(sub); got != filepath.Clean(repo) {
		t.Errorf("DefaultDir(subdirectory) = %q, want the repository root %q", got, repo)
	}
	plain := t.TempDir()
	if got := DefaultDir(plain); got != plain {
		t.Errorf("DefaultDir(not a repo) = %q, want %q", got, plain)
	}
}

// isolate points the ticket directory at a fresh temp dir (os.UserCacheDir
// reads XDG_CACHE_HOME on Linux and HOME on macOS).
// It returns a project directory to make requests from.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("HOME", dir)
	return t.TempDir()
}

func TestIssueConsume(t *testing.T) {
	cwd := isolate(t)
	req := Request{Args: []string{"commands", "allow", "make"}}

	if err := Consume(cwd, req); !errors.Is(err, ErrNoTicket) {
		t.Fatalf("Consume before Issue = %v, want ErrNoTicket", err)
	}
	if err := Issue(cwd, req); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := Consume(cwd, Request{Args: []string{"commands", "allow", "make"}}); err != nil {
		t.Fatalf("Consume after Issue: %v", err)
	}
	// Single use.
	if err := Consume(cwd, req); !errors.Is(err, ErrNoTicket) {
		t.Fatalf("second Consume = %v, want ErrNoTicket", err)
	}
}

func TestConsumeOtherArgs(t *testing.T) {
	cwd := isolate(t)
	if err := Issue(cwd, Request{Args: []string{"commands", "allow", "make"}}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"commands", "allow", "make", "--dir", "/"},
		{"commands", "allow"},
		{"commands allow make"},
		{"mode", "set", "open"},
	} {
		if err := Consume(cwd, Request{Args: args}); !errors.Is(err, ErrNoTicket) {
			t.Errorf("Consume(cwd, %q) = %v, want ErrNoTicket", args, err)
		}
	}
}

// TestTicketWorkingDirectory checks a ticket names the working directory it
// was issued from, however that directory is spelled: a symlink to the same
// directory finds it, another project with the same arguments does not.
func TestTicketWorkingDirectory(t *testing.T) {
	cwd := isolate(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(cwd, link); err != nil {
		t.Fatal(err)
	}
	req := Request{Args: []string{"commands", "allow", "make", "--dir", "."}}
	if err := Issue(cwd, req); err != nil {
		t.Fatal(err)
	}
	if err := Consume(t.TempDir(), req); !errors.Is(err, ErrNoTicket) {
		t.Fatalf("Consume from another project = %v, want ErrNoTicket", err)
	}
	if err := Consume(link, req); err != nil {
		t.Fatalf("Consume through a symlink to the same directory: %v", err)
	}
}

func TestValidate(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		wantErr string
	}{
		{args: nil, wantErr: "needs a subcommand"},
		{args: []string{"edit"}, wantErr: "interactive"},
		{args: []string{"-v", "edit"}, wantErr: "interactive"},
		{args: []string{"commands", "allow", "make"}},
		// "edit" as a value, not the subcommand.
		{args: []string{"commands", "allow", "edit"}},
	} {
		err := Request{Args: tc.args}.Validate()
		if tc.wantErr == "" {
			if err != nil {
				t.Errorf("Validate(%q) = %v, want nil", tc.args, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("Validate(%q) = %v, want error containing %q", tc.args, err, tc.wantErr)
		}
	}
}

func TestScopeSummary(t *testing.T) {
	for _, tc := range []struct {
		scope Scope
		want  string
	}{
		{Scope{PathsAllow: true}, "✓ read  ✗ write  ✗ internal  ✓ this project (~/p)  ✗ global"},
		{Scope{PathsAllow: true, Write: true, Internal: true}, "✓ read  ✓ write  ✓ internal  ✓ this project (~/p)  ✗ global"},
		{Scope{}, "✓ this project (~/p)  ✗ global"},
		{Scope{Global: true}, "✗ this project (~/p)  ✓ global"},
	} {
		if got := tc.scope.Summary("~/p"); got != tc.want {
			t.Errorf("%+v.Summary = %q, want %q", tc.scope, got, tc.want)
		}
	}
}

func TestCommand(t *testing.T) {
	got := Request{Args: []string{"paths", "allow", "~/my dir", "--write"}}.Command()
	want := "lite-sandbox config paths allow '~/my dir' --write"
	if got != want {
		t.Errorf("Command() = %q, want %q", got, want)
	}
}

func TestParse(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    []string // nil: not a config request
	}{
		{"lite-sandbox config commands allow make", []string{"commands", "allow", "make"}},
		{"/usr/local/bin/lite-sandbox config paths allow ~/.cache/foo --write", []string{"paths", "allow", "~/.cache/foo", "--write"}},
		{`lite-sandbox config commands allow "uv run pyright"`, []string{"commands", "allow", "uv run pyright"}},
		{"lite-sandbox config commands allow 'go generate'", []string{"commands", "allow", "go generate"}},
		{"lite-sandbox config profiles enable go --dir /srv/app", []string{"profiles", "enable", "go", "--dir", "/srv/app"}},
		{"  lite-sandbox config mode show  ", []string{"mode", "show"}},
		{"lite-sandbox config", []string{}},

		{"lite-sandbox version", nil},
		{"lite-sandbox --log-level debug config mode set open", nil},
		{"git config user.name", nil},
		{"echo lite-sandbox config", nil},
		{"lite-sandbox config commands allow make && rm -rf .", nil},
		{"lite-sandbox config commands allow make\nrm -rf .", nil},
		{"lite-sandbox config commands allow make; rm -rf .", nil},
		{"lite-sandbox config commands allow make || true", nil},
		{"lite-sandbox config commands allow make | tee x", nil},
		{"lite-sandbox config commands allow make > x", nil},
		{"lite-sandbox config commands allow make &", nil},
		{"! lite-sandbox config commands allow make", nil},
		{"X=1 lite-sandbox config commands allow make", nil},
		{"lite-sandbox config commands allow $X", nil},
		{"lite-sandbox config commands allow \"$X\"", nil},
		{"lite-sandbox config commands allow `id`", nil},
		{"lite-sandbox config commands allow $(id)", nil},
		{"lite-sandbox config commands allow $'a\\nb'", nil},
		{"lite-sandbox config paths allow *", nil},
		{"lite-sandbox config paths allow {a,b}", nil},
		{"lite-sandbox config paths allow a\\ b", nil},
		{"$BIN config commands allow make", nil},
		{"(lite-sandbox config commands allow make)", nil},
		{"lite-sandbox config commands allow 'make", nil},
	} {
		req, ok := Parse(tc.command)
		if tc.want == nil {
			if ok {
				t.Errorf("Parse(%q) = %q, want not a config request", tc.command, req.Args)
			}
			continue
		}
		if !ok || !slices.Equal(req.Args, tc.want) {
			t.Errorf("Parse(%q) = %q, %v; want %q", tc.command, req.Args, ok, tc.want)
		}
	}
}

func TestIsHelp(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want bool
	}{
		{[]string{"--help"}, true},
		{[]string{"-h"}, true},
		{[]string{"paths", "--help"}, true},
		{[]string{"paths", "allow", "-h"}, true},
		{[]string{"--help", "mode", "set", "open"}, true},

		{[]string{}, false},
		{[]string{"paths", "show"}, false},
		{[]string{"mode", "set", "open", "--dir", "--help"}, false},
		{[]string{"mode", "set", "open", "--help=false"}, false},
		{[]string{"mode", "set", "open", "--dir=.", "--help"}, false},
		{[]string{"paths", "allow", "/x", "--write", "-h"}, false},
		{[]string{"mode", "set", "open", "-hx"}, false},
		{[]string{"mode", "set", "open", "--", "--help"}, false},
		{[]string{"mode", "set", "", "--help"}, false},
	} {
		if got := (Request{Args: tc.args}).IsHelp(); got != tc.want {
			t.Errorf("IsHelp(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
}
