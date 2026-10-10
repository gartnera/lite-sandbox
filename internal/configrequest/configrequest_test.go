package configrequest

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

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
		{args: []string{"--dir", "/srv", "edit"}, wantErr: "interactive"},
		{args: []string{"commands", "allow", "make"}},
		// "edit" as a value, not the subcommand.
		{args: []string{"commands", "allow", "edit"}},
		{args: []string{"--dir", "edit", "show"}},
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

func TestScope(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "work", "proj")
	for _, tc := range []struct {
		args    []string
		want    []string // nil: want an error
		wantErr string
	}{
		// No --dir: scoped to cwd.
		{args: []string{"commands", "allow", "make"}, want: []string{"--dir", cwd, "commands", "allow", "make"}},
		// A --dir at or under cwd is kept, as the absolute directory it names.
		{args: []string{"commands", "allow", "make", "--dir", "."}, want: []string{"commands", "allow", "make", "--dir", cwd}},
		{args: []string{"--dir", "sub/dir", "show"}, want: []string{"--dir", filepath.Join(cwd, "sub", "dir"), "show"}},
		{args: []string{"--dir=" + cwd + "/", "show"}, want: []string{"--dir=" + cwd, "show"}},
		{args: []string{"--dir=x", "show"}, want: []string{"--dir=" + filepath.Join(cwd, "x"), "show"}},
		{args: []string{"show", "--dir", "~/work/proj/x"}, want: []string{"show", "--dir", filepath.Join(cwd, "x")}},
		// "--dir" after "--" is positional.
		{args: []string{"paths", "allow", "--", "--dir"}, want: []string{"--dir", cwd, "paths", "allow", "--", "--dir"}},
		// Anywhere else is refused.
		{args: []string{"--dir", "/", "mode", "set", "open"}, wantErr: "outside the working directory"},
		{args: []string{"--dir", "~", "mode", "set", "open"}, wantErr: "outside the working directory"},
		{args: []string{"--dir", "..", "mode", "set", "open"}, wantErr: "outside the working directory"},
		{args: []string{"--dir", "../proj-other", "show"}, wantErr: "outside the working directory"},
		{args: []string{"--dir", "sub/../../x", "show"}, wantErr: "outside the working directory"},
		{args: []string{"--dir=/etc", "show"}, wantErr: "outside the working directory"},
		{args: []string{"--dir", ".", "show", "--dir", "/"}, wantErr: "outside the working directory"},
		{args: []string{"--dir=", "mode", "set", "open"}, wantErr: "needs a directory"},
		{args: []string{"--dir", "", "mode", "set", "open"}, wantErr: "needs a directory"},
		{args: []string{"show", "--dir"}, wantErr: "needs a directory"},
	} {
		got, err := Request{Args: tc.args}.Scope(cwd)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Scope(%q) = %q, %v; want error containing %q", tc.args, got.Args, err, tc.wantErr)
			}
			continue
		}
		if err != nil || !slices.Equal(got.Args, tc.want) {
			t.Errorf("Scope(%q) = %q, %v; want %q", tc.args, got.Args, err, tc.want)
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
