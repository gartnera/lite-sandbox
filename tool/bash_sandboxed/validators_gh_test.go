package bash_sandboxed

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"

	"github.com/gartnera/lite-sandbox/config"
)

func TestValidateGhArgs(t *testing.T) {
	tests := []struct {
		command    string
		allowToken bool
		allowGit   bool
		errSubstr  string // "" when allowed
	}{
		// Read-only and API invocations.
		{command: "gh"},
		{command: "gh --version"},
		{command: "gh --help"},
		{command: "gh pr list"},
		{command: "gh pr ls -R cli/cli --state open"},
		{command: "gh pr -R cli/cli view 123"},
		{command: "gh pr --repo=cli/cli view 123"},
		{command: "gh pr view"},
		{command: "gh pr status"},
		{command: "gh pr diff 12"},
		{command: "gh pr checks 12 --watch"},
		{command: `gh pr comment 12 --body "looks good"`},
		{command: "gh pr merge 12 --squash --auto"},
		{command: "gh pr merge 12 -s -d -R cli/cli"},
		{command: "gh pr close 12 --delete-branch --repo cli/cli"},
		{command: "gh pr close 12 -c done"},
		{command: "gh issue list"},
		{command: `gh issue create --title "Bug" --body "details"`},
		{command: "gh issue develop 12 --list"},
		{command: "gh issue develop -l 12"},
		{command: "gh run view 42 --log-failed"},
		{command: "gh workflow run ci.yml"},
		{command: "gh release create v1.0.0 --notes x"},
		{command: "gh release delete v1.0.0 --yes"},
		{command: "gh repo view cli/cli"},
		{command: "gh repo create my-repo --private"},
		{command: "gh repo create my-repo -h https://example.com --public"},
		{command: "gh repo fork cli/cli"},
		{command: "gh repo sync owner/fork"},
		{command: "gh repo sync owner/fork -b main --force"},
		{command: "gh search prs --author @me"},
		{command: "gh api /user"},
		{command: "gh api repos/cli/cli/pulls --paginate --jq '.[].title'"},
		{command: "gh auth status"},
		{command: "gh auth status -h github.com --active"},
		{command: "gh alias list"},
		{command: "gh config get git_protocol"},
		{command: "gh cs list"},
		{command: "gh gist view abc"},
		{command: "gh pr checkout --help"},

		// pr create: only with --head, which skips git.
		{command: "gh pr create --head my-branch --title t --body b"},
		{command: "gh pr create -H owner:branch -t t -b b -d"},
		{command: "gh pr create --head=my-branch --fill"},
		{command: "gh pr create --title t --body b", errSubstr: "without --head"},
		{command: "gh pr create -t t -b -H", errSubstr: "without --head"}, // -H is the body
		{command: "gh pr create -b-H -t t", errSubstr: "without --head"},
		{command: "gh pr create --bogus x --head b", errSubstr: "unknown flag --bogus"},

		// The token.
		{command: "gh auth token", errSubstr: "gh auth token is not allowed"},
		{command: "gh auth status --show-token", errSubstr: "prints the token"},
		{command: "gh auth status -at", errSubstr: "prints the token"},
		{command: "gh auth token", allowToken: true},
		{command: "gh auth status -t", allowToken: true},
		{command: "gh auth git-credential get", allowToken: true, errSubstr: "prints the token"},
		{command: "gh auth login --with-token", errSubstr: "changes gh's credentials"},
		{command: "gh auth refresh -s repo", errSubstr: "changes gh's credentials"},
		{command: "gh auth setup-git", errSubstr: "changes gh's credentials"},
		{command: "gh auth switch", errSubstr: "changes gh's credentials"},
		{command: "gh auth logout", errSubstr: "changes gh's credentials"},

		// Code that is not gh's.
		{command: "gh my-extension", errSubstr: "only gh's built-in commands"},
		{command: "gh co 12", errSubstr: "only gh's built-in commands"}, // a user alias
		{command: "gh extension install owner/gh-ext", errSubstr: "extensions are programs"},
		{command: "gh ext list", errSubstr: "extensions are programs"},
		{command: "gh copilot", errSubstr: "Copilot CLI"},
		{command: "gh alias set co 'pr checkout'", errSubstr: "only gh alias list"},
		{command: "gh config set editor vim", errSubstr: "only gh config get/list"},
		{command: "gh codespace ssh", errSubstr: "runs programs on this machine"},
		{command: "gh cs ports forward 8080:8080", errSubstr: "runs programs on this machine"},

		// Invocations that make gh run git.
		{command: "gh pr checkout 12", errSubstr: "allow_git true"},
		{command: "gh pr co 12", errSubstr: "allow_git true"},
		{command: "gh pr merge 12 --delete-branch", errSubstr: "without -R"},
		{command: "gh pr merge 12 -sd", errSubstr: "without -R"},
		{command: "gh pr close 12 -d", errSubstr: "without -R"},
		{command: "gh issue develop 12", errSubstr: "without --list"},
		{command: "gh issue develop 12 --checkout", errSubstr: "without --list"},
		{command: "gh issue develop 12 -n -l", errSubstr: "without --list"}, // -l is the name
		{command: "gh release delete v1 --cleanup-tag", errSubstr: "allow_git true"},
		{command: "gh repo clone cli/cli", errSubstr: "gh repo clone is not allowed"},
		{command: "gh repo create r --clone", errSubstr: "--clone is not allowed"},
		{command: "gh repo create r -c --private", errSubstr: "-c is not allowed"},
		{command: "gh repo create r --source=. --push", errSubstr: "is not allowed"},
		{command: "gh repo fork --remote", errSubstr: "--remote is not allowed"},
		{command: "gh repo fork cli/cli --clone", errSubstr: "--clone is not allowed"},
		{command: "gh repo sync", errSubstr: "without a destination repository"},
		{command: "gh repo sync --branch main", errSubstr: "without a destination repository"},
		{command: "gh gist clone abc", errSubstr: "gh gist clone is not allowed"},

		// allow_git lifts the refusals of the invocations that run git, and
		// only those.
		{command: "gh pr checkout 12", allowGit: true},
		{command: "gh pr create --title t --body b", allowGit: true},
		{command: "gh pr create --fill --some-new-flag", allowGit: true},
		{command: "gh pr merge 12 -sd", allowGit: true},
		{command: "gh issue develop 12 --checkout", allowGit: true},
		{command: "gh release delete v1 --cleanup-tag", allowGit: true},
		{command: "gh repo clone cli/cli", allowGit: true},
		{command: "gh repo create r --source=. --push", allowGit: true},
		{command: "gh repo fork --clone", allowGit: true},
		{command: "gh repo sync", allowGit: true},
		{command: "gh gist clone abc", allowGit: true},
		{command: "gh auth token", allowGit: true, errSubstr: "gh auth token is not allowed"},
		{command: "gh my-extension", allowGit: true, errSubstr: "only gh's built-in commands"},
		{command: "gh codespace ssh", allowGit: true, errSubstr: "runs programs on this machine"},

		// The command path must be unambiguous.
		{command: "gh -R cli/cli pr list", errSubstr: "put the command first"},
		{command: "gh pr --web view 12", errSubstr: "put the subcommand before"},
	}

	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatal(err)
			}
			args := f.Stmts[0].Cmd.(*syntax.CallExpr).Args
			err = validateGhArgs(args, ghOptions{allowToken: tt.allowToken, allowGit: tt.allowGit})
			if tt.errSubstr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.errSubstr) {
				t.Errorf("error = %v, want one containing %q", err, tt.errSubstr)
			}
		})
	}
}

// TestGhProfile_Validation: the gh profile whitelists gh with its validator,
// allow_token opens gh auth token, and the validator runs at the runtime layer
// on arguments known only after expansion.
func TestGhProfile_Validation(t *testing.T) {
	dir := t.TempDir()
	paths := []string{dir}
	validate := func(s *Sandbox, cmd string) error {
		return s.ValidateCommand(cmd, dir, paths, paths)
	}

	if err := validate(newTestSandbox(), "gh pr list"); err == nil || !strings.Contains(err.Error(), "profiles enable gh") {
		t.Errorf("gh without the profile should name it: %v", err)
	}
	on := newTestSandboxWithProfiles("gh")
	if err := validate(on, "gh pr list"); err != nil {
		t.Errorf("gh pr list with the profile: %v", err)
	}
	if err := validate(on, "gh auth token"); err == nil || !strings.Contains(err.Error(), "profiles set gh allow_token true") {
		t.Errorf("gh auth token should be refused with the option's name: %v", err)
	}
	token := newTestSandboxWithConfig(&config.Config{Profiles: []config.ProfileEntry{
		{Name: "gh", Options: map[string]bool{"allow_token": true}},
	}})
	if err := validate(token, "gh auth token"); err != nil {
		t.Errorf("gh auth token with allow_token: %v", err)
	}

	// Refused at runtime before anything runs, offline.
	_, err := on.Execute(context.Background(), "T=token; gh auth $T", dir, paths, paths)
	if err == nil || !strings.Contains(err.Error(), "gh auth token is not allowed") {
		t.Errorf("dynamically built gh auth token should be refused at runtime: %v", err)
	}
	_, err = on.Execute(context.Background(), `B="$(echo body)"; gh pr create --title t --body "$B"`, dir, paths, paths)
	if err == nil || !strings.Contains(err.Error(), "without --head") {
		t.Errorf("gh pr create without --head should be refused at runtime: %v", err)
	}
}

// TestGhAPIPaths: gh api's endpoint is not a file, and -F key=@file reads
// one, which is checked against the read set.
func TestGhAPIPaths(t *testing.T) {
	for _, tt := range []struct {
		args     []string
		endpoint int
		files    []string
	}{
		{[]string{"gh", "api", "/user"}, 2, nil},
		{[]string{"gh", "api", "-X", "POST", "/gists", "-F", "files[a][content]=@notes.md"}, 4, []string{"notes.md"}},
		{[]string{"gh", "api", "--field=x=@/etc/passwd", "--method", "POST", "/x"}, 5, []string{"/etc/passwd"}},
		{[]string{"gh", "api", "-Fx=@a", "-fy=@b", "-F", "z=@-", "/x"}, 6, []string{"a"}},
		{[]string{"gh", "api", "--jq", "/x", "--", "/y"}, 5, nil},
		{[]string{"gh", "pr", "list"}, -1, nil},
	} {
		endpoint, files := ghAPIPaths(tt.args)
		if endpoint != tt.endpoint || !slices.Equal(files, tt.files) {
			t.Errorf("ghAPIPaths(%q) = %d, %q; want %d, %q", tt.args, endpoint, files, tt.endpoint, tt.files)
		}
	}

	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.WriteFile(outside, []byte("oauth_token: x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestSandboxWithProfiles("gh")
	paths := []string{dir}
	if err := s.ValidateCommand("gh api /user", dir, paths, paths); err != nil {
		t.Errorf("gh api /user: %v", err)
	}
	for _, cmd := range []string{
		"gh api -X POST /gists -F files[a][content]=@" + outside,
		"gh api -X POST /gists --input " + outside,
		"gh gist create " + outside,
	} {
		if err := s.ValidateCommand(cmd, dir, paths, paths); err == nil || !strings.Contains(err.Error(), "outside allowed directories") {
			t.Errorf("%s: want a path boundary error, got %v", cmd, err)
		}
	}
	// Quoted, the field is known only after expansion: the runtime layer
	// refuses it before gh runs.
	_, err := s.Execute(context.Background(), "gh api -X POST /gists -F 'files[a][content]=@"+outside+"'", dir, paths, paths)
	if err == nil || !strings.Contains(err.Error(), "outside allowed directories") {
		t.Errorf("quoted field file: want a path boundary error, got %v", err)
	}
	if err := s.ValidateCommand("gh api -X POST /gists -F files[a][content]=@notes.md", dir, paths, paths); err != nil {
		t.Errorf("a field read from the working directory: %v", err)
	}
}

// TestOSSandboxGhProfile: with the gh profile on, gh runs in a worker of its
// own that reads its config dir and reaches the keyring (the session bus
// socket on Linux), while a program run in the shared worker, and a gh that
// program launches, see neither.
func TestOSSandboxGhProfile(t *testing.T) {
	requireOSSandbox(t)
	if runtime.GOOS != "linux" {
		t.Skip("the keyring check connects to a stand-in session bus socket")
	}
	work := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, "ls-gh-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	ghDir := filepath.Join(root, "gh-config")
	bin := filepath.Join(root, "bin")
	runDir := filepath.Join(root, "run")
	for _, d := range []string{ghDir, bin, runDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	hosts := filepath.Join(ghDir, "hosts.yml")
	if err := os.WriteFile(hosts, []byte("oauth_token: gho_s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bus := filepath.Join(runDir, "bus")
	l, err := net.Listen("unix", bus)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("keyring-ok\n"))
			c.Close()
		}
	}()
	// Reads what a unix socket sends. Not nc: Ubuntu 26.04 confines
	// nc.openbsd with an AppArmor profile that refuses connects from inside
	// any mount namespace ("Failed name lookup - disconnected path").
	busRead := `python3 -c 'import socket, sys; s = socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); sys.stdout.write(s.recv(64).decode())'`
	// A stand-in gh: prints the token in its config dir and what it reads
	// from the keyring socket.
	script := "#!/bin/sh\ncat \"$GH_CONFIG_DIR/hosts.yml\"\n" + busRead + " \"$XDG_RUNTIME_DIR/bus\"\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GH_CONFIG_DIR", ghDir)
	t.Setenv("XDG_RUNTIME_DIR", runDir)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+bus)

	yes := true
	s := NewSandbox()
	s.updateConfig(&config.Config{
		OSSandbox: &yes,
		Profiles:  []config.ProfileEntry{{Name: "gh"}},
		Commands:  []config.CommandEntry{{Command: "bash", Allow: &yes}}, // stands in for a program the agent runs
	}, work)
	defer s.Close()
	paths := []string{work}
	run := func(cmd string) (string, error) {
		return s.Execute(context.Background(), cmd, work, paths, paths)
	}

	out, err := run("gh pr list")
	if err != nil {
		t.Fatalf("gh in its own worker: %v\n%s", err, out)
	}
	if !strings.Contains(out, "gho_s3cret") || !strings.Contains(out, "keyring-ok") {
		t.Errorf("gh did not reach its token and the keyring: %q", out)
	}
	for _, cmd := range []string{
		"bash -c 'cat " + hosts + "'",
		`bash -c "` + busRead + ` ` + bus + `"`,
		"bash -c 'gh pr list'",
	} {
		if out, _ := run(cmd); strings.Contains(out, "gho_s3cret") || strings.Contains(out, "keyring-ok") {
			t.Errorf("%s: the shared worker reached gh's credentials: %q", cmd, out)
		}
	}
	if out, err := run("cat " + hosts); err == nil || strings.Contains(out, "gho_s3cret") {
		t.Errorf("the agent read gh's token: %v %q", err, out)
	}
}

// TestScopedGitEnv: a scoped worker's git gets the hardening entries after the
// server's own GIT_CONFIG_COUNT entries, and the server's own ssh, askpass,
// and editor settings are kept.
func TestScopedGitEnv(t *testing.T) {
	env := map[string]string{
		"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "user.name", "GIT_CONFIG_VALUE_0": "me",
		"GIT_SSH": "/opt/my ssh", "GIT_EDITOR": "vim",
	}
	scopedGitEnv(env, false)
	if env["GIT_CONFIG_KEY_0"] != "user.name" || env["GIT_CONFIG_VALUE_0"] != "me" {
		t.Errorf("the server's own config entry was overwritten: %v", env)
	}
	if env["GIT_CONFIG_KEY_1"] != "core.hooksPath" || env["GIT_CONFIG_VALUE_1"] != "/dev/null" {
		t.Errorf("hooksPath not appended after the server's entries: %v", env)
	}
	if got, want := env["GIT_CONFIG_COUNT"], strconv.Itoa(1+len(scopedGitConfig)+len(scopedGitSigningOff)); got != want {
		t.Errorf("GIT_CONFIG_COUNT = %s, want %s", got, want)
	}
	// A worker whose git signs leaves signing as the user set it.
	signing := map[string]string{}
	scopedGitEnv(signing, true)
	for k, v := range signing {
		if strings.HasPrefix(k, "GIT_CONFIG_KEY_") && strings.HasSuffix(v, "gpgSign") {
			t.Errorf("signing worker sets %s", v)
		}
	}
	if env["GIT_SSH_COMMAND"] != `'/opt/my ssh'` {
		t.Errorf("GIT_SSH_COMMAND = %q, want the server's GIT_SSH, quoted", env["GIT_SSH_COMMAND"])
	}
	if env["GIT_EDITOR"] != "vim" || env["GIT_ASKPASS"] != "true" || env["GIT_PAGER"] != "cat" {
		t.Errorf("editor/askpass/pager = %q/%q/%q", env["GIT_EDITOR"], env["GIT_ASKPASS"], env["GIT_PAGER"])
	}
}

// TestOSSandboxScopedGitHardening: a git that a scoped CLI starts runs no hook
// or fsmonitor the project's .git configures, even with allow_git on.
func TestOSSandboxScopedGitHardening(t *testing.T) {
	requireOSSandbox(t)
	work := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, "ls-gh-git-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	ghDir := filepath.Join(root, "gh-config")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{ghDir, bin} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	gitRun := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", work, "-c", "user.email=a@b", "-c", "user.name=a"}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	gitRun("init", "-q")
	gitRun("commit", "-q", "--allow-empty", "-m", "init")
	// What a credential stealer would plant: each appends to pwned.
	pwned := filepath.Join(work, "pwned")
	hook := filepath.Join(work, ".git", "hooks", "post-checkout")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\necho hook >> "+pwned+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	gitRun("config", "core.fsmonitor", "echo fsmonitor >> "+pwned)
	gitRun("config", "credential.helper", "!echo helper >> "+pwned)
	// A stand-in gh that, like gh pr checkout, runs git.
	script := "#!/bin/sh\ngit checkout -q -b from-gh && git status --porcelain >/dev/null && echo ran\n"
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GH_CONFIG_DIR", ghDir)

	yes := true
	s := NewSandbox()
	s.updateConfig(&config.Config{
		OSSandbox: &yes,
		Profiles:  []config.ProfileEntry{{Name: "gh", Options: map[string]bool{"allow_git": true}}},
	}, work)
	defer s.Close()
	out, err := s.Execute(context.Background(), "gh pr checkout 12", work, []string{work}, []string{work})
	if err != nil || !strings.Contains(out, "ran") {
		t.Fatalf("gh pr checkout with allow_git: %v\n%s", err, out)
	}
	if b, err := os.ReadFile(pwned); err == nil {
		t.Errorf("git in gh's worker ran the project's configured code: %q", b)
	}
}
