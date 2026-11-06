package bash_sandboxed

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

func TestIsServerOnlyHostEnv(t *testing.T) {
	for _, name := range []string{
		"HOME", "PATH", "NODE_OPTIONS", "GIT_CONFIG_COUNT", "GIT_SSH_COMMAND",
		"PYTHONPATH", "PYTHONSTARTUP", "PERL5OPT", "RUBYOPT", "LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES", "BASH_ENV", "ZDOTDIR", "BASH_FUNC_ls%%",
		"XDG_CONFIG_HOME", "npm_config_script_shell", "NPM_CONFIG_USERCONFIG",
		"CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER", "KUBECONFIG", "LESSOPEN",
		"GH_BROWSER", "GH_CONFIG_DIR", "GOCACHEPROG", "PKG_CONFIG", "DEVELOPER_DIR",
		"GIT_PAGER", "GIT_TRACE",
	} {
		if !isServerOnlyHostEnv(name) {
			t.Errorf("%s: expected the server's value for no_sandbox commands", name)
		}
	}
	for _, name := range []string{
		"FOO", "GOOS", "CGO_ENABLED", "AWS_PROFILE", "TERM", "LANG",
		"GIT_AUTHOR_NAME", "GIT_COMMITTER_DATE", "GIT_TERMINAL_PROMPT", "CARGO_TERM_COLOR", "CARGO_INCREMENTAL",
	} {
		if isServerOnlyHostEnv(name) {
			t.Errorf("%s: expected the agent's value to be kept", name)
		}
	}
}

func TestServerPath(t *testing.T) {
	t.Setenv("PATH", ":/usr/bin:bin:.:/bin:")
	if got := serverPath(); got != "/usr/bin:/bin" {
		t.Errorf("serverPath() = %q, want only the absolute entries", got)
	}
}

func TestCheckHostEnvAssigns(t *testing.T) {
	for _, tc := range []struct {
		args []string
		ok   bool
	}{
		{[]string{"git", "status"}, true},
		{[]string{"env", "FOO=1", "git", "status"}, true},
		{[]string{"env", "-u", "FOO", "git", "status"}, true},
		{[]string{"env", "-C", "/tmp", "git", "status"}, false}, // refused by the wrapper spec
		{[]string{"env", "HOME=/x", "git", "status"}, false},
		{[]string{"timeout", "5", "env", "-u", "X", "GIT_DIR=/x", "git", "status"}, false},
		{[]string{"env", "FOO=1", "env", "NODE_OPTIONS=--require=x", "node"}, false},
		{[]string{"env", "-P", "./bin", "git", "status"}, false},
		{[]string{"env", "-iP./bin", "git", "status"}, false},
		{[]string{"xargs", "-I", "X", "env", "X=/x", "git", "status"}, false},
		{[]string{"xargs", "-I", "X", "git", "X"}, true},
		{[]string{"env", "-u", "GIT_CONFIG_COUNT", "git", "status"}, false},
		{[]string{"env", "-uGIT_CONFIG_COUNT", "git", "status"}, false},
		{[]string{"timeout", "5", "env", "--unset=HOME", "git", "status"}, false},
		{[]string{"env", "--unset", "HOME", "git", "status"}, false},
		{[]string{"env", "-i", "git", "status"}, false},
		{[]string{"env", "-", "git", "status"}, false},
		{[]string{"env", "--ignore-environment", "git", "status"}, false},
		{[]string{"env", "-a", "-P", "git", "status"}, true}, // -P is -a's value
	} {
		err := checkHostEnvAssigns(tc.args)
		if (err == nil) != tc.ok {
			t.Errorf("%v: err %v, want ok=%v", tc.args, err, tc.ok)
		}
	}
}

func TestCheckHostEnv(t *testing.T) {
	t.Setenv("HOME", "/h")
	t.Setenv("PATH", "/bin")
	t.Setenv("GIT_CONFIG_COUNT", "1")
	t.Setenv("GIT_TOKEN", "secret")
	t.Setenv("NODE_OPTIONS", "")
	os.Unsetenv("NODE_OPTIONS")
	server := envSliceToMap(os.Environ())
	delete(server, "GIT_TOKEN") // as the OS sandbox scrubs it
	with := func(k, v string) map[string]string {
		m := map[string]string{}
		for a, b := range server {
			m[a] = b
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for _, tc := range []struct {
		name string
		env  map[string]string
		ok   bool
	}{
		{"server's", server, true},
		{"other variables", with("GOOS", "linux"), true},
		{"exempt git identity", with("GIT_AUTHOR_NAME", "bot"), true},
		{"credential kept", with("GIT_TOKEN", "secret"), true},
		{"credential scrubbed", with("GIT_TOKEN", ""), true},
		{"changed", with("HOME", "/agent"), false},
		{"set", with("NODE_OPTIONS", "--require=x"), false},
		{"credential changed", with("GIT_TOKEN", "agent"), false},
		{"unset", with("GIT_CONFIG_COUNT", ""), false},
	} {
		err := checkHostEnv(tc.env)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v, want ok=%v", tc.name, err, tc.ok)
		}
	}
}

// newHostEnvSandbox returns a sandbox (OS sandbox off) that allows printenv
// with no_sandbox and, sandboxed, timeout and env.
func newHostEnvSandbox(t *testing.T, work string, extra ...config.CommandEntry) *Sandbox {
	t.Helper()
	yes := true
	entries := append([]config.CommandEntry{
		{Command: "printenv", Allow: &yes, NoSandbox: true},
	}, extra...)
	s := NewSandbox()
	s.updateConfig(&config.Config{Commands: entries}, work)
	t.Cleanup(func() { s.Close() })
	return s
}

func TestNoSandboxCommandRefusesAgentEnv(t *testing.T) {
	work := t.TempDir()
	t.Setenv("HOME", "/server/home")
	t.Setenv("NODE_OPTIONS", "--server")
	t.Setenv("GIT_CONFIG_COUNT", "")
	os.Unsetenv("GIT_CONFIG_COUNT") // restored by t.Setenv
	s := newHostEnvSandbox(t, work)
	paths := []string{work}
	run := func(cmd string) (string, error) {
		return s.Execute(context.Background(), cmd, work, paths, paths)
	}

	// The agent changing a listed variable: an inline assignment, an export,
	// a name only known at runtime, under a wrapper, through env,
	// and through env under xargs -I.
	for _, cmd := range []string{
		`HOME=/agent printenv HOME`,
		`export NODE_OPTIONS=--require=./x.js; printenv NODE_OPTIONS`,
		`n=GIT_CONFIG_COUNT; export "$n=1"; printenv GIT_CONFIG_COUNT`,
		`HOME=/agent timeout 5 printenv HOME`,
		`env HOME=/agent printenv HOME`,
		`echo HOME | xargs -I X env X=/agent printenv HOME`,
	} {
		out, err := run(cmd)
		if err == nil || strings.Contains(out, "/agent") || strings.Contains(out, "x.js") || strings.TrimSpace(out) == "1" {
			t.Errorf("%s: expected a refusal, got %v %q", cmd, err, out)
		}
	}

	// The server's values, and other variables, are fine.
	for _, tc := range []struct{ cmd, want string }{
		{`printenv HOME`, "/server/home"},
		{`HOME=/server/home printenv HOME`, "/server/home"},
		{`FOO=agent printenv FOO`, "agent"},
		{`GIT_AUTHOR_NAME=bot printenv GIT_AUTHOR_NAME`, "bot"},
		{`export FOO=agent; timeout 5 printenv FOO`, "agent"},
	} {
		out, err := run(tc.cmd)
		if err != nil || strings.TrimSpace(out) != tc.want {
			t.Errorf("%s: got %v %q, want %q", tc.cmd, err, out, tc.want)
		}
	}
}

// TestNoSandboxLooksUpInServerPath: a PATH the agent changes at runtime
// is refused (by checkHostEnv), so its directory is never searched.
func TestNoSandboxLooksUpInServerPath(t *testing.T) {
	work := t.TempDir()
	bin := filepath.Join(work, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(work, "hijacked")
	if err := os.WriteFile(filepath.Join(bin, "printenv"), []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	s := newHostEnvSandbox(t, work)
	paths := []string{work}
	out, err := s.Execute(context.Background(), `n=PATH; export "$n=$PWD/bin:$PATH"; printenv HOME`, work, paths, paths)
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatalf("the agent's PATH picked the no_sandbox command (err %v, out %q)", err, out)
	}
	if err == nil {
		t.Errorf("expected a refusal, got %q", out)
	}
}

func TestNoSandboxEmptyServerPath(t *testing.T) {
	work := t.TempDir()
	t.Setenv("PATH", "")
	s := newHostEnvSandbox(t, work)
	paths := []string{work}
	if out, err := s.Execute(context.Background(), `printenv HOME`, work, paths, paths); err == nil {
		t.Errorf("expected a refusal with an empty server PATH, got %q", out)
	}
}

// TestNoSandboxRsyncKeepsHomeStripped: restrictCommandEnv still drops HOME
// for rsync after the check (popt reads ~/.popt).
func TestNoSandboxRsyncKeepsHomeStripped(t *testing.T) {
	t.Setenv("HOME", "/h")
	env := envSliceToMap(os.Environ())
	if err := checkHostEnv(env); err != nil {
		t.Fatal(err)
	}
	restrictCommandEnv([]string{"rsync", "a", "b"}, env)
	if _, ok := env["HOME"]; ok {
		t.Errorf("rsync kept HOME: %v", env)
	}
}

func TestSandboxedCommandKeepsAgentEnv(t *testing.T) {
	work := t.TempDir()
	t.Setenv("HOME", "/server/home")
	s := NewSandbox()
	s.updateConfig(&config.Config{ExtraCommands: []string{"printenv"}}, work)
	t.Cleanup(func() { s.Close() })
	out, err := s.Execute(context.Background(), `HOME=/agent printenv HOME`, work, []string{work}, []string{work})
	if err != nil {
		t.Fatalf("%v %q", err, out)
	}
	if strings.TrimSpace(out) != "/agent" {
		t.Errorf("a sandboxed command keeps the agent's HOME, got %q", out)
	}
}

func TestNoSandboxScriptEnv(t *testing.T) {
	work := t.TempDir()
	t.Setenv("HOME", "/server/home")
	t.Setenv("NODE_OPTIONS", "--server")
	script := "#!/bin/bash\nprintenv HOME\nprintenv NODE_OPTIONS\nexport NODE_OPTIONS=--script HOME=/script\nprintenv NODE_OPTIONS\nprintenv HOME\n"
	if err := os.WriteFile(filepath.Join(work, "s.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	yes := true
	s := newHostEnvSandbox(t, work, config.CommandEntry{Command: "./s.sh", Allow: &yes, NoSandbox: true})
	paths := []string{work}
	for _, cmd := range []string{`./s.sh`, `bash ./s.sh`, `FOO=1 ./s.sh`} {
		out, err := s.Execute(context.Background(), cmd, work, paths, paths)
		if err != nil {
			t.Fatalf("%s: %v %q", cmd, err, out)
		}
		// The script starts from the server's values and keeps what it sets.
		if got, want := strings.Join(strings.Fields(out), " "), "/server/home --server --script /script"; got != want {
			t.Errorf("%s: got %q, want %q", cmd, got, want)
		}
	}
	for _, cmd := range []string{
		`HOME=/agent ./s.sh`,
		`export NODE_OPTIONS=--agent; bash ./s.sh`,
		`HOME=/agent timeout 5 ./s.sh`,
	} {
		out, err := s.Execute(context.Background(), cmd, work, paths, paths)
		if err == nil || strings.Contains(out, "/server/home") {
			t.Errorf("%s: expected a refusal before the script runs, got %v %q", cmd, err, out)
		}
	}
}

// TestNoSandboxGitIgnoresAgentHome is the issue's reproduction: git allowed
// with no_sandbox must not read a .gitconfig the agent points HOME at.
func TestNoSandboxGitIgnoresAgentHome(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	work := t.TempDir()
	if out, err := exec.Command("git", "-C", work, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	marker := filepath.Join(work, "pwned")
	yes := true
	s := NewSandbox()
	s.updateConfig(&config.Config{Commands: []config.CommandEntry{
		{Command: "git", Allow: &yes, NoSandbox: true},
	}}, work)
	t.Cleanup(func() { s.Close() })
	paths := []string{work}
	cmd := `mkdir -p h && printf '[core]\n\tfsmonitor = touch ` + marker + `\n' > h/.gitconfig && HOME=$PWD/h git status`
	out, err := s.Execute(context.Background(), cmd, work, paths, paths)
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatalf("git ran the fsmonitor from the agent's HOME on the host (err %v, output %q)", err, out)
	}
}

// TestNoSandboxEnvAuditedInOpenMode: open mode only audits, as for every
// other runtime rule.
func TestNoSandboxEnvAuditedInOpenMode(t *testing.T) {
	work := t.TempDir()
	t.Setenv("HOME", "/server/home")
	yes := true
	s := NewSandbox()
	s.updateConfig(&config.Config{Mode: string(config.ModeOpen), Commands: []config.CommandEntry{
		{Command: "printenv", Allow: &yes, NoSandbox: true},
	}}, work)
	t.Cleanup(func() { s.Close() })
	out, err := s.Execute(context.Background(), `HOME=/agent printenv HOME`, work, []string{work}, []string{work})
	if err != nil || strings.TrimSpace(out) != "/agent" {
		t.Errorf("open mode: got %v %q, want the command to run", err, out)
	}
}
