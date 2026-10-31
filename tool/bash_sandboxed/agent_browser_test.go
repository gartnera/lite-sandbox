package bash_sandboxed

import (
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// TestAgentBrowserSocketEnv checks every agent-browser the sandbox runs is
// pointed at lite-sandbox's own daemons, overriding a socket directory in the
// environment (the user's), and that other commands are left alone.
func TestAgentBrowserSocketEnv(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	want := config.AgentBrowserSocketDir()
	for _, argv0 := range []string{"agent-browser", "/usr/local/bin/agent-browser"} {
		env := map[string]string{"AGENT_BROWSER_SOCKET_DIR": "/run/user/1000/agent-browser"}
		agentBrowserSocketEnv([]string{argv0, "open", "example.com"}, env)
		if got := env["AGENT_BROWSER_SOCKET_DIR"]; got != want {
			t.Errorf("%s: AGENT_BROWSER_SOCKET_DIR = %q, want %q", argv0, got, want)
		}
	}
	env := map[string]string{}
	agentBrowserSocketEnv([]string{"ls", "agent-browser"}, env)
	if _, ok := env["AGENT_BROWSER_SOCKET_DIR"]; ok {
		t.Error("AGENT_BROWSER_SOCKET_DIR set for a command other than agent-browser")
	}
}

// TestAgentBrowserWorkerEnv checks an agent-browser in an OS sandbox worker
// on macOS gets $CI, so it launches Chrome with --no-sandbox (Chrome's own
// Seatbelt sandbox can't nest in the worker's), keeping a $CI already set,
// and that other commands and other platforms are left alone.
func TestAgentBrowserWorkerEnv(t *testing.T) {
	for _, argv0 := range []string{"agent-browser", "/opt/homebrew/bin/agent-browser"} {
		env := map[string]string{}
		agentBrowserWorkerEnvFor("darwin", []string{argv0, "open", "example.com"}, env)
		if got := env["CI"]; got != "1" {
			t.Errorf("%s on darwin: CI = %q, want \"1\"", argv0, got)
		}
	}
	env := map[string]string{"CI": "true"}
	agentBrowserWorkerEnvFor("darwin", []string{"agent-browser", "open"}, env)
	if got := env["CI"]; got != "true" {
		t.Errorf("CI already set: CI = %q, want it kept as \"true\"", got)
	}
	for _, c := range []struct {
		goos string
		args []string
	}{
		{"linux", []string{"agent-browser", "open"}},
		{"darwin", []string{"ls", "agent-browser"}},
		{"darwin", nil},
	} {
		env := map[string]string{}
		agentBrowserWorkerEnvFor(c.goos, c.args, env)
		if _, ok := env["CI"]; ok {
			t.Errorf("%s %v: CI set", c.goos, c.args)
		}
	}
}
