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
