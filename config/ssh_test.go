package config

import (
	"slices"
	"testing"
)

func TestSSHConfigAccessors(t *testing.T) {
	var none *SSHConfig
	if none.HostsConfigured() || none.AgentEnabled() || none.AgentUnrestricted() || none.AllowsHost("a") {
		t.Fatal("a missing ssh section must allow nothing")
	}
	no := false
	s := &SSHConfig{Hosts: []string{"Build-Box", "[::1]"}}
	if !s.HostsConfigured() || !s.AgentEnabled() || s.AgentUnrestricted() {
		t.Fatalf("defaults wrong: %+v", s)
	}
	for _, h := range []string{"build-box", "BUILD-BOX", "::1", "[::1]"} {
		if !s.AllowsHost(h) {
			t.Errorf("AllowsHost(%q) = false", h)
		}
	}
	for _, h := range []string{"", "build", "build-box.example.com", "evil"} {
		if s.AllowsHost(h) {
			t.Errorf("AllowsHost(%q) = true", h)
		}
	}
	s.Agent = &no
	if s.AgentEnabled() {
		t.Error("agent: false must turn the agent off")
	}
}

func TestParseRejectsBadSSHHosts(t *testing.T) {
	for _, h := range []string{"user@host", "-oProxyCommand=x", "a b", "*.example.com", "host/x", "a,b"} {
		if _, err := Parse([]byte("ssh:\n  hosts: ['" + h + "']\n")); err == nil {
			t.Errorf("hosts entry %q accepted", h)
		}
	}
	cfg, err := Parse([]byte("ssh:\n  hosts: [build-box, 10.0.0.12]\n  unrestricted_agent: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SSH.AllowsHost("10.0.0.12") || !cfg.SSH.AgentUnrestricted() {
		t.Fatalf("parsed %+v", cfg.SSH)
	}
	if _, err := Parse([]byte("overrides:\n  - path: /x\n    ssh:\n      hosts: [a@b]\n")); err == nil {
		t.Error("bad host in an override accepted")
	}
}

func TestAddRemoveSSHHost(t *testing.T) {
	c := &Config{}
	if added, err := c.AddSSHHost("box"); err != nil || !added {
		t.Fatalf("AddSSHHost = %v, %v", added, err)
	}
	if added, _ := c.AddSSHHost("BOX"); added {
		t.Error("duplicate host added")
	}
	if _, err := c.AddSSHHost("me@box"); err == nil {
		t.Error("user@host accepted")
	}
	if !c.RemoveSSHHost("Box") || c.SSH.Hosts != nil {
		t.Errorf("RemoveSSHHost left %v", c.SSH.Hosts)
	}
	if c.RemoveSSHHost("box") {
		t.Error("removed a host twice")
	}
}

func TestWithSSHAgentScopesTheSocket(t *testing.T) {
	c := (&Config{SSH: &SSHConfig{Hosts: []string{"box"}}}).Effective()
	got := c.WithSSHAgent("/run/agent.sock")
	if got == c {
		t.Fatal("agent grant not added")
	}
	if len(c.Paths) != 0 {
		t.Fatal("WithSSHAgent changed its receiver")
	}
	scope, ok := got.ScopeForCommand("ssh")
	if !ok || !slices.Equal(scope.Commands, []string{"git", "ssh", "sshpass"}) {
		t.Fatalf("scope = %+v, %v", scope, ok)
	}
	denied := got.ScopedDeniedReadEntries()
	if len(denied) != 1 || denied[0].Path != "/run/agent.sock" {
		t.Errorf("shared worker would not hide the socket: %+v", denied)
	}
	if paths := got.ForScope(scope).ExpandedInternalReadablePaths(); !slices.Contains(paths, "/run/agent.sock") {
		t.Errorf("the scope's worker would not get the socket: %v", paths)
	}

	gitOnly := (&Config{SSH: &SSHConfig{}}).WithSSHAgent("/run/agent.sock")
	if _, ok := gitOnly.ScopeForCommand("ssh"); ok {
		t.Error("ssh got the agent with no hosts listed")
	}
	if _, ok := gitOnly.ScopeForCommand("git"); !ok {
		t.Error("git did not get the agent")
	}

	no := false
	off := &Config{SSH: &SSHConfig{Agent: &no}}
	if off.WithSSHAgent("/run/agent.sock") != off {
		t.Error("agent: false still granted the socket")
	}
	if c.WithSSHAgent("") != c {
		t.Error("no socket still granted something")
	}
	if (&Config{}).WithSSHAgent("/run/agent.sock").SSH != nil {
		t.Error("no ssh section still granted something")
	}
}
