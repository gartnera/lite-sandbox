package config

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSSHConfigAccessors(t *testing.T) {
	var none *SSHConfig
	if none.HostsConfigured() || none.AgentEnabled() || none.AgentUnrestricted() || none.AllowsHost("a") {
		t.Fatal("a missing ssh section must allow nothing")
	}
	no := false
	s := &SSHConfig{Hosts: []SSHHost{{Host: "Build-Box"}, {Host: "[::1]"}}}
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
	if added, err := c.AddSSHHost("box", false); err != nil || !added {
		t.Fatalf("AddSSHHost = %v, %v", added, err)
	}
	if added, _ := c.AddSSHHost("BOX", false); added {
		t.Error("duplicate host added")
	}
	if _, err := c.AddSSHHost("me@box", false); err == nil {
		t.Error("user@host accepted")
	}
	if !c.RemoveSSHHost("Box") || c.SSH.Hosts != nil {
		t.Errorf("RemoveSSHHost left %v", c.SSH.Hosts)
	}
	if c.RemoveSSHHost("box") {
		t.Error("removed a host twice")
	}
}

func TestAddSSHHostOptions(t *testing.T) {
	c := &Config{}
	if changed, err := c.AddSSHHost("box", false, "systemctl  restart"); err != nil || !changed {
		t.Fatalf("AddSSHHost = %v, %v", changed, err)
	}
	if changed, _ := c.AddSSHHost("BOX", false, "systemctl restart"); changed {
		t.Error("a command already listed changed the entry")
	}
	if changed, _ := c.AddSSHHost("box", true, "docker ps"); !changed {
		t.Error("write and a new command did not change the entry")
	}
	h := c.SSH.Host("box")
	if !h.Writes() || !slices.Equal(h.Commands, []string{"systemctl  restart", "docker ps"}) {
		t.Fatalf("entry = %+v", h)
	}
	if changed, _ := c.AddSSHHost("box", false); changed {
		t.Error("adding a listed host without options changed it")
	}
	for _, bad := range []string{"", "-x", "/bin/rm", "$X", "a;b"} {
		if _, err := c.AddSSHHost("other", false, bad); err == nil {
			t.Errorf("commands entry %q accepted", bad)
		}
	}
}

func TestSSHHostEntryForms(t *testing.T) {
	src := `ssh:
  hosts:
    - build-box
    - host: deploy-box
      commands: [systemctl restart, docker ps]
    - host: scratch-vm
      write: true
`
	cfg, err := ParseStrict([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	hosts := cfg.SSH.Hosts
	if len(hosts) != 3 || hosts[0].Host != "build-box" || hosts[0].Writes() || len(hosts[0].Commands) != 0 {
		t.Fatalf("bare entry: %+v", hosts)
	}
	if hosts[1].Host != "deploy-box" || !slices.Equal(hosts[1].Commands, []string{"systemctl restart", "docker ps"}) {
		t.Errorf("commands entry: %+v", hosts[1])
	}
	if !hosts[2].Writes() || !cfg.SSH.AllowsHost("Scratch-VM") {
		t.Errorf("write entry: %+v", hosts[2])
	}
	out, err := yaml.Marshal(cfg.SSH)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "- build-box\n") || !strings.Contains(string(out), "host: scratch-vm") {
		t.Errorf("marshaled:\n%s", out)
	}

	for name, bad := range map[string]string{
		"listed twice": "ssh:\n  hosts: [box, {host: BOX, write: true}]\n",
		"unknown key":  "ssh:\n  hosts:\n    - host: box\n      command: [ls]\n",
		"bad command":  "ssh:\n  hosts:\n    - host: box\n      commands: ['rm;ls']\n",
		"override key": "overrides:\n  - path: /x\n    ssh:\n      hosts:\n        - {host: box, writes: true}\n",
		"missing host": "ssh:\n  hosts:\n    - write: true\n",
	} {
		if _, err := ParseStrict([]byte(bad)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSSHHostsMergePerEntry(t *testing.T) {
	src := `ssh:
  hosts:
    - build-box
    - host: deploy-box
      commands: [systemctl restart]
overrides:
  - path: /work
    merge: true
    ssh:
      hosts:
        - host: build-box
          write: true
        - extra-box
`
	cfg, err := ParseStrict([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.ForDirectory("/work").SSH
	if h := s.Host("build-box"); h == nil || !h.Writes() {
		t.Errorf("build-box not restated by the override: %+v", s.Hosts)
	}
	if h := s.Host("deploy-box"); h == nil || len(h.Commands) != 1 {
		t.Errorf("deploy-box dropped by the merge: %+v", s.Hosts)
	}
	if !s.AllowsHost("extra-box") {
		t.Errorf("extra-box not added: %+v", s.Hosts)
	}
	if h := cfg.ForDirectory("/elsewhere").SSH.Host("build-box"); h == nil || h.Writes() {
		t.Errorf("the override applied outside its path: %+v", h)
	}
}

func TestWithSSHAgentScopesTheSocket(t *testing.T) {
	c := (&Config{SSH: &SSHConfig{Hosts: []SSHHost{{Host: "box"}}}}).Effective()
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
