package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// SSHConfig controls ssh access: the hosts ssh and sshpass may connect to,
// and how the user's ssh agent reaches ssh, sshpass, and the ssh that git's
// remote commands (fetch, pull, push, clone, ...) start.
//
//	ssh:
//	  hosts:                     # ssh/sshpass may connect to these, as typed
//	    - build-box              # (an alias of ~/.ssh/config, or a host name)
//	    - 10.0.0.12
//	  agent: true                # default true once the section exists
//	  unrestricted_agent: false  # default false: the agent goes through a filter
//
// The agent, when on, is given to those commands alone: they run in an OS
// sandbox worker of their own (a command scope, see CommandScope) that can
// reach it, while every other worker masks it. By default that is a filtering
// proxy in front of the real agent (internal/sshagent), which lists keys and
// signs with them but refuses everything else: adding, removing, or locking
// keys, other extensions, and use over a forwarded connection.
// unrestricted_agent hands those commands the real socket instead.
type SSHConfig struct {
	Hosts []string `yaml:"hosts,omitempty"`
	// Agent gives ssh, sshpass, and git's remote commands the ssh agent
	// (default true when the section is present).
	Agent *bool `yaml:"agent,omitempty"`
	// UnrestrictedAgent gives them the real agent socket rather than the
	// filtering proxy (default false).
	UnrestrictedAgent *bool `yaml:"unrestricted_agent,omitempty"`
}

// SSHCommands are the commands the ssh section whitelists once it lists a
// host. sshpass is only allowed to run ssh.
var SSHCommands = []string{"ssh", "sshpass"}

// SSHAgentCommands returns the commands that get the ssh agent: git, whose
// remote commands start ssh (only those are routed to the agent's worker; see
// the sandbox's scopedInvocation), and ssh and sshpass once hosts are listed —
// without hosts their host check does not run (denylist mode still runs them),
// so they do not get the agent either.
func (s *SSHConfig) SSHAgentCommands() []string {
	if s.HostsConfigured() {
		return []string{"git", "ssh", "sshpass"}
	}
	return []string{"git"}
}

// HostsConfigured reports whether ssh and sshpass are allowed: the section
// lists at least one host.
func (s *SSHConfig) HostsConfigured() bool {
	return s != nil && len(s.Hosts) > 0
}

// AllowsHost reports whether host, as given on the command line (without
// user@ or :port), is one of the listed hosts. Matching is exact and
// case-insensitive, as ssh's own Host matching is; IPv6 brackets are ignored.
func (s *SSHConfig) AllowsHost(host string) bool {
	if s == nil {
		return false
	}
	host = normalizeSSHHost(host)
	if host == "" {
		return false
	}
	for _, h := range s.Hosts {
		if normalizeSSHHost(h) == host {
			return true
		}
	}
	return false
}

func normalizeSSHHost(h string) string {
	h = strings.TrimSpace(h)
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	return strings.ToLower(h)
}

// AgentEnabled reports whether ssh, sshpass, and git's remote commands get
// the ssh agent: the section is present and agent is not set false.
func (s *SSHConfig) AgentEnabled() bool {
	if s == nil {
		return false
	}
	return s.Agent == nil || *s.Agent
}

// AgentUnrestricted reports whether they get the real agent socket instead of
// the filtering proxy (default false).
func (s *SSHConfig) AgentUnrestricted() bool {
	return s != nil && s.UnrestrictedAgent != nil && *s.UnrestrictedAgent
}

// ValidateSSHHost rejects a hosts entry ssh could not take as a destination
// host: empty, an option, or one carrying a user, port, path or whitespace.
func ValidateSSHHost(h string) error {
	switch {
	case strings.TrimSpace(h) == "":
		return fmt.Errorf("empty ssh host")
	case strings.HasPrefix(h, "-"):
		return fmt.Errorf("ssh host %q starts with -", h)
	case strings.ContainsAny(h, "@/ \t\n,*?!"):
		return fmt.Errorf("ssh host %q must be a bare host name or address (no user@, path, list, or pattern)", h)
	}
	return nil
}

// validateSSH rejects a malformed ssh section on the base config or any
// override.
func (c *Config) validateSSH() error {
	check := func(s *SSHConfig) error {
		if s == nil {
			return nil
		}
		for _, h := range s.Hosts {
			if err := ValidateSSHHost(h); err != nil {
				return err
			}
		}
		return nil
	}
	if err := check(c.SSH); err != nil {
		return err
	}
	for _, o := range c.Overrides {
		if err := check(o.SSH); err != nil {
			return fmt.Errorf("override %q: %w", o.Path, err)
		}
	}
	return nil
}

// AddSSHHost adds host to the ssh section, creating it, and reports whether it
// was new.
func (c *Config) AddSSHHost(host string) (bool, error) {
	if err := ValidateSSHHost(host); err != nil {
		return false, err
	}
	if c.SSH == nil {
		c.SSH = &SSHConfig{}
	}
	if c.SSH.AllowsHost(host) {
		return false, nil
	}
	c.SSH.Hosts = append(c.SSH.Hosts, host)
	return true, nil
}

// RemoveSSHHost removes host from the ssh section and reports whether it was
// listed.
func (c *Config) RemoveSSHHost(host string) bool {
	if c.SSH == nil {
		return false
	}
	n := len(c.SSH.Hosts)
	c.SSH.Hosts = slices.DeleteFunc(c.SSH.Hosts, func(h string) bool {
		return normalizeSSHHost(h) == normalizeSSHHost(host)
	})
	if len(c.SSH.Hosts) == 0 {
		c.SSH.Hosts = nil
	}
	return len(c.SSH.Hosts) != n
}

// SSHAuthSock returns the user's ssh agent socket ($SSH_AUTH_SOCK), symlinks
// resolved (the OS sandbox masks and grants it by its real path), when it is
// an absolute path to a unix socket, else "".
func SSHAuthSock() string {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if !filepath.IsAbs(sock) || !isUnixSocket(sock) {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(sock); err == nil {
		return resolved
	}
	return filepath.Clean(sock)
}

// WithSSHAgent returns c with the ssh agent's socket granted to the
// SSHAgentCommands alone, as a scoped internal read grant: those commands then
// run in a worker of their own that can reach it, while every other worker
// hides it (ScopedDeniedReadEntries). socket is the filtering proxy's, or the
// real agent's when the agent is unrestricted. c is returned unchanged when
// the agent is off or there is no socket.
func (c *Config) WithSSHAgent(socket string) *Config {
	if c == nil || !c.SSH.AgentEnabled() || socket == "" {
		return c
	}
	cp := *c
	yes := true
	cp.Paths = append(slices.Clone(c.Paths), PathEntry{
		Path:     socket,
		Read:     &yes,
		Internal: true,
		Commands: c.SSH.SSHAgentCommands(),
	})
	return &cp
}
