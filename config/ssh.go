package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// SSHConfig controls ssh access: the hosts ssh and sshpass may connect to,
// and how the user's ssh agent reaches ssh, sshpass, and the ssh that git's
// remote commands (fetch, pull, push, clone, ...) start.
//
//	ssh:
//	  hosts:                     # ssh/sshpass may connect to these, as typed
//	    - build-box              # (an alias of ~/.ssh/config, or a host name)
//	    - 10.0.0.12
//	    - host: deploy-box       # the mapping form: what the remote command may do
//	      commands: [systemctl restart]
//	  agent: true                # default true once the section exists
//	  unrestricted_agent: false  # default false: the agent goes through a filter
//	  git_signing: false         # default false: git commit/tag signing with the agent
//
// The agent, when on, is given to those commands alone: they run in an OS
// sandbox worker of their own (a command scope, see CommandScope) that can
// reach it, while every other worker masks it. By default that is a filtering
// proxy in front of the real agent (internal/sshagent), which lists keys and
// signs with them but refuses everything else: adding, removing, or locking
// keys, other extensions, and use over a forwarded connection.
// unrestricted_agent hands those commands the real socket instead.
type SSHConfig struct {
	Hosts []SSHHost `yaml:"hosts,omitempty"`
	// Agent gives ssh, sshpass, and git's remote commands the ssh agent
	// (default true when the section is present).
	Agent *bool `yaml:"agent,omitempty"`
	// UnrestrictedAgent gives them the real agent socket rather than the
	// filtering proxy (default false).
	UnrestrictedAgent *bool `yaml:"unrestricted_agent,omitempty"`
	// GitSigning gives the agent to the git commands that sign commits and
	// tags too (gpg.format ssh), and lets the proxy sign them (default false).
	GitSigning *bool `yaml:"git_signing,omitempty"`
}

// SSHHost is one entry of the ssh section's hosts list: a host ssh may
// connect to, plus what the command it runs there may do. The command is held
// to read-only commands by default (see the sandbox's remote command check);
// like a paths entry, the entry widens that:
//
//	hosts:
//	  - build-box                # read-only remote commands
//	  - host: deploy-box         # also systemctl restart (any arguments) and
//	    commands:                # docker ps, beyond the read-only commands
//	      - systemctl restart
//	      - docker ps
//	  - host: scratch-vm         # the remote command is not checked
//	    write: true
//
// An entry with neither is written as the bare host.
type SSHHost struct {
	Host string `yaml:"host"`
	// Write lifts the remote command check: the command runs as written.
	Write *bool `yaml:"write,omitempty"`
	// Commands are allowed in the remote command beyond the read-only ones: a
	// command name, or a name and the leading arguments it is limited to
	// ("systemctl restart"), like a commands entry. Their arguments are not
	// checked.
	Commands []string `yaml:"commands,omitempty"`
}

// sshHostFields is SSHHost without its YAML methods, for decoding and encoding
// the mapping form.
type sshHostFields SSHHost

// UnmarshalYAML accepts both the bare-host form ("build-box") and the mapping
// form.
func (h *SSHHost) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*h = SSHHost{Host: n.Value}
		return nil
	}
	var f sshHostFields
	if err := n.Decode(&f); err != nil {
		return err
	}
	*h = SSHHost(f)
	return nil
}

// MarshalYAML writes an entry that only lists its host as the bare host.
func (h SSHHost) MarshalYAML() (any, error) {
	if h.Write == nil && len(h.Commands) == 0 {
		return h.Host, nil
	}
	return sshHostFields(h), nil
}

// MergeKey makes the entry a keyedEntry: a merge: true override restates a
// base entry by naming the same host.
func (h SSHHost) MergeKey() string { return normalizeSSHHost(h.Host) }

// Writes reports whether the remote command goes unchecked (write: true).
func (h *SSHHost) Writes() bool { return h != nil && h.Write != nil && *h.Write }

// Describe renders what the remote command may do on the host, for listings.
func (h SSHHost) Describe() string {
	switch {
	case h.Writes():
		return "any remote command"
	case len(h.Commands) > 0:
		return "read-only remote commands, and " + strings.Join(h.Commands, ", ")
	}
	return "read-only remote commands"
}

// Validate rejects an entry ssh could not take as a destination, or a
// commands entry that names no command.
func (h SSHHost) Validate() error {
	if err := ValidateSSHHost(h.Host); err != nil {
		return err
	}
	for _, c := range h.Commands {
		if err := ValidateSSHHostCommand(c); err != nil {
			return fmt.Errorf("ssh host %q: %w", h.Host, err)
		}
	}
	return nil
}

// ValidateSSHHostCommand rejects a host commands entry that does not start
// with a bare command name.
func ValidateSSHHostCommand(c string) error {
	f := strings.Fields(c)
	if len(f) == 0 {
		return fmt.Errorf("empty commands entry")
	}
	if strings.HasPrefix(f[0], "-") || strings.ContainsAny(f[0], "/$`'\"=;&|<>(){}*?[]") {
		return fmt.Errorf("commands entry %q must start with a bare command name", c)
	}
	return nil
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
	return s.Host(host) != nil
}

// Host returns the hosts entry for host, as given on the command line
// (without user@ or :port), matched as AllowsHost does, or nil.
func (s *SSHConfig) Host(host string) *SSHHost {
	if s == nil {
		return nil
	}
	host = normalizeSSHHost(host)
	if host == "" {
		return nil
	}
	for i := range s.Hosts {
		if normalizeSSHHost(s.Hosts[i].Host) == host {
			return &s.Hosts[i]
		}
	}
	return nil
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

// GitSigningEnabled reports whether the git commands that sign commits and
// tags get the agent, and the proxy signs for them: git_signing is on and so
// is the agent.
func (s *SSHConfig) GitSigningEnabled() bool {
	return s.AgentEnabled() && s.GitSigning != nil && *s.GitSigning
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
		seen := map[string]bool{}
		for _, h := range s.Hosts {
			if err := h.Validate(); err != nil {
				return err
			}
			if seen[h.MergeKey()] {
				return fmt.Errorf("ssh host %q is listed twice; combine the entries into one", h.Host)
			}
			seen[h.MergeKey()] = true
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
// changed anything. An entry for a listed host takes write when set, and the
// commands it does not list yet.
func (c *Config) AddSSHHost(host string, write bool, commands ...string) (bool, error) {
	entry := SSHHost{Host: host, Commands: commands}
	if write {
		entry.Write = &write
	}
	if err := entry.Validate(); err != nil {
		return false, err
	}
	if c.SSH == nil {
		c.SSH = &SSHConfig{}
	}
	h := c.SSH.Host(host)
	if h == nil {
		c.SSH.Hosts = append(c.SSH.Hosts, entry)
		return true, nil
	}
	changed := false
	if write && !h.Writes() {
		h.Write = entry.Write
		changed = true
	}
	for _, cmd := range commands {
		norm := strings.Join(strings.Fields(cmd), " ")
		if !slices.ContainsFunc(h.Commands, func(c string) bool { return strings.Join(strings.Fields(c), " ") == norm }) {
			h.Commands = append(h.Commands, norm)
			changed = true
		}
	}
	return changed, nil
}

// RemoveSSHHost removes host from the ssh section and reports whether it was
// listed.
func (c *Config) RemoveSSHHost(host string) bool {
	if c.SSH == nil {
		return false
	}
	n := len(c.SSH.Hosts)
	c.SSH.Hosts = slices.DeleteFunc(c.SSH.Hosts, func(h SSHHost) bool {
		return h.MergeKey() == normalizeSSHHost(host)
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
