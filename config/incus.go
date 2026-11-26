package config

import (
	"os"
	"path/filepath"
)

// IncusConfig controls access to an Incus (or LXD) daemon. When enabled, a
// local filtering proxy is started in front of the daemon's unix socket and
// the sandboxed `incus` / `lxc` CLIs talk to it via INCUS_SOCKET / LXD_SOCKET.
// The proxy pins every request to one project, rejects privileged instances
// and the low-level options and device types Incus's own restricted projects
// block, and checks host-path disk devices against the sandbox's path
// boundary. See internal/incusproxy.
type IncusConfig struct {
	Enabled    *bool  `yaml:"enabled,omitempty"`
	SocketPath string `yaml:"socket_path,omitempty"` // upstream daemon socket; autodetected when empty
	// Project is the Incus project every request is pinned to (default
	// "default"). A request naming another project, or asking for all of
	// them, is refused. Point it at a restricted project to have the daemon
	// enforce the same limits as the proxy.
	Project string `yaml:"project,omitempty"`
	// TaggedOnly restricts the sandbox to the instances it created itself:
	// instances created through the proxy are tagged with the
	// user.lite-sandbox config key, every per-instance request needs the tag,
	// instance listings are filtered to tagged instances, and profile writes
	// (which would reach untagged instances too) are refused. Default false.
	TaggedOnly *bool `yaml:"tagged_only,omitempty"`
	// AllowPrivileged permits privileged containers, low-level options
	// (raw.*, volatile.*, syscall interception, ...) and passthrough device
	// types (unix-char, gpu, proxy, ...). Host-path disk devices are still
	// checked against the path boundary. Default false.
	AllowPrivileged *bool `yaml:"allow_privileged,omitempty"`
	// AllowNesting permits security.nesting=true (running containers, e.g.
	// docker, inside an unprivileged container). Default false.
	AllowNesting *bool `yaml:"allow_nesting,omitempty"`
	// AllowUnsandboxed permits the incus/lxc commands without the OS sandbox,
	// where the real daemon socket cannot be masked and a command can bypass
	// the proxy by unsetting INCUS_SOCKET. Default false.
	AllowUnsandboxed *bool `yaml:"allow_unsandboxed,omitempty"`
}

// DefaultIncusProject is the project the proxy pins requests to when none is
// configured.
const DefaultIncusProject = "default"

// IncusTagKey is the instance config key marking instances the sandbox
// created, enforced when tagged_only is set.
const IncusTagKey = "user.lite-sandbox"

// incusDaemonDirs are the directories the Incus and LXD daemons keep their
// unix sockets in (unix.socket, unix.socket.user, the guest API sockets), in
// the order the clients probe them.
var incusDaemonDirs = []string{
	"/run/incus",
	"/var/lib/incus",
	"/var/snap/lxd/common/lxd",
	"/var/lib/lxd",
}

// IncusEnabled returns whether the incus/lxc commands are allowed (default false).
func (c *IncusConfig) IncusEnabled() bool {
	return c != nil && c.Enabled != nil && *c.Enabled
}

// UpstreamSocket returns the daemon socket the proxy forwards to: socket_path
// when set, otherwise DetectIncusSocket.
func (c *IncusConfig) UpstreamSocket() string {
	if c != nil && c.SocketPath != "" {
		return c.SocketPath
	}
	return DetectIncusSocket()
}

// ProjectName returns the project requests are pinned to.
func (c *IncusConfig) ProjectName() string {
	if c == nil || c.Project == "" {
		return DefaultIncusProject
	}
	return c.Project
}

// RequiresTag returns whether only instances the sandbox created are reachable.
func (c *IncusConfig) RequiresTag() bool {
	return c != nil && c.TaggedOnly != nil && *c.TaggedOnly
}

// AllowsPrivileged returns whether privileged instances and low-level options
// pass the proxy (default false).
func (c *IncusConfig) AllowsPrivileged() bool {
	return c != nil && c.AllowPrivileged != nil && *c.AllowPrivileged
}

// AllowsNesting returns whether security.nesting may be enabled (default false).
func (c *IncusConfig) AllowsNesting() bool {
	return c != nil && c.AllowNesting != nil && *c.AllowNesting
}

// AllowsUnsandboxed returns whether the incus/lxc commands may run without the
// OS sandbox (default false).
func (c *IncusConfig) AllowsUnsandboxed() bool {
	return c != nil && c.AllowUnsandboxed != nil && *c.AllowUnsandboxed
}

// DetectIncusSocket resolves the daemon socket the way the clients do:
// $INCUS_SOCKET, $INCUS_DIR/unix.socket, $LXD_SOCKET, $LXD_DIR/unix.socket,
// then the first well-known socket that exists (Incus's /run/incus and
// /var/lib/incus, the LXD snap's and LXD's own directory, Colima's incus
// runtime), falling back to /var/lib/incus/unix.socket. Only the admin socket
// (unix.socket) is chosen automatically; point socket_path at
// unix.socket.user to go through incus-user's per-user project instead.
func DetectIncusSocket() string {
	if p := os.Getenv("INCUS_SOCKET"); p != "" {
		return p
	}
	if d := os.Getenv("INCUS_DIR"); d != "" {
		return filepath.Join(d, "unix.socket")
	}
	if p := os.Getenv("LXD_SOCKET"); p != "" {
		return p
	}
	if d := os.Getenv("LXD_DIR"); d != "" {
		return filepath.Join(d, "unix.socket")
	}
	for _, c := range incusSocketCandidates() {
		if isUnixSocket(c) {
			return c
		}
	}
	return "/var/lib/incus/unix.socket"
}

func incusSocketCandidates() []string {
	var out []string
	for _, d := range incusDaemonDirs {
		out = append(out, filepath.Join(d, "unix.socket"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".colima", "default", "incus.sock"))
	}
	return out
}

// IncusDaemonDirs returns the daemon socket directories the OS sandbox masks
// while the proxy runs, so neither the admin socket nor incus-user's socket is
// reachable around the proxy.
func IncusDaemonDirs() []string {
	return append([]string(nil), incusDaemonDirs...)
}

// IncusMaskSockets returns the socket files the OS sandbox masks while the
// proxy runs: upstream (which may sit outside the daemon directories) and the
// well-known sockets outside them (Colima's).
func IncusMaskSockets(upstream string) []string {
	out := []string{}
	if upstream != "" {
		out = append(out, upstream)
	}
	if home, err := os.UserHomeDir(); err == nil {
		out = append(out, filepath.Join(home, ".colima", "default", "incus.sock"))
	}
	return out
}

// IncusClientConfigDirs returns the client configuration directories of the
// incus and lxc CLIs ($INCUS_CONF / $LXD_CONF, else under the XDG config
// directory, and the LXD snap's). They hold the client certificate and key
// trusted by remote daemons, which would let a command reach a daemon over
// HTTPS around the proxy.
func IncusClientConfigDirs() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	xdg := xdgConfigHome(home)
	out := []string{filepath.Join(xdg, "incus"), filepath.Join(xdg, "lxc"), filepath.Join(home, "snap", "lxd", "common", "config")}
	if d := os.Getenv("INCUS_CONF"); d != "" {
		out = append(out, d)
	}
	if d := os.Getenv("LXD_CONF"); d != "" {
		out = append(out, d)
	}
	return out
}
