package config

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

const appName = "lite-sandbox"

// GitConfig controls granular git permission levels.
type GitConfig struct {
	LocalRead           *bool `yaml:"local_read,omitempty"`
	LocalWrite          *bool `yaml:"local_write,omitempty"`
	RemoteRead          *bool `yaml:"remote_read,omitempty"`
	RemoteWrite         *bool `yaml:"remote_write,omitempty"`
	AllowWorktreeParent *bool `yaml:"allow_worktree_parent,omitempty"`
}

// GitLocalRead returns whether local read git operations are allowed (default: true).
func (g *GitConfig) GitLocalRead() bool {
	if g == nil || g.LocalRead == nil {
		return true
	}
	return *g.LocalRead
}

// GitLocalWrite returns whether local write git operations are allowed (default: true).
func (g *GitConfig) GitLocalWrite() bool {
	if g == nil || g.LocalWrite == nil {
		return true
	}
	return *g.LocalWrite
}

// GitRemoteRead returns whether remote read git operations are allowed (default: true).
func (g *GitConfig) GitRemoteRead() bool {
	if g == nil || g.RemoteRead == nil {
		return true
	}
	return *g.RemoteRead
}

// GitRemoteWrite returns whether remote write git operations are allowed (default: false).
func (g *GitConfig) GitRemoteWrite() bool {
	if g == nil || g.RemoteWrite == nil {
		return false
	}
	return *g.RemoteWrite
}

// AllowsWorktreeParent returns whether the sandbox should extend its read/write
// paths to include the main worktree when the working directory is inside a
// linked git worktree (default: false).
func (g *GitConfig) AllowsWorktreeParent() bool {
	if g == nil || g.AllowWorktreeParent == nil {
		return false
	}
	return *g.AllowWorktreeParent
}

// GoConfig controls granular Go runtime permission levels.
type GoConfig struct {
	Enabled  *bool `yaml:"enabled,omitempty"`
	Generate *bool `yaml:"generate,omitempty"`
}

// GoEnabled returns whether go commands are allowed (default: false).
func (g *GoConfig) GoEnabled() bool {
	if g == nil || g.Enabled == nil {
		return false
	}
	return *g.Enabled
}

// GoGenerate returns whether go generate is allowed (default: false).
func (g *GoConfig) GoGenerate() bool {
	if g == nil || g.Generate == nil {
		return false
	}
	return *g.Generate
}

// PnpmConfig controls granular pnpm runtime permission levels.
type PnpmConfig struct {
	Enabled *bool `yaml:"enabled,omitempty"`
	Publish *bool `yaml:"publish,omitempty"`
}

// PnpmEnabled returns whether pnpm commands are allowed (default: false).
func (p *PnpmConfig) PnpmEnabled() bool {
	if p == nil || p.Enabled == nil {
		return false
	}
	return *p.Enabled
}

// PnpmPublish returns whether pnpm publish is allowed (default: false).
func (p *PnpmConfig) PnpmPublish() bool {
	if p == nil || p.Publish == nil {
		return false
	}
	return *p.Publish
}

// AWSConfig controls AWS CLI permissions and credential delivery method.
// Two modes:
//  1. allow_raw_credentials: true - AWS CLI reads from ~/.aws/credentials directly (no blocking)
//  2. force_profile: "name" - AWS CLI uses IMDS server with specified profile (blocks ~/.aws/)
//
// Overrides let either mode be changed for specific working directories, so a
// single config can broker a different profile (or switch modes) depending on
// where the sandbox is launched. Resolve the effective settings for a directory
// with ForDirectory before reading the mode accessors.
type AWSConfig struct {
	AllowRawCredentials *bool                  `yaml:"allow_raw_credentials,omitempty"`
	ForceProfile        string                 `yaml:"force_profile,omitempty"`
	Overrides           []AWSDirectoryOverride `yaml:"overrides,omitempty"`
}

// AWSDirectoryOverride replaces the AWS credential mode for commands whose
// working directory is at (or under) Path. Path supports ~ expansion. When a
// directory matches more than one override the most specific (longest) Path
// wins. A matching override fully defines the mode for that directory — its
// fields replace the base force_profile / allow_raw_credentials rather than
// merging, so the two modes never mix.
type AWSDirectoryOverride struct {
	Path                string `yaml:"path"`
	AllowRawCredentials *bool  `yaml:"allow_raw_credentials,omitempty"`
	ForceProfile        string `yaml:"force_profile,omitempty"`
}

// ForDirectory returns the effective AWS configuration for commands running in
// dir, applying the most specific matching directory override (if any) on top
// of the base settings. The returned config carries no overrides itself, so all
// the mode accessors (AWSEnabled, UsesIMDS, IMDSProfile, ...) reflect dir.
func (a *AWSConfig) ForDirectory(dir string) *AWSConfig {
	if a == nil {
		return nil
	}
	resolved := &AWSConfig{
		AllowRawCredentials: a.AllowRawCredentials,
		ForceProfile:        a.ForceProfile,
	}
	if o := a.matchOverride(dir); o != nil {
		resolved.AllowRawCredentials = o.AllowRawCredentials
		resolved.ForceProfile = o.ForceProfile
	}
	return resolved
}

// matchOverride returns the most specific override whose Path contains dir, or
// nil when none match. dir is matched if it equals an override Path or lies
// beneath it; the longest matching Path wins so nested overrides take priority.
func (a *AWSConfig) matchOverride(dir string) *AWSDirectoryOverride {
	if a == nil || dir == "" || len(a.Overrides) == 0 {
		return nil
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		abs = dir
	}
	var best *AWSDirectoryOverride
	bestLen := -1
	for i := range a.Overrides {
		base := expandPath(a.Overrides[i].Path)
		if base == "" {
			continue
		}
		if abs == base || strings.HasPrefix(abs, base+string(filepath.Separator)) {
			if len(base) > bestLen {
				best = &a.Overrides[i]
				bestLen = len(base)
			}
		}
	}
	return best
}

// AWSEnabled returns whether aws commands are allowed at all (default: false).
// Either allow_raw_credentials or force_profile must be set.
func (a *AWSConfig) AWSEnabled() bool {
	if a == nil {
		return false
	}
	return a.AllowRawCredentials != nil && *a.AllowRawCredentials || a.ForceProfile != ""
}

// AllowsRawCredentials returns whether AWS CLI can read from ~/.aws/credentials directly.
// If true, ~/.aws/ is NOT blocked and no IMDS server is started.
func (a *AWSConfig) AllowsRawCredentials() bool {
	if a == nil || a.AllowRawCredentials == nil {
		return false
	}
	return *a.AllowRawCredentials
}

// UsesIMDS returns whether AWS CLI should use IMDS server for credentials.
// If true, ~/.aws/ IS blocked and IMDS server provides credentials via force_profile.
func (a *AWSConfig) UsesIMDS() bool {
	if a == nil {
		return false
	}
	return a.ForceProfile != ""
}

// IMDSProfile returns the AWS profile to use for IMDS credentials.
// Only valid when UsesIMDS() returns true.
func (a *AWSConfig) IMDSProfile() string {
	return a.ForceProfile
}

// DockerConfig controls access to the Docker daemon. When enabled, a local
// filtering proxy is started in front of the real Docker socket and the
// sandboxed `docker` CLI talks to it via DOCKER_HOST. The proxy rejects
// privileged containers and bind mounts whose host source falls outside the
// sandbox's readable/writable path boundary.
type DockerConfig struct {
	Enabled         *bool  `yaml:"enabled,omitempty"`
	SocketPath      string `yaml:"socket_path,omitempty"`      // upstream daemon socket, default /var/run/docker.sock
	AllowPrivileged *bool  `yaml:"allow_privileged,omitempty"` // default false
	// AllowUnsandboxed permits the docker command without the OS sandbox. By
	// default docker requires os_sandbox, because only the OS sandbox can mask
	// the real daemon socket and make the filtering proxy unbypassable — without
	// it a command can simply `unset DOCKER_HOST` (or pass -H) and talk to the
	// real socket directly. Setting this accepts that weaker, bypassable boundary.
	AllowUnsandboxed *bool `yaml:"allow_unsandboxed,omitempty"`
}

// DefaultDockerSocket is the upstream Docker daemon socket used when SocketPath
// is not configured.
const DefaultDockerSocket = "/var/run/docker.sock"

// DockerEnabled returns whether docker commands are allowed (default: false).
func (d *DockerConfig) DockerEnabled() bool {
	if d == nil || d.Enabled == nil {
		return false
	}
	return *d.Enabled
}

// UpstreamSocket returns the upstream Docker daemon socket path the proxy
// forwards to. An explicit socket_path wins; otherwise it is autodetected the
// way the docker CLI resolves the daemon (DOCKER_HOST, active context, then
// well-known locations), falling back to /var/run/docker.sock.
func (d *DockerConfig) UpstreamSocket() string {
	if d != nil && d.SocketPath != "" {
		return d.SocketPath
	}
	return DetectDockerSocket()
}

// DetectDockerSocket resolves the host's Docker daemon unix socket the way the
// docker CLI would: the DOCKER_HOST env var, then the active docker context's
// endpoint, then well-known per-tool locations (Docker Desktop, OrbStack,
// Colima), falling back to /var/run/docker.sock. Only unix sockets are
// supported (the proxy dials a unix socket); a tcp:// DOCKER_HOST is ignored.
func DetectDockerSocket() string {
	if p := socketFromDockerHost(os.Getenv("DOCKER_HOST")); p != "" {
		return p
	}
	if p := socketFromDockerContext(); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err == nil {
		for _, c := range []string{
			filepath.Join(home, ".docker", "run", "docker.sock"),     // Docker Desktop (macOS)
			filepath.Join(home, ".orbstack", "run", "docker.sock"),   // OrbStack
			filepath.Join(home, ".colima", "default", "docker.sock"), // Colima
		} {
			if isUnixSocket(c) {
				return c
			}
		}
	}
	return DefaultDockerSocket
}

// socketFromDockerHost extracts the filesystem path from a unix:// DOCKER_HOST
// value, returning "" for empty, tcp://, or other non-unix endpoints.
func socketFromDockerHost(host string) string {
	if strings.HasPrefix(host, "unix://") {
		return strings.TrimPrefix(host, "unix://")
	}
	return ""
}

// socketFromDockerContext resolves the active docker context's unix endpoint by
// reading ~/.docker (the current context name, then its meta.json, whose
// directory is named with the sha256 hex digest of the context name).
func socketFromDockerContext() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}

	name := os.Getenv("DOCKER_CONTEXT")
	if name == "" {
		if data, err := os.ReadFile(filepath.Join(home, ".docker", "config.json")); err == nil {
			var cfg struct {
				CurrentContext string `json:"currentContext"`
			}
			_ = json.Unmarshal(data, &cfg)
			name = cfg.CurrentContext
		}
	}
	if name == "" || name == "default" {
		return ""
	}

	digest := sha256.Sum256([]byte(name))
	metaPath := filepath.Join(home, ".docker", "contexts", "meta", hex.EncodeToString(digest[:]), "meta.json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return ""
	}
	var meta struct {
		Endpoints struct {
			Docker struct {
				Host string `json:"Host"`
			} `json:"docker"`
		} `json:"Endpoints"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return ""
	}
	return socketFromDockerHost(meta.Endpoints.Docker.Host)
}

// isUnixSocket reports whether path exists and is a unix socket.
func isUnixSocket(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

// AllowsPrivileged returns whether privileged containers (and equivalent
// escalation vectors) are permitted through the proxy (default: false).
func (d *DockerConfig) AllowsPrivileged() bool {
	if d == nil || d.AllowPrivileged == nil {
		return false
	}
	return *d.AllowPrivileged
}

// AllowsUnsandboxed returns whether the docker command may run without the OS
// sandbox (default: false). When false, docker requires os_sandbox so the real
// daemon socket can be masked and the proxy cannot be bypassed.
func (d *DockerConfig) AllowsUnsandboxed() bool {
	if d == nil || d.AllowUnsandboxed == nil {
		return false
	}
	return *d.AllowUnsandboxed
}

// LocalBinaryExecutionConfig controls whether direct path execution
// (./binary, ../binary, /path/to/binary) is allowed.
type LocalBinaryExecutionConfig struct {
	Enabled *bool `yaml:"enabled,omitempty"`
}

// IsEnabled returns whether local binary execution is allowed (default: false).
func (l *LocalBinaryExecutionConfig) IsEnabled() bool {
	if l == nil || l.Enabled == nil {
		return false
	}
	return *l.Enabled
}

// RustConfig controls granular Rust runtime permission levels.
type RustConfig struct {
	Enabled *bool `yaml:"enabled,omitempty"`
	Publish *bool `yaml:"publish,omitempty"`
}

// RustEnabled returns whether cargo/rustc commands are allowed (default: false).
func (r *RustConfig) RustEnabled() bool {
	if r == nil || r.Enabled == nil {
		return false
	}
	return *r.Enabled
}

// RustPublish returns whether cargo publish is allowed (default: false).
func (r *RustConfig) RustPublish() bool {
	if r == nil || r.Publish == nil {
		return false
	}
	return *r.Publish
}

// DenoConfig controls granular Deno runtime permission levels.
type DenoConfig struct {
	Enabled *bool `yaml:"enabled,omitempty"`
	Publish *bool `yaml:"publish,omitempty"`
	// AutoSandbox, when enabled, automatically injects --allow-read and
	// --allow-write flags scoped to the sandbox's allowed paths into deno
	// commands, so Deno's own permission model mirrors the sandbox filesystem
	// policy.
	AutoSandbox *bool `yaml:"auto_sandbox,omitempty"`
	// AllowNetwork controls whether deno commands may open outbound network
	// sockets (--allow-net). When false (default), the sandbox forces
	// --deny-net so the invoker cannot grant socket access via --allow-net or
	// --allow-all. This is enforced whenever deno is enabled, independent of
	// auto_sandbox.
	AllowNetwork *bool `yaml:"allow_network,omitempty"`
	// AllowImport controls whether deno may fetch remote modules
	// (--allow-import, plus the CLI fetch subcommands cache/add/install). Deno
	// allows imports from a default host allowlist (deno.land/jsr.io/...) out of
	// the box, so this defaults to true. When false, the sandbox forces
	// --deny-import on code-executing subcommands and blocks the fetch
	// subcommands, independent of auto_sandbox.
	AllowImport *bool `yaml:"allow_import,omitempty"`
}

// DenoEnabled returns whether deno commands are allowed (default: false).
func (d *DenoConfig) DenoEnabled() bool {
	if d == nil || d.Enabled == nil {
		return false
	}
	return *d.Enabled
}

// DenoPublish returns whether deno publish is allowed (default: false).
func (d *DenoConfig) DenoPublish() bool {
	if d == nil || d.Publish == nil {
		return false
	}
	return *d.Publish
}

// DenoAutoSandbox returns whether deno commands should have --allow-read and
// --allow-write automatically configured from the sandbox paths (default: true).
// Deno runs with no permissions by default, so auto-sandbox grants read/write
// scoped to the sandbox paths and runs non-interactively out of the box.
func (d *DenoConfig) DenoAutoSandbox() bool {
	if d == nil || d.AutoSandbox == nil {
		return true
	}
	return *d.AutoSandbox
}

// DenoAllowNetwork returns whether deno commands may open network sockets
// (default: false). When false, the sandbox forces --deny-net.
func (d *DenoConfig) DenoAllowNetwork() bool {
	if d == nil || d.AllowNetwork == nil {
		return false
	}
	return *d.AllowNetwork
}

// DenoAllowImport returns whether deno may fetch remote modules (default: true).
// When false, the sandbox forces --deny-import and blocks the fetch
// subcommands (cache/add/install).
func (d *DenoConfig) DenoAllowImport() bool {
	if d == nil || d.AllowImport == nil {
		return true
	}
	return *d.AllowImport
}

// RuntimesConfig controls code execution runtime permissions.
type RuntimesConfig struct {
	Go   *GoConfig   `yaml:"go,omitempty"`
	Pnpm *PnpmConfig `yaml:"pnpm,omitempty"`
	Rust *RustConfig `yaml:"rust,omitempty"`
	Deno *DenoConfig `yaml:"deno,omitempty"`
}

// Config holds all user configuration. New fields can be added over time;
// unknown YAML fields are silently ignored for forward compatibility.
type Config struct {
	ExtraCommands        []string                    `yaml:"extra_commands,omitempty"`
	ReadablePaths        []string                    `yaml:"readable_paths,omitempty"`
	WritablePaths        []string                    `yaml:"writable_paths,omitempty"`
	Git                  *GitConfig                  `yaml:"git,omitempty"`
	Runtimes             *RuntimesConfig             `yaml:"runtimes,omitempty"`
	AWS                  *AWSConfig                  `yaml:"aws,omitempty"`
	Docker               *DockerConfig               `yaml:"docker,omitempty"`
	LocalBinaryExecution *LocalBinaryExecutionConfig `yaml:"local_binary_execution,omitempty"`
	OSSandbox            *bool                       `yaml:"os_sandbox,omitempty"`
}

// ExpandedReadablePaths returns ReadablePaths with ~ expanded to the user's
// home directory and all paths resolved to absolute paths.
func (c *Config) ExpandedReadablePaths() []string {
	return expandPaths(c.ReadablePaths)
}

// ExpandedWritablePaths returns WritablePaths with ~ expanded to the user's
// home directory and all paths resolved to absolute paths.
func (c *Config) ExpandedWritablePaths() []string {
	return expandPaths(c.WritablePaths)
}

// ExpandPath expands ~ and resolves p to an absolute path (so "." and other
// relative paths become canonical), returning "" when p is empty or cannot be
// resolved. Callers persisting a user-supplied directory should canonicalize it
// with this so it doesn't later resolve against an unrelated working directory.
func ExpandPath(p string) string {
	return expandPath(p)
}

// expandPath expands ~ and resolves a single path to absolute, returning ""
// when the path is empty or cannot be resolved.
func expandPath(p string) string {
	if p == "" {
		return ""
	}
	expanded := expandPaths([]string{p})
	if len(expanded) == 0 {
		return ""
	}
	return expanded[0]
}

// expandPaths expands ~ to the user's home directory and resolves absolute paths.
func expandPaths(paths []string) []string {
	if len(paths) == 0 {
		return nil
	}
	home, _ := os.UserHomeDir()
	result := make([]string, 0, len(paths))
	for _, p := range paths {
		if home != "" && len(p) > 0 && p[0] == '~' {
			if len(p) == 1 {
				p = home
			} else if p[1] == '/' {
				p = filepath.Join(home, p[2:])
			}
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		result = append(result, abs)
	}
	return result
}

// OSSandboxEnabled returns whether OS-level sandboxing with bwrap is enabled (default: false).
func (c *Config) OSSandboxEnabled() bool {
	if c == nil || c.OSSandbox == nil {
		return false
	}
	return *c.OSSandbox
}

// Path returns the platform-appropriate config file path.
// If LITE_SANDBOX_CONFIG env var is set, that path is used directly.
func Path() (string, error) {
	if p := os.Getenv("LITE_SANDBOX_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine config directory: %w", err)
	}
	return filepath.Join(dir, appName, "config.yaml"), nil
}

// Load reads and parses the config file. If the file does not exist,
// a zero-value Config is returned with no error.
func Load() (*Config, error) {
	p, err := Path()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	return &cfg, nil
}

// Save writes the config to the YAML file, creating the directory if needed.
func Save(cfg *Config) error {
	p, err := Path()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}

// Watch monitors the config file for changes and calls onChange with the
// newly loaded Config. It blocks until ctx is cancelled. If the config
// directory does not exist yet, Watch creates it so fsnotify can watch it.
func Watch(ctx context.Context, onChange func(*Config)) error {
	p, err := Path()
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(dir); err != nil {
		return fmt.Errorf("watching config directory: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			// Only react to writes/creates of the config file itself.
			if filepath.Base(event.Name) != filepath.Base(p) {
				continue
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				cfg, err := Load()
				if err != nil {
					slog.Error("failed to reload config", "error", err)
					continue
				}
				onChange(cfg)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			slog.Error("config watcher error", "error", err)
		}
	}
}
