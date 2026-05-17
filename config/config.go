package config

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

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
type AWSConfig struct {
	AllowRawCredentials *bool  `yaml:"allow_raw_credentials,omitempty"`
	ForceProfile        string `yaml:"force_profile,omitempty"`
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

// RuntimesConfig controls code execution runtime permissions.
type RuntimesConfig struct {
	Go   *GoConfig   `yaml:"go,omitempty"`
	Pnpm *PnpmConfig `yaml:"pnpm,omitempty"`
	Rust *RustConfig `yaml:"rust,omitempty"`
}

// Config holds all user configuration. New fields can be added over time;
// unknown YAML fields are silently ignored for forward compatibility.
type Config struct {
	ExtraCommands []string        `yaml:"extra_commands,omitempty"`
	ReadablePaths []string        `yaml:"readable_paths,omitempty"`
	WritablePaths []string        `yaml:"writable_paths,omitempty"`
	Git           *GitConfig      `yaml:"git,omitempty"`
	Runtimes      *RuntimesConfig `yaml:"runtimes,omitempty"`
	AWS                  *AWSConfig                  `yaml:"aws,omitempty"`
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
