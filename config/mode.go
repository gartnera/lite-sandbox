package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Mode is the sandbox's enforcement posture. It selects which validation
// layers block a command and, when the OS sandbox is enabled, how the worker's
// filesystem is confined. See docs/adoption.md for the intended progression.
type Mode string

const (
	// ModeOpen enforces nothing: every command runs. Validation still executes
	// so that, with audit enabled, each finding is recorded together with the
	// modes that would have blocked it. Use it to evaluate before committing.
	ModeOpen Mode = "open"
	// ModeDenylist drops the command whitelist (any program may run) but keeps
	// the path boundary on arguments and redirections, the per-command
	// argument validators (find -delete, git push, publish flags, ...), and the
	// structural checks. Under the OS sandbox the home directory is writable
	// and only the denied paths are masked. This is the opt-out for incremental
	// adoption: it assumes a cooperative agent and stops accidental scope
	// escapes and secret reads without breaking developer tooling.
	ModeDenylist Mode = "denylist"
	// ModeAllowlist is the original behavior: only whitelisted commands run,
	// code-execution runtimes are opt-in, and the OS sandbox confines writes to
	// the working directory plus configured paths. This is the posture for
	// untrusted input, where the agent may be steered by content it reads.
	ModeAllowlist Mode = "allowlist"
)

// DefaultMode is the mode in effect when the config sets none: the strict
// posture. Looser modes are explicit opt-outs (`lite-sandbox config mode set`).
const DefaultMode = ModeAllowlist

// Modes lists every valid mode, loosest first.
var Modes = []Mode{ModeOpen, ModeDenylist, ModeAllowlist}

// ParseMode validates a mode name from config or the CLI.
func ParseMode(s string) (Mode, error) {
	m := Mode(s)
	for _, known := range Modes {
		if m == known {
			return m, nil
		}
	}
	return "", fmt.Errorf("invalid mode %q (valid: open, denylist, allowlist)", s)
}

// EffectiveMode returns the configured mode, or DefaultMode when unset. An
// invalid value is rejected by Load, so a loaded config never reaches here
// with one; a config built in code with a bad value falls back to the default.
func (c *Config) EffectiveMode() Mode {
	if c == nil || c.Mode == "" {
		return DefaultMode
	}
	if m, err := ParseMode(c.Mode); err == nil {
		return m
	}
	return DefaultMode
}

// AuditEnabled reports whether validation findings are written to the audit
// log (default: false).
func (c *Config) AuditEnabled() bool {
	if c == nil || c.Audit == nil {
		return false
	}
	return *c.Audit
}

// validateModes rejects an unknown mode on the base config or any override, so
// a typo cannot silently fall back to the default posture.
func (c *Config) validateModes() error {
	if c.Mode != "" {
		if _, err := ParseMode(c.Mode); err != nil {
			return err
		}
	}
	for _, o := range c.Overrides {
		if o.Mode != "" {
			if _, err := ParseMode(o.Mode); err != nil {
				return fmt.Errorf("override %q: %w", o.Path, err)
			}
		}
	}
	return nil
}

// DefaultDeniedReadPaths returns the built-in set of paths whose contents are
// hidden from sandboxed commands in denylist mode: credential stores and the
// agents' own auth files. Paths are absolute; missing ones are harmless (the OS
// sandbox skips what does not exist). SSH private keys are handled separately
// by the worker, which detects them by content rather than name.
//
// The list is deliberately limited to secrets that developer tooling rarely
// needs: a masked ~/.npmrc or ~/.docker/config.json would break private
// registry access, so those are write-denied instead (see
// DefaultDeniedWritePaths).
func DefaultDeniedReadPaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	claudeDir, claudeUserConfig := claudeConfigPaths(home)
	xdg := xdgConfigHome(home)
	return []string{
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".gnupg"),
		filepath.Join(home, ".netrc"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".pypirc"),
		filepath.Join(xdg, "gh"),
		filepath.Join(home, "Library", "Keychains"),
		// The agents' own credentials.
		claudeUserConfig,
		filepath.Join(claudeDir, ".credentials.json"),
		filepath.Join(codexHome(home), "auth.json"),
	}
}

// DefaultDeniedWritePaths returns the built-in set of paths sandboxed commands
// may read but not modify in denylist mode: shell startup files and other
// persistence vectors, plus the sandbox's and the agents' own configuration so
// a command cannot loosen the policy that governs it (the config file is
// hot-reloaded, and the agent settings hold the built-in Bash deny).
func DefaultDeniedWritePaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	claudeDir, _ := claudeConfigPaths(home)
	codex := codexHome(home)
	xdg := xdgConfigHome(home)
	paths := []string{
		// Shell startup and identity files: readable so tools behave, not writable.
		filepath.Join(home, ".bashrc"),
		filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".bash_login"),
		filepath.Join(home, ".profile"),
		filepath.Join(home, ".zshrc"),
		filepath.Join(home, ".zshenv"),
		filepath.Join(home, ".zprofile"),
		filepath.Join(home, ".gitconfig"),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".npmrc"),
		filepath.Join(home, ".docker", "config.json"),
		// Persistence vectors.
		filepath.Join(xdg, "systemd", "user"),
		filepath.Join(home, "Library", "LaunchAgents"),
		// Self-protection: the sandbox's own config and the agents' settings.
		filepath.Join(claudeDir, "settings.json"),
		filepath.Join(claudeDir, "settings.local.json"),
		filepath.Join(claudeDir, "CLAUDE.md"),
		filepath.Join(codex, "config.toml"),
		filepath.Join(codex, "AGENTS.md"),
		filepath.Join(xdg, "opencode", "opencode.json"),
		filepath.Join(xdg, "opencode", "opencode.jsonc"),
		filepath.Join(xdg, "opencode", "AGENTS.md"),
		filepath.Join(xdg, "crush", "crushrc"),
		filepath.Join(xdg, "crush", "crush.json"),
		filepath.Join(xdg, "crush", "CRUSH.md"),
	}
	if p, err := Path(); err == nil {
		paths = append(paths, p)
	}
	return paths
}

// EffectiveDeniedReadPaths returns the read-denied paths in effect: the
// built-in defaults plus the config's denied_read_paths (with ~ expanded). When
// AWS is configured to use raw credentials, ~/.aws is dropped from the defaults
// since the CLI must read it.
func (c *Config) EffectiveDeniedReadPaths() []string {
	defaults := DefaultDeniedReadPaths()
	if c != nil && c.AWS.AllowsRawCredentials() {
		if home, err := os.UserHomeDir(); err == nil {
			aws := filepath.Join(home, ".aws")
			defaults = deleteString(defaults, aws)
		}
	}
	var extra []string
	if c != nil {
		extra = expandPaths(c.DeniedReadPaths)
	}
	return uniqueStrings(append(defaults, extra...))
}

// EffectiveDeniedWritePaths returns the write-denied paths in effect: the
// built-in defaults plus the config's denied_write_paths (with ~ expanded).
func (c *Config) EffectiveDeniedWritePaths() []string {
	var extra []string
	if c != nil {
		extra = expandPaths(c.DeniedWritePaths)
	}
	return uniqueStrings(append(DefaultDeniedWritePaths(), extra...))
}

// claudeConfigPaths mirrors Claude Code's own resolution: $CLAUDE_CONFIG_DIR
// when set (with the user config file inside it), otherwise ~/.claude and
// ~/.claude.json.
func claudeConfigPaths(home string) (dir, userConfig string) {
	if d := os.Getenv("CLAUDE_CONFIG_DIR"); d != "" {
		return d, filepath.Join(d, ".claude.json")
	}
	return filepath.Join(home, ".claude"), filepath.Join(home, ".claude.json")
}

func codexHome(home string) string {
	if d := os.Getenv("CODEX_HOME"); d != "" {
		return d
	}
	return filepath.Join(home, ".codex")
}

func xdgConfigHome(home string) string {
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return d
	}
	return filepath.Join(home, ".config")
}

func deleteString(list []string, s string) []string {
	out := list[:0:0]
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}

func uniqueStrings(list []string) []string {
	seen := make(map[string]bool, len(list))
	out := make([]string, 0, len(list))
	for _, v := range list {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
