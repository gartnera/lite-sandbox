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

// DeniedPath is one deny-list entry. Dir records whether the entry names a
// directory, which the OS sandbox needs to know for a path that does not exist
// yet: a missing directory can be created (harmlessly, and then masked) so the
// protection holds, while a missing file cannot be masked without creating an
// empty file on the host — which for a shell startup file would change the
// user's shell — so missing files are skipped and reported by `config mode
// show`. Built-in entries carry the right kind; user-added entries are
// classified by what exists on disk.
//
// The remaining fields describe a built-in entry. A built-in is one statement
// in the default path list that the config's own `paths` entries are merged
// over (see LiftedBy and the Effective* accessors): a grant on the same path
// lifts it, so the user decides, not the binary.
type DeniedPath struct {
	Path string
	Dir  bool
	// AllModes marks a built-in the OS sandbox enforces in every mode, not only
	// denylist: the credential masks (SSH private keys; ~/.aws in IMDS broker
	// mode), which hold in allowlist mode too where the rest of the deny lists
	// are unused.
	AllModes bool
	// Group is a second path whose grant also lifts the entry, for a built-in
	// that stands for part of a directory: each SSH private key names ~/.ssh,
	// so one grant on the directory lifts every key while the non-key files
	// there were never masked.
	Group string
	// Note describes a built-in in listings ("SSH private key").
	Note string
	// LiftedBy is the path (as written) of the paths grant that lifts this
	// built-in, when one does; such an entry is reported, not enforced.
	LiftedBy string
}

// Paths returns just the path strings of entries.
func deniedPathStrings(entries []DeniedPath) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Path)
	}
	return out
}

// DefaultDeniedReadPaths returns the built-in set of paths whose contents are
// hidden from sandboxed commands in denylist mode: credential stores and the
// agents' own auth files, plus — in every mode (AllModes) — the SSH private
// keys in ~/.ssh, one entry per key file (see SSHPrivateKeyEntries). Paths are
// absolute.
//
// The list is deliberately limited to secrets that developer tooling rarely
// needs: a masked ~/.npmrc or ~/.docker/config.json would break private
// registry access, so those are write-denied instead (see
// DefaultDeniedWritePaths). Agent-specific entries are included only when that
// agent's config directory exists, so no empty agent directories are created
// on hosts that never installed it.
func DefaultDeniedReadPaths() []DeniedPath {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	claudeDir, claudeUserConfig := claudeConfigPaths(home)
	xdg := xdgConfigHome(home)
	dir := func(p string) DeniedPath { return DeniedPath{Path: p, Dir: true} }
	file := func(p string) DeniedPath { return DeniedPath{Path: p} }
	out := []DeniedPath{
		dir(filepath.Join(home, ".aws")),
		dir(filepath.Join(home, ".gnupg")),
		file(filepath.Join(home, ".netrc")),
		dir(filepath.Join(home, ".kube")),
		file(filepath.Join(home, ".pypirc")),
		dir(filepath.Join(xdg, "gh")),
		dir(filepath.Join(home, "Library", "Keychains")),
	}
	// The agents' own credentials.
	if dirExists(claudeDir) {
		out = append(out, file(claudeUserConfig), file(filepath.Join(claudeDir, ".credentials.json")))
	}
	if codex := codexHome(home); dirExists(codex) {
		out = append(out, file(filepath.Join(codex, "auth.json")))
	}
	return append(out, SSHPrivateKeyEntries(home)...)
}

// DefaultDeniedWritePaths returns the built-in set of paths sandboxed commands
// may read but not modify in denylist mode: shell startup files and other
// persistence vectors, plus the sandbox's and the agents' own configuration so
// a command cannot loosen the policy that governs it (the config file is
// hot-reloaded, the agent settings hold the built-in Bash deny, and the audit
// log is the evidence the report is built on).
func DefaultDeniedWritePaths() []DeniedPath {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	claudeDir, _ := claudeConfigPaths(home)
	codex := codexHome(home)
	xdg := xdgConfigHome(home)
	dir := func(p string) DeniedPath { return DeniedPath{Path: p, Dir: true} }
	file := func(p string) DeniedPath { return DeniedPath{Path: p} }
	out := []DeniedPath{
		// Shell startup and identity files: readable so tools behave, not writable.
		file(filepath.Join(home, ".bashrc")),
		file(filepath.Join(home, ".bash_profile")),
		file(filepath.Join(home, ".bash_login")),
		file(filepath.Join(home, ".bash_aliases")),
		file(filepath.Join(home, ".bash_logout")),
		file(filepath.Join(home, ".profile")),
		file(filepath.Join(home, ".zshrc")),
		file(filepath.Join(home, ".zshenv")),
		file(filepath.Join(home, ".zprofile")),
		file(filepath.Join(home, ".zlogin")),
		file(filepath.Join(xdg, "fish", "config.fish")),
		file(filepath.Join(home, ".gitconfig")),
		file(filepath.Join(xdg, "git", "config")),
		dir(filepath.Join(home, ".ssh")),
		file(filepath.Join(home, ".npmrc")),
		file(filepath.Join(home, ".docker", "config.json")),
		// Persistence vectors: things the host runs or puts on PATH later.
		dir(filepath.Join(home, ".local", "bin")),
		dir(filepath.Join(xdg, "systemd", "user")),
		dir(filepath.Join(xdg, "autostart")),
		dir(filepath.Join(xdg, "environment.d")),
		dir(filepath.Join(home, "Library", "LaunchAgents")),
	}
	// Self-protection: the sandbox's own config, audit log, and mask file.
	if p, err := Path(); err == nil {
		out = append(out, file(p))
	}
	if cache, err := os.UserCacheDir(); err == nil {
		out = append(out, dir(filepath.Join(cache, appName)))
	}
	if cfgDir, err := os.UserConfigDir(); err == nil {
		out = append(out, file(filepath.Join(cfgDir, appName, "audit.jsonl")))
	}
	if p := os.Getenv("LITE_SANDBOX_AUDIT_LOG"); p != "" {
		out = append(out, file(p))
	}
	// The agents' settings and instruction files, only for installed agents.
	if dirExists(claudeDir) {
		out = append(out,
			file(filepath.Join(claudeDir, "settings.json")),
			file(filepath.Join(claudeDir, "settings.local.json")),
			file(filepath.Join(claudeDir, "CLAUDE.md")),
			dir(filepath.Join(claudeDir, "skills")),
			dir(filepath.Join(claudeDir, "agents")),
			dir(filepath.Join(claudeDir, "commands")),
			dir(filepath.Join(claudeDir, "plugins")),
		)
	}
	if dirExists(codex) {
		out = append(out,
			file(filepath.Join(codex, "config.toml")),
			file(filepath.Join(codex, "AGENTS.md")),
			dir(filepath.Join(codex, "prompts")),
		)
	}
	if oc := filepath.Join(xdg, "opencode"); dirExists(oc) {
		out = append(out,
			file(filepath.Join(oc, "opencode.json")),
			file(filepath.Join(oc, "opencode.jsonc")),
			file(filepath.Join(oc, "AGENTS.md")),
		)
	}
	if cr := filepath.Join(xdg, "crush"); dirExists(cr) {
		out = append(out,
			file(filepath.Join(cr, "crushrc")),
			file(filepath.Join(cr, "crush.json")),
			file(filepath.Join(cr, "CRUSH.md")),
		)
	}
	return out
}

// EffectiveDeniedReadEntries returns the read-denied entries in effect in
// denylist mode: the built-in defaults that no paths grant lifts (see
// LiftedDeniedEntries) plus the config's read: false paths entries (and the
// deprecated denied_read_paths), with ~ expanded and classified by what exists
// on disk. When AWS is configured to use raw credentials, ~/.aws is dropped
// from the defaults since the CLI must read it.
func (c *Config) EffectiveDeniedReadEntries() []DeniedPath {
	active, _ := c.splitDefaults(c.defaultDeniedReadPaths(), liftsRead)
	return uniqueDeniedPaths(append(active, userDeniedPaths(c.DeniedReadPathList())...))
}

// EffectiveDeniedWriteEntries returns the write-denied entries in effect in
// denylist mode: the built-in defaults that no paths grant lifts plus the
// config's write: false paths entries (and the deprecated denied_write_paths).
func (c *Config) EffectiveDeniedWriteEntries() []DeniedPath {
	active, _ := c.splitDefaults(DefaultDeniedWritePaths(), liftsWrite)
	return uniqueDeniedPaths(append(active, userDeniedPaths(c.DeniedWritePathList())...))
}

// AlwaysDeniedReadEntries returns the read-denied built-ins in effect in every
// mode — the credential masks (AllModes) that no paths grant lifts. In
// allowlist mode they are the whole of what the OS sandbox hides; in denylist
// mode they are a subset of EffectiveDeniedReadEntries.
func (c *Config) AlwaysDeniedReadEntries() []DeniedPath {
	active, _ := c.splitDefaults(c.defaultDeniedReadPaths(), liftsRead)
	var out []DeniedPath
	for _, d := range active {
		if d.AllModes {
			out = append(out, d)
		}
	}
	return uniqueDeniedPaths(out)
}

// LiftedDeniedEntries returns the built-in deny-list entries the config's paths
// grants lift, read-denied and write-denied, each with LiftedBy set to the
// granting path. They are what `config mode show` reports as not enforced.
func (c *Config) LiftedDeniedEntries() (read, write []DeniedPath) {
	_, read = c.splitDefaults(c.defaultDeniedReadPaths(), liftsRead)
	_, write = c.splitDefaults(DefaultDeniedWritePaths(), liftsWrite)
	return read, write
}

// defaultDeniedReadPaths is DefaultDeniedReadPaths with the aws section
// applied to its ~/.aws entry — the aws section is a shim over the same list,
// not a second mask. allow_raw_credentials drops the entry, since the CLI must
// read the files; force_profile (IMDS broker mode) makes it hold in every mode,
// since the credentials come from the broker and the files must stay hidden
// even where the rest of the deny list is unused. Like every built-in, a paths
// grant on ~/.aws lifts it.
func (c *Config) defaultDeniedReadPaths() []DeniedPath {
	defaults := DefaultDeniedReadPaths()
	if c == nil {
		return defaults
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return defaults
	}
	aws := filepath.Join(home, ".aws")
	switch {
	case c.AWS.AllowsRawCredentials():
		defaults = deleteDeniedPath(defaults, aws)
	case c.AWS.UsesIMDS():
		for i := range defaults {
			if defaults[i].Path == aws {
				defaults[i].AllModes = true
				defaults[i].Note = "AWS credentials; brokered via IMDS"
			}
		}
	}
	return defaults
}

// splitDefaults merges the config's paths entries over the built-in defaults:
// a default is lifted when an entry for the same path (or the default's Group)
// grants what the default denies, per lifts. It returns the defaults still in
// force and the lifted ones with LiftedBy set. Only an exact path lifts — a
// grant on a parent (a writable ~, say) leaves every default beneath it
// masked, so widening the boundary never silently drops the deny lists.
func (c *Config) splitDefaults(defaults []DeniedPath, lifts func(PathEntry) bool) (active, lifted []DeniedPath) {
	var grants []PathEntry
	for _, e := range c.AllPathEntries() {
		if lifts(e) {
			grants = append(grants, e)
		}
	}
	for _, d := range defaults {
		by := ""
		for _, e := range grants {
			if e.SamePath(d.Path) || (d.Group != "" && e.SamePath(d.Group)) {
				by = e.Path
				break
			}
		}
		if by == "" {
			active = append(active, d)
			continue
		}
		d.LiftedBy = by
		lifted = append(lifted, d)
	}
	return active, lifted
}

// liftsRead reports whether a paths entry grants read access (a write grant
// implies read), which lifts a read denial on its path.
func liftsRead(e PathEntry) bool { return e.GrantsRead() || e.GrantsWrite() }

// liftsWrite reports whether a paths entry grants write access, which lifts a
// write denial on its path.
func liftsWrite(e PathEntry) bool { return e.GrantsWrite() }

// DeniedEntriesLiftedBy returns the built-in deny-list entries that a paths
// grant on p lifts, for the CLI to say so when it records one.
func (c *Config) DeniedEntriesLiftedBy(p string) []DeniedPath {
	read, write := c.LiftedDeniedEntries()
	var out []DeniedPath
	for _, d := range append(read, write...) {
		if (PathEntry{Path: d.LiftedBy}).SamePath(p) {
			out = append(out, d)
		}
	}
	return out
}

// EffectiveDeniedReadPaths is EffectiveDeniedReadEntries as plain paths.
func (c *Config) EffectiveDeniedReadPaths() []string {
	return deniedPathStrings(c.EffectiveDeniedReadEntries())
}

// EffectiveDeniedWritePaths is EffectiveDeniedWriteEntries as plain paths.
func (c *Config) EffectiveDeniedWritePaths() []string {
	return deniedPathStrings(c.EffectiveDeniedWriteEntries())
}

// userDeniedPaths expands user-added entries and classifies each by what is
// on disk; a missing user path is recorded as a file, so it is never created.
func userDeniedPaths(paths []string) []DeniedPath {
	var out []DeniedPath
	for _, p := range expandPaths(paths) {
		out = append(out, DeniedPath{Path: p, Dir: dirExists(p)})
	}
	return out
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
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

func deleteDeniedPath(list []DeniedPath, path string) []DeniedPath {
	out := list[:0:0]
	for _, v := range list {
		if v.Path != path {
			out = append(out, v)
		}
	}
	return out
}

func uniqueDeniedPaths(list []DeniedPath) []DeniedPath {
	seen := make(map[string]bool, len(list))
	out := make([]DeniedPath, 0, len(list))
	for _, v := range list {
		if v.Path == "" || seen[v.Path] {
			continue
		}
		seen[v.Path] = true
		out = append(out, v)
	}
	return out
}
