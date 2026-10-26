package config

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// The OS sandbox worker hides the user's private state from the programs it
// runs: a dependency's install script, a test, or a local binary can read
// anything the worker can, and a credential stealer reads every file it can
// find under $HOME (browser profiles, wallets, ~/.config/*, token files) and
// asks the keyring for the rest. The static path checks never see those
// reads, so only the worker can stop them. With hiding on (the default):
//
//   - $HOME is empty and read-only (allowlist mode; denylist mode binds it
//     writable and relies on its deny lists instead), except for the working
//     directory, every paths grant (profile toolchain dirs included), the
//     built-ins of HomeVisiblePaths, and the worker binary itself;
//   - the user's runtime directory ($XDG_RUNTIME_DIR, Linux) is hidden in
//     denylist mode too: it holds the session D-Bus (the Secret Service: gnome-keyring,
//     KWallet), the keyring's own sockets, and the gpg and ssh agents;
//   - on macOS the keychain daemon is not reachable unless a grant exposes
//     ~/Library/Keychains (see KeychainDir).
//
// A grant re-exposes a path the usual way (paths allow ~/.npmrc --internal),
// and os_sandbox_hide_home: false turns all of it off. Open mode, which only
// audits, hides nothing.

// OSSandboxHidesHome reports whether the OS sandbox worker hides $HOME and the
// user's runtime directory (default: true). See the OSSandboxHideHome field.
func (c *Config) OSSandboxHidesHome() bool {
	if c == nil || c.OSSandboxHideHome == nil {
		return true
	}
	return *c.OSSandboxHideHome
}

// HidesPrivateState reports whether a worker built from c hides the user's
// private state: hiding is on, and the mode enforces anything (open mode,
// which only audits, leaves the worker's reads as they were).
func (c *Config) HidesPrivateState() bool {
	return c.OSSandboxHidesHome() && c.EffectiveMode() != ModeOpen
}

// HomeVisiblePaths returns the paths under the home directory a worker that
// hides it still shows, besides the config's grants: git's configuration
// (~/.gitconfig, $XDG_CONFIG_HOME/git; its credential store is masked by
// HiddenHomeDeniedReadEntries), ~/.aws when the aws section reads raw
// credentials, the docker CLI's config directory when docker is enabled, the
// non-key files of ~/.ssh (SSHPublicFiles), and the toolchains installed under $HOME that the server's PATH names
// (HomePathToolchains). Paths are absolute and exist.
func (c *Config) HomeVisiblePaths() []string {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	out := []string{
		filepath.Join(home, ".gitconfig"),
		filepath.Join(xdgConfigHome(home), "git"),
	}
	if c != nil && c.AWS.AllowsRawCredentials() {
		out = append(out, filepath.Join(home, ".aws"))
	}
	if c != nil && c.Docker.DockerEnabled() {
		if dir := DockerConfigDir(); filepath.IsAbs(dir) {
			out = append(out, dir)
		}
	}
	out = slices.DeleteFunc(out, func(p string) bool { return !pathExists(p) })
	out = append(out, SSHPublicFiles(home)...)
	return append(out, HomePathToolchains(home, os.Getenv("PATH"))...)
}

// HiddenHomeDeniedReadEntries returns the credential files inside the
// directories a hidden home still shows that must stay hidden: git's
// credential store, and cargo's registry token, since the rust profile grants
// all of ~/.cargo and a build script runs with it. A grant on the file itself
// lifts its entry. Only existing files are returned: bubblewrap cannot mask a
// missing one, and one created later is masked from the next worker start.
func (c *Config) HiddenHomeDeniedReadEntries() []DeniedPath {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	cargo := os.Getenv("CARGO_HOME")
	if cargo == "" {
		cargo = filepath.Join(home, ".cargo")
	}
	candidates := []DeniedPath{
		{Path: filepath.Join(home, ".git-credentials")},
		{Path: filepath.Join(xdgConfigHome(home), "git", "credentials")},
		{Path: filepath.Join(cargo, "credentials.toml")},
		{Path: filepath.Join(cargo, "credentials")},
	}
	var out []DeniedPath
	for _, d := range candidates {
		if !pathExists(d.Path) {
			continue
		}
		lifted := false
		for _, e := range c.AllPathEntries() {
			if e.GrantsRead() && !e.Scoped() && e.SamePath(d.Path) {
				lifted = true
				break
			}
		}
		if !lifted {
			out = append(out, d)
		}
	}
	return out
}

// HomePathToolchains returns what a hidden home must keep showing so the
// programs on pathEnv that are installed under home still run: each PATH
// directory under home, and the installation it belongs to. A directory named
// bin or shims stands for its parent (~/.cargo/bin for ~/.cargo,
// ~/.nvm/versions/node/v22/bin for the node install with its lib/), and a
// symlink in a PATH directory for its target's installation
// (~/.local/bin/ruff -> ~/.local/share/uv/tools/ruff/bin/ruff for
// ~/.local/share/uv/tools/ruff), followed one link further (that venv's
// bin/python, into a uv-managed interpreter). Directories that hold more than one tool's
// state ($HOME itself, ~/.local, ~/.local/share, ~/.config, ~/Library) are
// never exposed whole.
func HomePathToolchains(home, pathEnv string) []string {
	if home == "" {
		return nil
	}
	home = filepath.Clean(home)
	homes := []string{home}
	if r, err := filepath.EvalSymlinks(home); err == nil && r != home {
		homes = append(homes, r)
	}
	shared := map[string]bool{}
	for _, h := range homes {
		for _, d := range []string{"", ".local", ".local/share", ".local/state", ".config", ".cache", "Library", "Library/Application Support"} {
			shared[filepath.Join(h, d)] = true
		}
	}
	shared[filepath.Clean(xdgConfigHome(home))] = true
	underHome := func(p string) bool {
		for _, h := range homes {
			if strings.HasPrefix(p, h+string(filepath.Separator)) {
				return true
			}
		}
		return false
	}
	var out []string
	add := func(p string) {
		if !underHome(p) || shared[p] || slices.Contains(out, p) {
			return
		}
		out = append(out, p)
	}
	// install exposes the installation dir belongs to and, depth levels
	// deep, those of the symlinks in it: a PATH entry's link to a tool's
	// venv, and the venv's link to its interpreter.
	var install func(dir string, depth int)
	install = func(dir string, depth int) {
		add(dir)
		if b := filepath.Base(dir); b == "bin" || b == "shims" {
			add(filepath.Dir(dir))
		}
		if depth == 0 {
			return
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, ent := range entries {
			if ent.Type()&os.ModeSymlink == 0 {
				continue
			}
			target, err := filepath.EvalSymlinks(filepath.Join(dir, ent.Name()))
			if err != nil || !underHome(target) {
				continue
			}
			install(filepath.Dir(target), depth-1)
		}
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if dir == "" || !filepath.IsAbs(dir) {
			continue
		}
		if dir = filepath.Clean(dir); underHome(dir) {
			install(dir, 2)
		}
	}
	return out
}

// HiddenDirs returns the directories a worker built from c hides (see the
// package comment above): $HOME in allowlist mode, and the user's runtime
// directory in denylist mode too. None when hiding is off, and in open mode.
func (c *Config) HiddenDirs() []string {
	if !c.HidesPrivateState() {
		return nil
	}
	var out []string
	if c.EffectiveMode() == ModeAllowlist {
		if home, err := os.UserHomeDir(); err == nil && home != "" && home != "/" {
			out = append(out, home)
		}
	}
	if d := UserRuntimeDir(); d != "" {
		out = append(out, d)
	}
	return out
}

// UserRuntimeDir returns the user's runtime directory: $XDG_RUNTIME_DIR, or
// /run/user/<uid> when that exists. "" on macOS, which has none, and when
// neither is set or present.
func UserRuntimeDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" && filepath.IsAbs(d) && filepath.Clean(d) != "/" {
		return filepath.Clean(d)
	}
	if d := filepath.Join("/run/user", strconv.Itoa(os.Getuid())); dirExists(d) {
		return d
	}
	return ""
}

// KeychainDir returns the directory of the user's macOS keychains. A worker
// in which it is hidden (or read-denied) also cannot reach the keychain
// daemon; a grant on it gives a command both back.
func KeychainDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, "Library", "Keychains")
}
