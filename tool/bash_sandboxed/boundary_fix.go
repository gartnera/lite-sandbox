package bash_sandboxed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/audit"
)

// boundaryError is the refusal of a path outside the allowed directories: a
// command argument, a redirection target, or a file a monty program opens.
// Its message is the bare refusal. Where the sandbox reports it to the agent
// (Sandbox.report, montyFS.authorize) it is extended with the `lite-sandbox
// config paths allow` command that would lift it, when there is one worth
// naming (boundaryFix).
type boundaryError struct {
	what     string // "path" or "redirect path"
	orig     string // the path as written
	abs      string // orig made absolute against the working directory, symlinks not followed
	resolved string // abs with symlinks followed
	write    bool   // checked against the write set
}

func newBoundaryError(what, orig, path, workDir, resolved string, write bool) *boundaryError {
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(workDir, abs)
	}
	return &boundaryError{what: what, orig: orig, abs: filepath.Clean(abs), resolved: resolved, write: write}
}

func (e *boundaryError) Error() string {
	return fmt.Sprintf("%s %q resolves to %q which is outside allowed directories", e.what, e.orig, e.resolved)
}

// withBoundaryFix returns err extended with the config command that would
// lift the boundary refusal it carries, or err itself when it carries none or
// boundaryFix names none. The extended error wraps err, so its rule tag is
// still found.
func withBoundaryFix(cfg *config.Config, err error) error {
	var be *boundaryError
	if !errors.As(err, &be) {
		return err
	}
	fix := boundaryFix(cfg, be)
	if fix == "" {
		return err
	}
	return fmt.Errorf("%w; if it is needed, the user can allow it with `%s`", err, fix)
}

// boundaryFix returns the `lite-sandbox config paths allow` command that
// would let e's path through, or "" when there is none worth naming. The
// command is the user's to approve (a config request asks them), but the
// sandbox shouldn't propose widening the boundary to where it refuses on
// purpose, so there is none for:
//   - a grant that would reach something protected (protectedOverlap): the
//     home directory or an ancestor of it; a protected entry
//     (protectedEntries: the deny lists — the sandbox's own config, audit
//     log and approval tickets, credentials, shell startup files, agent
//     settings, ... — hidden-home credential masks, the runtime directory,
//     internal grants), an entry under the path, or a path under an entry;
//     and system roots and /run outside the home directory. The deny lists
//     only bind the OS sandbox in denylist mode, so a grant over one would
//     open it to the path checks and to Python everywhere else.
//   - a path inside .git, or a write to a coding agent's configuration,
//     which stay refused whatever the paths config says.
//   - a path that can't be written as a literal word a config request
//     accepts, or one whose last element is "*", which the config reads as
//     "nested below the parent" rather than the file.
//
// A read names the path itself. A write names the directory that holds it,
// unless the path is itself an existing directory: the OS sandbox creates a
// write grant as a directory when it does not exist, which would turn the
// file the command meant to write into a directory.
func boundaryFix(cfg *config.Config, e *boundaryError) string {
	target := e.resolved
	if e.write {
		if fi, err := os.Stat(target); err != nil || !fi.IsDir() {
			target = filepath.Dir(target)
		}
		if AgentConfigMatch(e.abs) != "" || AgentConfigMatch(e.resolved) != "" || AgentConfigMatch(target) != "" {
			return ""
		}
	}
	if isGitInternalPath(e.resolved) || isGitInternalPath(target) || filepath.Base(target) == ".git" {
		return ""
	}
	if filepath.Base(target) == "*" {
		return ""
	}
	protected := protectedEntries(cfg)
	if protectedOverlap(protected, e.abs) || protectedOverlap(protected, e.resolved) || protectedOverlap(protected, target) {
		return ""
	}
	word, ok := configWord(target)
	if !ok {
		return ""
	}
	fix := "lite-sandbox config paths allow " + word
	if e.write {
		fix += " --write"
	}
	return fix
}

// protectedOverlap reports whether a grant on path would reach something the
// sandbox protects on purpose: path is the home directory or an ancestor of
// it, a protected entry (protectedEntries) is path, under it or above it, or
// path is in a system root (audit.SystemRoots, plus /run) outside the home
// directory. Each protected entry is
// compared both as written and with symlinks followed, and on macOS without
// regard to case, since its default filesystem ignores case (~/.SSH is
// ~/.ssh).
func protectedOverlap(protected []string, path string) bool {
	if path == string(filepath.Separator) {
		return true
	}
	var homes []string
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		homes = withResolved(filepath.Clean(home))
	}
	for _, h := range homes {
		if pathWithin(h, path) {
			return true // the home directory itself, or above it
		}
	}
	for _, d := range protected {
		if !filepath.IsAbs(d) {
			continue
		}
		for _, p := range withResolved(filepath.Clean(d)) {
			if pathWithin(path, p) || pathWithin(p, path) {
				return true
			}
		}
	}
	for _, h := range homes {
		if pathWithin(path, h) {
			return false // under the home directory, wherever it lives
		}
	}
	for _, root := range append(audit.SystemRoots(), "/run") {
		for _, r := range withResolved(root) {
			if pathWithin(path, r) {
				return true
			}
		}
	}
	return false
}

// protectedEntries returns the paths a fix must neither name nor cover: both
// deny lists, the credential masks inside the hidden home, the user's runtime
// directory (agent sockets, the session bus), the paths of internal grants,
// which are meant for the programs a command starts (or, scoped, for one CLI)
// and never for the agent's own reads and writes, and what the OS sandbox
// worker alone guards: the lite-sandbox binary and the PATH directories ahead
// of it, the coding agents' control sockets and configuration directories
// (installed or not), and docker's state (buildx builders, daemon sockets).
func protectedEntries(cfg *config.Config) []string {
	var out []string
	if d := config.UserRuntimeDir(); d != "" {
		out = append(out, d)
	}
	// What only the OS sandbox worker protects (workerOptions, guardHost):
	// shell redirects and Python file operations run in the server process,
	// past the worker, so a grant over these would expose them there.
	out = append(out, config.ServerExecutable()...)
	out = append(out, config.AgentSocketDirs()...)
	out = append(out, config.AgentSocketPaths()...)
	out = append(out, config.AgentConfigDirs()...)
	if dir := config.BuildxConfigDir(); filepath.IsAbs(dir) {
		out = append(out, dir)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		// The docker daemon sockets the proxy masks live in these.
		out = append(out, filepath.Join(home, ".docker"), filepath.Join(home, ".orbstack"), filepath.Join(home, ".colima"))
	}
	if cfg == nil {
		return out
	}
	out = append(out, cfg.HostProgramDirs(os.Getenv("PATH"))...)
	out = append(out, cfg.Docker.UpstreamSocket()) // nil-safe: detects the daemon's socket
	out = append(out, cfg.EffectiveDeniedReadPaths()...)
	out = append(out, cfg.EffectiveDeniedWritePaths()...)
	for _, d := range cfg.HiddenHomeDeniedReadEntries() {
		out = append(out, d.Path)
	}
	for _, e := range cfg.Paths {
		if e.Internal && e.Grants() {
			if p := config.ExpandPath(strings.TrimSuffix(e.Path, "/*")); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// withResolved returns p and, when it differs, p with symlinks followed.
func withResolved(p string) []string {
	if r := ResolvePath(p, string(filepath.Separator)); r != p {
		return []string{p, r}
	}
	return []string{p}
}

// pathWithin reports whether path is dir or below it, ignoring case on macOS.
func pathWithin(path, dir string) bool {
	if runtime.GOOS == "darwin" {
		path, dir = strings.ToLower(path), strings.ToLower(dir)
	}
	dir = strings.TrimSuffix(dir, string(filepath.Separator))
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}

// configWord writes s as one shell word that a config request takes as a
// literal argument (see internal/configrequest): bare when it is a plain
// word, else single-quoted, else double-quoted. ok is false when s has both a
// single quote and a character a double-quoted literal can't hold.
func configWord(s string) (word string, ok bool) {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@+,", r))
	}) < 0 {
		return s, true
	}
	if !strings.Contains(s, "'") {
		return "'" + s + "'", true
	}
	if !strings.ContainsAny(s, "\\$`\"") {
		return `"` + s + `"`, true
	}
	return "", false
}
