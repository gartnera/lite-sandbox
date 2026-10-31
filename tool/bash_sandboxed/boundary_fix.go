package bash_sandboxed

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
// sandbox shouldn't propose widening the boundary to where it is refusing on
// purpose, so there is none for:
//   - a path the audit report never suggests either (audit.IsProtected): the
//     home directory itself, anything under a deny-list entry (the sandbox's
//     own config and audit log, credentials, agent settings, ...), and system
//     roots outside the home directory. Granting a deny-listed path would lift
//     that entry.
//   - a write to a coding agent's configuration, which stays read-only
//     whatever the paths config says (checkAgentConfigWrite).
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
	if filepath.Base(target) == "*" {
		return ""
	}
	var protected []string
	if cfg != nil {
		protected = append(cfg.EffectiveDeniedReadPaths(), cfg.EffectiveDeniedWritePaths()...)
	}
	if audit.IsProtected(e.resolved, protected) || audit.IsProtected(target, protected) {
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
