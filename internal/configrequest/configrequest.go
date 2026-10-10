// Package configrequest lets an agent change lite-sandbox's own configuration
// by running `lite-sandbox config ...` with the bash tool, only with the user's
// approval each time.
//
// The sandbox denies `lite-sandbox config` to every sandboxed command, because
// a policy the agent can rewrite governs nothing. A config request is the one
// way past that deny: a bash tool call whose whole command is a single
// `lite-sandbox config` invocation with literal arguments (see Parse), which
// the MCP server runs itself, outside the sandbox — but only once the user has
// approved it. The server cannot see the agent's permission prompt, so the
// approval travels as a ticket (internal/approval): the PreToolUse hook, which
// the agent runs before the tool call, answers "ask" (the agent prompts the
// user) and records a ticket naming the exact arguments. The server runs a
// request only after consuming the matching ticket. With no hook registered
// there is no ticket, so the server refuses instead of making an unapproved
// change.
package configrequest

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/approval"
)

// Request is a config request: the arguments to `lite-sandbox config`.
type Request struct {
	Args []string
}

// Parse reports whether command is a config request: exactly one simple
// command, `lite-sandbox config` (under any name this binary is installed as,
// with or without a path) followed by literal words. Anything more —
// a pipeline, a list, a redirection, an assignment, a substitution, a
// variable — is not, and goes to the sandbox, whose deny list refuses it: the
// user approves the command they see, so it must be all that runs. The binary
// that runs is always this one, never the path the command names.
func Parse(command string) (Request, bool) {
	if !strings.Contains(command, "config") {
		return Request{}, false // the hook's fast path for every other command
	}
	f, err := syntax.NewParser().Parse(strings.NewReader(command), "")
	if err != nil || len(f.Stmts) != 1 {
		return Request{}, false
	}
	st := f.Stmts[0]
	if st.Negated || st.Background || st.Coprocess || len(st.Redirs) > 0 {
		return Request{}, false
	}
	call, ok := st.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) > 0 || len(call.Args) < 2 {
		return Request{}, false
	}
	words := make([]string, len(call.Args))
	for i, w := range call.Args {
		lit, ok := literal(w)
		if !ok {
			return Request{}, false
		}
		words[i] = lit
	}
	if !slices.Contains(config.SelfCommandNames(), filepath.Base(words[0])) || words[1] != "config" {
		return Request{}, false
	}
	return Request{Args: words[2:]}, true
}

// literal returns a word's value when it has no expansion: plain text and
// quoted plain text only. A leading ~ is kept as written; the config
// subcommands expand it themselves.
func literal(w *syntax.Word) (string, bool) {
	var b strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(p.Value, "\\*?[{") {
				return "", false // escapes, globs and braces: not worth interpreting
			}
			b.WriteString(p.Value)
		case *syntax.SglQuoted:
			if p.Dollar {
				return "", false
			}
			b.WriteString(p.Value)
		case *syntax.DblQuoted:
			for _, q := range p.Parts {
				lit, ok := q.(*syntax.Lit)
				if !ok || strings.ContainsAny(lit.Value, "\\") {
					return "", false
				}
				b.WriteString(lit.Value)
			}
		default:
			return "", false
		}
	}
	return b.String(), true
}

// Validate rejects a request the config tool will not run.
func (r Request) Validate() error {
	if len(r.Args) == 0 {
		return errors.New("`lite-sandbox config` needs a subcommand, e.g. `lite-sandbox config commands allow make`")
	}
	for i := 0; i < len(r.Args); i++ {
		a := r.Args[i]
		if a == "--dir" {
			i++ // its value
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if a == "edit" {
			// `config edit` opens $EDITOR; there is no terminal to open it on.
			return errors.New("`lite-sandbox config edit` is interactive and cannot be run here; request the individual change instead (e.g. `lite-sandbox config paths allow <path>`)")
		}
		break
	}
	return nil
}

// RootEnv names the environment variable the server sets when it runs a
// config request: the directory the request is confined to. The config
// subcommands refuse to run under it unless --dir names that directory or one
// beneath it, which catches whatever Scope's reading of the arguments missed
// (cobra, not Scope, decides what --dir ends up as).
const RootEnv = "LITE_SANDBOX_CONFIG_REQUEST_ROOT"

// Scope confines the request to cwd, the directory the agent works in. A
// config request never edits the global config: the change is always a
// per-directory override (--dir) for cwd or a directory beneath it. A request
// that names no --dir gets `--dir <cwd>`; one whose --dir points elsewhere —
// a parent, a sibling, $HOME, / — is refused, since an override there would
// reach beyond the project the user is approving changes for.
//
// Every --dir is rewritten as the absolute directory it names, so the
// command the user approves says which directory it changes, and is exactly
// what runs. The hook and the server both scope the request, so the user
// approves the command the server runs.
func (r Request) Scope(cwd string) (Request, error) {
	cwd = filepath.Clean(cwd)
	args := slices.Clone(r.Args)
	found := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break // the rest is positional
		}
		var dir string
		switch {
		case a == "--dir":
			if i+1 >= len(args) {
				return Request{}, errors.New("`--dir` needs a directory")
			}
			i++
			dir = args[i]
		case strings.HasPrefix(a, "--dir="):
			dir = strings.TrimPrefix(a, "--dir=")
		default:
			continue
		}
		// An empty --dir is no --dir at all to the config subcommands: global.
		if dir == "" {
			return Request{}, errors.New("`--dir` needs a directory")
		}
		abs := ResolveDir(cwd, dir)
		if !Within(cwd, abs) {
			return Request{}, fmt.Errorf("`--dir %s` is outside the working directory %s: config changes the agent requests apply only to the project, as a per-directory override for %s or a directory beneath it", dir, cwd, cwd)
		}
		if a == "--dir" {
			args[i] = abs
		} else {
			args[i] = "--dir=" + abs
		}
		found = true
	}
	if !found {
		args = append([]string{"--dir", cwd}, args...)
	}
	return Request{Args: args}, nil
}

// ResolveDir resolves a --dir value the way the config subcommands do — a
// leading ~ is the home directory, a relative path is taken from cwd — and
// cleans it.
func ResolveDir(cwd, dir string) string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if dir == "~" {
			dir = home
		} else if strings.HasPrefix(dir, "~/") {
			dir = filepath.Join(home, dir[2:])
		}
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(cwd, dir)
	}
	return filepath.Clean(dir)
}

// Within reports whether dir is root or a directory beneath it. Both must be
// absolute and clean. The comparison is lexical, as override matching is.
func Within(root, dir string) bool {
	if dir == "" {
		return false
	}
	rel, err := filepath.Rel(root, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// Command renders the request as the command line it runs.
func (r Request) Command() string {
	quoted := make([]string, len(r.Args))
	for i, a := range r.Args {
		quoted[i] = shellQuote(a)
	}
	return "lite-sandbox config " + strings.Join(quoted, " ")
}

// shellQuote quotes s for display when it is not a plain word.
func shellQuote(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_./:=@~+,", r))
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// subject is the approval subject of request r: its arguments as the agent
// wrote them, before Scope. Those are what the hook and the server both read
// from the same command, whereas the scoped arguments carry cwd, which the two
// may spell differently; the ticket is keyed on the working directory itself
// (see approval.Issue).
func (r Request) subject() approval.Subject {
	return append(approval.Subject{"config"}, r.Args...)
}

// Issue records a ticket for request r made from cwd. The hook calls it as it
// asks the user to approve the call.
func Issue(cwd string, r Request) error {
	return approval.Issue(cwd, r.subject(), r.Command())
}

// ErrNoTicket is returned by Consume when no live ticket matches the request:
// the PreToolUse hook did not run for it, so the user was never asked.
var ErrNoTicket = approval.ErrNoTicket

// Consume takes the ticket for request r made from cwd, so each approval runs
// exactly one request. It returns ErrNoTicket when there is none, or only an
// expired one.
func Consume(cwd string, r Request) error {
	return approval.Consume(cwd, r.subject())
}
