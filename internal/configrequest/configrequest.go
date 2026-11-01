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
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/approval"
	"github.com/gartnera/lite-sandbox/internal/gitworktree"
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

// IsHelp reports whether the request only prints help: `--help` or `-h`
// together with nothing but plain words (the subcommand path, and arguments
// cobra ignores once help is asked for), e.g. `lite-sandbox config paths
// --help`. Such a request reads and changes nothing, so it needs no approval.
//
// Any other flag disqualifies it, because whether `--help` is the help flag
// depends on how cobra parses what precedes it: in `--dir --help` it is
// --dir's value, and `--help=false` turns help off, so the subcommand runs.
// With only words around it, cobra parses `--help` as the help flag and
// prints help before it runs any hook or the command itself.
func (r Request) IsHelp() bool {
	help := false
	for _, a := range r.Args {
		switch {
		case a == "--help" || a == "-h":
			help = true
		case a == "" || strings.HasPrefix(a, "-"):
			return false
		}
	}
	return help
}

// Validate rejects a request the config tool will not run.
func (r Request) Validate() error {
	if len(r.Args) == 0 {
		return errors.New("`lite-sandbox config` needs a subcommand, e.g. `lite-sandbox config commands allow make`")
	}
	for _, a := range r.Args {
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

// DirEnv names the environment variable the server sets when it runs a config
// request: the directory the request is scoped to (DefaultDir of the working
// directory it runs in). The config subcommands refuse to run under it unless
// the directory they scope the change to is exactly that one, which catches
// whatever CheckScope's reading of the arguments missed (cobra, not
// CheckScope, decides what --dir ends up as).
const DirEnv = "LITE_SANDBOX_CONFIG_REQUEST_DIR"

// DefaultDir is the directory a config command run from cwd is scoped to when
// it has neither --dir nor --global: the root of the git repository cwd is in,
// so a change made from a subdirectory applies to the whole repository —
// inside a linked git worktree, the repository's main worktree, whose override
// every one of its worktrees inherits (config.Config.ForDirectory), so a
// change made from a throwaway worktree reaches the worktrees created later
// too. Outside a git repository it is cwd.
func DefaultDir(cwd string) string {
	if main := gitworktree.MainWorktree(cwd); main != "" {
		return filepath.Clean(main)
	}
	if top := gitworktree.Toplevel(cwd); top != "" {
		return top
	}
	return filepath.Clean(cwd)
}

// CheckScope refuses --dir in a request: the config subcommands scope a change
// to the agent's project (DefaultDir) by default, or to every directory with
// --global, which the approval prompt marks (Summary). An arbitrary directory
// is not offered, so the prompt can only ever say one of those two things.
func (r Request) CheckScope() error {
	for _, a := range r.Args {
		if a == "--" {
			break // the rest is positional
		}
		if a == "--dir" || strings.HasPrefix(a, "--dir=") {
			return errors.New("`--dir` is not allowed: a config change the agent requests applies to this project, or to every directory with --global; leave out --dir")
		}
		// cobra reads --global=1, =t, =TRUE, ... as on; only the bare flag is
		// accepted, so the prompt's reading of it (Global) is cobra's.
		if strings.HasPrefix(a, "--global=") {
			return errors.New("write `--global` without a value")
		}
	}
	return nil
}

// Global reports whether the request sets --global, editing the base config.
// CheckScope has refused every other spelling of the flag. Where another flag
// takes "--global" as its value, this overstates the scope, which errs on the
// side of the prompt warning the user.
func (r Request) Global() bool {
	for _, a := range r.Args {
		switch a {
		case "--":
			return false
		case "--global":
			return true
		}
	}
	return false
}

// Summary renders a status line for the approval prompt, a ✓ or ✗ per thing
// the request grants: for `paths allow`, read, write and internal access, and
// for every request its scope: this project, or every directory (--global).
func (r Request) Summary() string {
	mark := func(on bool, label string) string {
		if on {
			return "✓ " + label
		}
		return "✗ " + label
	}
	// boolFlag reads a bool flag the way pflag does (strconv.ParseBool), so
	// --write=1 is marked as the write it is. A value pflag would reject
	// fails the command, so marking it on is harmless.
	boolFlag := func(a, name string, v *bool) bool {
		if a == name {
			*v = true
			return true
		}
		if val, ok := strings.CutPrefix(a, name+"="); ok {
			b, err := strconv.ParseBool(val)
			*v = b || err != nil
			return true
		}
		return false
	}
	var words []string
	write, internal, commands := false, false, false
	for _, a := range r.Args {
		switch {
		case a == "--":
		case boolFlag(a, "--write", &write), boolFlag(a, "--internal", &internal):
		case a == "--commands" || strings.HasPrefix(a, "--commands="):
			commands = true
		case !strings.HasPrefix(a, "-"):
			words = append(words, a)
		}
	}
	internal = internal || commands
	var parts []string
	if len(words) >= 2 && words[0] == "paths" && words[1] == "allow" {
		parts = append(parts, mark(true, "read"), mark(write, "write"), mark(internal, "internal"))
	}
	global := r.Global()
	parts = append(parts, mark(!global, "this project"), mark(global, "global"))
	return strings.Join(parts, "  ")
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
