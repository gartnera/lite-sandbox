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
// approval travels as a ticket: the PreToolUse hook, which the agent runs
// before the tool call, answers "ask" (the agent prompts the user) and records
// a ticket naming the exact arguments. The server runs a request only after
// consuming the matching ticket. With no hook registered there is no ticket,
// so the server refuses instead of making an unapproved change.
//
// Tickets live in lite-sandbox's cache directory, guarded like the config file
// itself: the path boundary keeps sandboxed commands' writes in the project,
// and under the OS sandbox the directory is in config.DefaultDeniedWritePaths.
// Nor can a command mint a ticket by running the hook, which the built-in
// command deny list denies. And a ticket only matters when the hook did not
// run: when it does, it asks the user about the call whatever tickets exist.
package configrequest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"mvdan.cc/sh/v3/syntax"

	"github.com/gartnera/lite-sandbox/config"
)

// TicketTTL bounds how long a ticket waits for its tool call. The hook writes
// it before the user is prompted, so it has to outlast a user who steps away
// from the prompt; anything older is from a call that never reached the server
// (the user declined, or the agent was interrupted) and is ignored.
const TicketTTL = 15 * time.Minute

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

// key names a request's ticket.
func (r Request) key() string {
	h := sha256.New()
	for _, a := range r.Args {
		fmt.Fprintf(h, "%d:%s\x00", len(a), a)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Dir is the directory tickets are kept in.
func Dir() (string, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine cache directory: %w", err)
	}
	return filepath.Join(cache, "lite-sandbox", "config-requests"), nil
}

// Issue records a ticket for r. The hook calls it as it asks the user to
// approve the call.
func Issue(r Request) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	pruneExpired(dir)
	p := filepath.Join(dir, r.key())
	tmp, err := os.CreateTemp(dir, ".ticket-*")
	if err != nil {
		return err
	}
	_, werr := tmp.WriteString(r.Command() + "\n")
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmp.Name())
		return werr
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// ErrNoTicket is returned by Consume when no live ticket matches the request:
// the PreToolUse hook did not run for it, so the user was never asked.
var ErrNoTicket = errors.New("no approval was recorded for this request")

// Consume takes the ticket for r, so each approval runs exactly one request.
// It returns ErrNoTicket when there is none, or only an expired one.
func Consume(r Request) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	p := filepath.Join(dir, r.key())
	info, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNoTicket
	}
	if err != nil {
		return err
	}
	// Remove first: of two concurrent calls only one removal succeeds, and
	// only that one may run.
	if err := os.Remove(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return ErrNoTicket
		}
		return err
	}
	if !info.Mode().IsRegular() || time.Since(info.ModTime()) > TicketTTL {
		return ErrNoTicket
	}
	return nil
}

// pruneExpired removes tickets past their TTL, which are left behind by calls
// the user declined.
func pruneExpired(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		if time.Since(info.ModTime()) > TicketTTL {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}
