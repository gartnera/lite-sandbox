// Package approval records the user's approval of a tool call, made in the
// agent's permission prompt, so the MCP server can tell that the user was
// asked before it runs the call.
//
// The server cannot see the agent's permission prompt. So the approval travels
// as a ticket: the PreToolUse hook, which the agent runs before the tool call,
// answers "ask" (the agent prompts the user) and records a ticket naming the
// exact call. The server runs the call as approved only after consuming the
// matching ticket. With no hook registered there is no ticket, so the server
// treats the call as unapproved. Two kinds of call use it: config requests
// (internal/configrequest) and commands that a commands entry with
// ask: true makes wait for the user.
//
// Tickets live in lite-sandbox's cache directory, guarded like the config file
// itself: the path boundary keeps sandboxed commands' writes in the project,
// and under the OS sandbox the directory is in config.DefaultDeniedWritePaths.
// Nor can a command mint a ticket by running the hook, which the built-in
// command deny list denies. And a ticket only matters when the hook did not
// run: when it does, it asks the user about the call whatever tickets exist.
package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// TicketTTL bounds how long a ticket waits for its tool call. The hook writes
// it before the user is prompted, so it has to outlast a user who steps away
// from the prompt; anything older is from a call that never reached the server
// (the user declined, or the agent was interrupted) and is ignored.
const TicketTTL = 15 * time.Minute

// Subject names what a ticket approves: a kind ("config", "command") followed
// by the call's parts as both the hook and the server read them.
type Subject []string

// key names the ticket for subject made from cwd. The working directory goes
// in with its symlinks resolved, since the hook and the server may spell it
// differently (the event's cwd against the server's os.Getwd, /tmp against
// /private/tmp), and so a ticket from one project never names a call in
// another. Every part is length-prefixed, so no two subjects share a key.
func key(cwd string, subject Subject) string {
	if real, err := filepath.EvalSymlinks(cwd); err == nil {
		cwd = real
	}
	h := sha256.New()
	fmt.Fprintf(h, "%d:%s\x00", len(cwd), filepath.Clean(cwd))
	for _, a := range subject {
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
	return filepath.Join(cache, "lite-sandbox", "approvals"), nil
}

// Issue records a ticket for subject made from cwd (see key); display is
// written into it for whoever looks. The hook calls it as it asks the user to
// approve the call.
func Issue(cwd string, subject Subject, display string) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	pruneExpired(dir)
	p := filepath.Join(dir, key(cwd, subject))
	tmp, err := os.CreateTemp(dir, ".ticket-*")
	if err != nil {
		return err
	}
	_, werr := tmp.WriteString(display + "\n")
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

// ErrNoTicket is returned by Consume when no live ticket matches the call:
// the PreToolUse hook did not run for it, so the user was never asked.
var ErrNoTicket = errors.New("no approval was recorded for this request")

// Consume takes the ticket for subject made from cwd, so each approval
// covers exactly one call. It returns ErrNoTicket when there is none, or only
// an expired one.
func Consume(cwd string, subject Subject) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	p := filepath.Join(dir, key(cwd, subject))
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

// CommandSubject is the subject of a bash tool call whose command runs a
// prompted invocation (a commands entry with ask: true): the command
// string exactly as the tool received it.
func CommandSubject(command string) Subject {
	return Subject{"command", command}
}
