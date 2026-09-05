// Package audit records sandbox validation findings to an append-only JSONL
// log. A finding is anything a validation layer objected to — a command not on
// the whitelist, a path outside the boundary, a blocked flag — whether or not
// the current mode actually blocked it. Each record carries the modes that
// would block it, so the log answers both "what is the sandbox rejecting right
// now?" and "what would break if I moved to a stricter mode?".
//
// The log is written by the MCP server and the PreToolUse hook, never by a
// sandboxed command. Records can carry full command strings, which may include
// inline secrets, so the file is created 0600.
package audit

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Record is one audit log line.
type Record struct {
	// Time is when the finding was recorded, RFC 3339 with sub-second precision.
	Time time.Time `json:"ts"`
	// CWD is the working directory the command or tool call ran in.
	CWD string `json:"cwd,omitempty"`
	// Mode is the enforcement mode in effect (open, denylist, allowlist).
	Mode string `json:"mode"`
	// Source is what produced the finding: "bash" for the sandboxed bash tool,
	// "hook" for the PreToolUse hook governing the agent's built-in tools.
	Source string `json:"source"`
	// Tool is the agent tool involved for hook findings (Read, Write, Bash...).
	Tool string `json:"tool,omitempty"`
	// Command is the full command string being validated, when there is one.
	Command string `json:"command,omitempty"`
	// Layer is where the finding surfaced: "static" (AST preflight), "runtime"
	// (interpreter handlers after expansion), or "hook".
	Layer string `json:"layer"`
	// Rule names the check that fired (command_whitelist, path_boundary, ...).
	Rule string `json:"rule"`
	// Message is the validation error text.
	Message string `json:"message"`
	// Subject is the thing the rule fired on when it can be isolated — the
	// command name for whitelist findings, the resolved path for boundary
	// findings — so reports can aggregate without parsing messages.
	Subject string `json:"subject,omitempty"`
	// Blocked reports whether the finding was enforced in the current mode.
	Blocked bool `json:"blocked"`
	// WouldBlockIn lists the modes in which this rule is enforced.
	WouldBlockIn []string `json:"would_block_in"`
}

// DefaultMaxBytes caps the log file. When a write finds the file larger than
// this, the oldest half of the records is dropped.
const DefaultMaxBytes int64 = 20 << 20

// Logger appends records to a JSONL file. It is safe for concurrent use. The
// file is opened per write so an external `audit clear` (or a deleted file)
// is picked up without a restart.
type Logger struct {
	path     string
	maxBytes int64
	mu       sync.Mutex
}

// New returns a Logger writing to path. maxBytes <= 0 selects DefaultMaxBytes.
func New(path string, maxBytes int64) *Logger {
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	return &Logger{path: path, maxBytes: maxBytes}
}

// Path returns the log file path.
func (l *Logger) Path() string { return l.path }

// Write appends r to the log, stamping Time when it is zero. Errors are
// returned but callers normally log and continue: auditing must never make a
// command fail.
func (l *Logger) Write(r Record) error {
	if r.Time.IsZero() {
		r.Time = time.Now()
	}
	if r.WouldBlockIn == nil {
		r.WouldBlockIn = []string{}
	}
	line, err := json.Marshal(r)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	if err := l.trimLocked(); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}

// trimLocked drops the oldest half of the log when it exceeds maxBytes.
func (l *Logger) trimLocked() error {
	fi, err := os.Stat(l.path)
	if err != nil || fi.Size() <= l.maxBytes {
		return nil
	}
	data, err := os.ReadFile(l.path)
	if err != nil {
		return err
	}
	// Cut at the first newline past the midpoint so we keep whole records.
	cut := len(data) / 2
	for cut < len(data) && data[cut] != '\n' {
		cut++
	}
	if cut >= len(data) {
		return os.WriteFile(l.path, nil, 0o600)
	}
	return os.WriteFile(l.path, data[cut+1:], 0o600)
}

// Read returns the records in the log at path recorded at or after since (all
// of them when since is zero). Malformed lines are skipped. A missing file
// yields no records and no error.
func Read(path string, since time.Time) ([]Record, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			continue
		}
		if !since.IsZero() && r.Time.Before(since) {
			continue
		}
		out = append(out, r)
	}
	return out, sc.Err()
}

// Clear truncates the log at path. A missing file is not an error.
func Clear(path string) error {
	err := os.Remove(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// DefaultPath returns the audit log location: $LITE_SANDBOX_AUDIT_LOG when set,
// otherwise audit.jsonl next to the config file in the platform config
// directory (the same directory `lite-sandbox config path` prints).
func DefaultPath() (string, error) {
	if p := os.Getenv("LITE_SANDBOX_AUDIT_LOG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine config directory: %w", err)
	}
	return filepath.Join(dir, "lite-sandbox", "audit.jsonl"), nil
}
