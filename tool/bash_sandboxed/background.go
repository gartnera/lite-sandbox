package bash_sandboxed

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// maxBackgroundOutputBytes caps the amount of output retained per background
// process. Long-running, chatty commands (e.g. dev servers, log tailers) could
// otherwise grow unbounded; once the cap is reached the oldest bytes are
// dropped so the most recent output is always available.
const maxBackgroundOutputBytes = 1 << 20 // 1 MiB

// streamBuffer is a goroutine-safe, capped output buffer with an incremental
// read cursor. Background processes write into it continuously while callers
// drain only the bytes produced since their last read (mirroring the Claude
// Code BashOutput tool, which returns new output each call).
type streamBuffer struct {
	mu        sync.Mutex
	buf       []byte
	discarded int // total bytes dropped from the front due to the cap
	readPos   int // absolute offset of the next unread byte
	cap       int
}

func newStreamBuffer(cap int) *streamBuffer {
	return &streamBuffer{cap: cap}
}

// Write appends p, dropping the oldest bytes if the cap would be exceeded.
func (b *streamBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	if b.cap > 0 && len(b.buf) > b.cap {
		drop := len(b.buf) - b.cap
		b.buf = b.buf[drop:]
		b.discarded += drop
	}
	return len(p), nil
}

// readNew returns all output produced since the previous readNew call and
// advances the read cursor.
func (b *streamBuffer) readNew() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	start := b.readPos - b.discarded
	if start < 0 {
		start = 0
	}
	if start > len(b.buf) {
		start = len(b.buf)
	}
	out := string(b.buf[start:])
	b.readPos = b.discarded + len(b.buf)
	return out
}

// BackgroundProcess represents a single command launched in the background.
type BackgroundProcess struct {
	ID      string
	Command string

	output  *streamBuffer
	cancel  context.CancelFunc
	started time.Time

	mu       sync.Mutex
	done     bool
	killed   bool
	exitCode int
	runErr   error
	ended    time.Time
}

// Status reports the current lifecycle state: "running", "completed",
// "failed", or "killed".
func (p *BackgroundProcess) Status() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.statusLocked()
}

func (p *BackgroundProcess) statusLocked() string {
	if !p.done {
		return "running"
	}
	if p.killed {
		return "killed"
	}
	if p.runErr != nil {
		return "failed"
	}
	return "completed"
}

// BackgroundOutputResult is a snapshot returned by BackgroundOutput.
type BackgroundOutputResult struct {
	ID       string
	Command  string
	Status   string
	Done     bool
	ExitCode int
	Output   string
}

// BackgroundStatus is a lightweight summary used when listing processes.
type BackgroundStatus struct {
	ID       string
	Command  string
	Status   string
	ExitCode int
}

// backgroundManager owns the set of live background processes.
type backgroundManager struct {
	mu      sync.Mutex
	procs   map[string]*BackgroundProcess
	counter int
}

func newBackgroundManager() *backgroundManager {
	return &backgroundManager{procs: make(map[string]*BackgroundProcess)}
}

func (m *backgroundManager) create(command string) *BackgroundProcess {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counter++
	id := fmt.Sprintf("bash_%d", m.counter)
	p := &BackgroundProcess{
		ID:      id,
		Command: command,
		output:  newStreamBuffer(maxBackgroundOutputBytes),
		started: time.Now(),
	}
	m.procs[id] = p
	return p
}

func (m *backgroundManager) get(id string) (*BackgroundProcess, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.procs[id]
	return p, ok
}

func (m *backgroundManager) list() []*BackgroundProcess {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*BackgroundProcess, 0, len(m.procs))
	for _, p := range m.procs {
		out = append(out, p)
	}
	return out
}

// finish records the terminal state of a process once its goroutine returns.
func (m *backgroundManager) finish(p *BackgroundProcess, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done = true
	p.ended = time.Now()
	p.runErr = err
	p.exitCode = exitCodeFromErr(err, p.killed)
}

// killAll cancels every running background process. Used on sandbox shutdown.
func (m *backgroundManager) killAll() {
	for _, p := range m.list() {
		p.mu.Lock()
		alreadyDone := p.done
		if !alreadyDone {
			p.killed = true
		}
		cancel := p.cancel
		p.mu.Unlock()
		if !alreadyDone && cancel != nil {
			cancel()
		}
	}
}

// exitCodeFromErr maps a runner error to a conventional exit code.
func exitCodeFromErr(err error, killed bool) int {
	if err == nil {
		return 0
	}
	if killed {
		return 137 // 128 + SIGKILL
	}
	var status interp.ExitStatus
	if errors.As(err, &status) {
		return int(status)
	}
	return 1
}

// ExecuteBackground validates a command, then launches it in the background and
// returns immediately with a handle. Validation errors are returned
// synchronously; runtime failures are recorded on the returned process and
// surfaced later via BackgroundOutput. This mirrors the Claude Code Bash tool's
// run_in_background option.
func (s *Sandbox) ExecuteBackground(command string, workDir string, readAllowedPaths, writeAllowedPaths []string) (*BackgroundProcess, error) {
	isExtra := s.isExtraCommandInvocation(command)

	var f *syntax.File
	if !isExtra {
		var err error
		f, err = ParseBash(command)
		if err != nil {
			return nil, err
		}
		if err := s.validateWithWorkDir(f, workDir); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		if err := validatePaths(f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		if err := validateRedirectPaths(f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
	}

	proc := s.bg.create(command)

	// Detached from any request context so the process outlives the call.
	// Cancellation is driven by KillBackground / Close via the stored cancel.
	ctx, cancel := context.WithCancel(context.Background())
	proc.cancel = cancel

	go func() {
		defer cancel()
		var err error
		if isExtra {
			err = s.runRawToWriter(ctx, command, workDir, proc.output)
		} else {
			err = s.runInterpToWriter(ctx, f, workDir, readAllowedPaths, writeAllowedPaths, proc.output)
		}
		s.bg.finish(proc, err)
	}()

	return proc, nil
}

// BackgroundOutput returns the output produced by the given background process
// since the previous call, along with its current status. An optional filter
// is applied as a regular expression that retains only matching output lines.
func (s *Sandbox) BackgroundOutput(id string, filter string) (*BackgroundOutputResult, error) {
	p, ok := s.bg.get(id)
	if !ok {
		return nil, fmt.Errorf("no background process with id %q", id)
	}

	output := p.output.readNew()
	if filter != "" {
		re, err := regexp.Compile(filter)
		if err != nil {
			return nil, fmt.Errorf("invalid filter regex: %w", err)
		}
		output = filterLines(output, re)
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	return &BackgroundOutputResult{
		ID:       p.ID,
		Command:  p.Command,
		Status:   p.statusLocked(),
		Done:     p.done,
		ExitCode: p.exitCode,
		Output:   output,
	}, nil
}

// KillBackground stops a running background process. It returns an error if the
// id is unknown or the process has already exited.
func (s *Sandbox) KillBackground(id string) error {
	p, ok := s.bg.get(id)
	if !ok {
		return fmt.Errorf("no background process with id %q", id)
	}
	p.mu.Lock()
	if p.done {
		status := p.statusLocked()
		p.mu.Unlock()
		return fmt.Errorf("background process %q already exited (%s)", id, status)
	}
	p.killed = true
	cancel := p.cancel
	p.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return nil
}

// ListBackground returns a summary of all known background processes.
func (s *Sandbox) ListBackground() []BackgroundStatus {
	procs := s.bg.list()
	out := make([]BackgroundStatus, 0, len(procs))
	for _, p := range procs {
		p.mu.Lock()
		out = append(out, BackgroundStatus{
			ID:       p.ID,
			Command:  p.Command,
			Status:   p.statusLocked(),
			ExitCode: p.exitCode,
		})
		p.mu.Unlock()
	}
	return out
}

// filterLines returns only the lines of s that match re, preserving order.
func filterLines(s string, re *regexp.Regexp) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if re.MatchString(line) {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}
