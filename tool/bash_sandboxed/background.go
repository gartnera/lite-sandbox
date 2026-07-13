package bash_sandboxed

import (
	"bytes"
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

// readNew returns all output produced since the previous read and advances the
// read cursor.
func (b *streamBuffer) readNew() string {
	return b.read(false)
}

// read returns output produced since the previous read and advances the cursor.
// When holdPartial is true, a trailing line that has not yet been terminated by
// a newline is left unread (the cursor stops after the last newline), so callers
// that match against whole lines never see a line split across two reads. If no
// complete line is available, it returns "" and consumes nothing.
func (b *streamBuffer) read(holdPartial bool) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	start := b.readPos - b.discarded
	if start < 0 {
		start = 0
	}
	if start > len(b.buf) {
		start = len(b.buf)
	}
	avail := b.buf[start:]
	end := len(avail)
	if holdPartial {
		nl := bytes.LastIndexByte(avail, '\n')
		if nl < 0 {
			return "" // no complete line yet; leave everything for next read
		}
		end = nl + 1
	}
	out := string(avail[:end])
	b.readPos = b.discarded + start + end
	return out
}

// BackgroundProcess represents a single command launched in the background.
type BackgroundProcess struct {
	ID      string
	Command string

	output *streamBuffer
	cancel context.CancelFunc

	mu       sync.Mutex
	done     bool
	killed   bool
	exitCode int
	runErr   error
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
//
// All process execution contexts are derived from parentCtx, so cancelling it
// once (via shutdown) tears down every background process and its worker exec at
// once — no per-process iteration can miss one. Individual processes still get
// their own cancel for targeted kill_shell.
type backgroundManager struct {
	mu      sync.Mutex
	procs   map[string]*BackgroundProcess
	counter int

	parentCtx    context.Context
	parentCancel context.CancelFunc

	// wg tracks the live runner goroutines launched by ExecuteBackground so
	// shutdown (killAll) can wait for each to finish tearing down its OS process
	// before the MCP server exits, rather than orphaning it.
	wg sync.WaitGroup
}

func newBackgroundManager() *backgroundManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &backgroundManager{
		procs:        make(map[string]*BackgroundProcess),
		parentCtx:    ctx,
		parentCancel: cancel,
	}
}

// create registers a new process and returns it together with the context its
// goroutine should run under. The context derives from parentCtx (so shutdown
// cancels it) and its cancel is stored on the process before it becomes
// reachable, so a concurrent get/kill can never observe a nil cancel.
func (m *backgroundManager) create(command string) (*BackgroundProcess, context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.counter++
	id := fmt.Sprintf("bash_%d", m.counter)
	ctx, cancel := context.WithCancel(m.parentCtx)
	p := &BackgroundProcess{
		ID:      id,
		Command: command,
		output:  newStreamBuffer(maxBackgroundOutputBytes),
		cancel:  cancel,
	}
	m.procs[id] = p
	return p, ctx
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
	if p.done {
		return // already recorded (e.g. grace-period abandon raced the runner)
	}
	p.done = true
	p.runErr = err
	p.exitCode = exitCodeFromErr(err, p.killed)
}

// shutdownGracePeriod bounds how long killAll waits for the runner goroutines to
// finish tearing down their OS processes after cancellation, so a wedged runner
// cannot block MCP shutdown indefinitely. It exceeds the per-runner grace period
// (runnerKillGracePeriod, after which a goroutine records its terminal state and
// returns) plus the host process-group SIGKILL delay (gracefulKillTimeout), so a
// cleanly terminating process is always fully reaped before shutdown proceeds.
const shutdownGracePeriod = runnerKillGracePeriod + gracefulKillTimeout

// killAll terminates every background process and waits for their runner
// goroutines to finish. It marks each running process as killed (for status
// reporting) and cancels the shared parent context, which tears down all derived
// process contexts and their worker execs at once. It then blocks until every
// runner goroutine has returned (bounded by shutdownGracePeriod) so that no
// background OS process is left orphaned when the MCP server exits.
func (m *backgroundManager) killAll() {
	for _, p := range m.list() {
		p.mu.Lock()
		if !p.done {
			p.killed = true
		}
		p.mu.Unlock()
	}
	m.parentCancel()

	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(shutdownGracePeriod):
	}
}

// exitCodeFromErr maps a runner error to a conventional exit code. A killed
// process always reports the SIGKILL code regardless of how the runner returned,
// so its exit code stays consistent with its "killed" status.
func exitCodeFromErr(err error, killed bool) int {
	if killed {
		return 137 // 128 + SIGKILL
	}
	if err == nil {
		return 0
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
	forceHost := s.isUnsandboxedInvocation(command)

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

	// create derives the run context from the manager's shared parent (so
	// shutdown cancels it) and stores its cancel before the process becomes
	// reachable. Cancellation is driven by KillBackground / Close.
	proc, ctx := s.bg.create(command)

	// Track the runner goroutine so shutdown (killAll) can wait for it to finish
	// tearing down its OS process. Add before launching so a concurrent shutdown
	// cannot miss it.
	s.bg.wg.Add(1)
	go func() {
		defer s.bg.wg.Done()
		defer proc.cancel()

		// Run in an inner goroutine so a runner that hangs after cancellation
		// (mvdan.cc/sh pipelines can block on non-context-aware io.Pipe copies
		// that SIGKILL cannot unblock) does not pin the process in "running"
		// forever — mirroring the foreground executeWithInterp grace period.
		runDone := make(chan error, 1)
		go func() {
			if isExtra {
				// newProcessGroup=true: background bare commands often start
				// servers/daemons that fork, so kill the whole group on stop.
				runDone <- s.runRawToWriter(ctx, command, workDir, proc.output, true, forceHost)
			} else {
				runDone <- s.runInterpToWriter(ctx, f, workDir, readAllowedPaths, writeAllowedPaths, proc.output)
			}
		}()

		select {
		case err := <-runDone:
			s.bg.finish(proc, err)
		case <-ctx.Done():
			// Killed: give the runner a short grace period to return cleanly,
			// otherwise abandon it and record the terminal state anyway.
			select {
			case err := <-runDone:
				s.bg.finish(proc, err)
			case <-time.After(runnerKillGracePeriod):
				s.bg.finish(proc, fmt.Errorf("killed: runner did not exit within grace period: %w", ctx.Err()))
			}
		}
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

	var re *regexp.Regexp
	if filter != "" {
		var err error
		re, err = regexp.Compile(filter)
		if err != nil {
			return nil, fmt.Errorf("invalid filter regex: %w", err)
		}
	}

	// When filtering a still-running process, hold back any trailing partial
	// line so a line is never split across two reads (which would make it miss
	// the filter). Once the process is done there is no more output coming, so
	// flush everything including a final unterminated line.
	holdPartial := re != nil && p.Status() == "running"
	output := p.output.read(holdPartial)
	if re != nil {
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
