package bash_sandboxed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// maxBackgroundOutputBytes caps the size of each background process's output
// file. Long-running, chatty commands (e.g. dev servers, log tailers) could
// otherwise grow it without bound; once the cap is reached the file is
// compacted to its most recent half (see outputFile.compact), so the latest
// output is always available.
const maxBackgroundOutputBytes = 32 << 20 // 32 MiB

// outputTruncatedMarker opens an output file whose earlier content was
// discarded by the size cap.
const outputTruncatedMarker = "[lite-sandbox: output exceeded the size cap; earlier output was discarded]\n"

// BackgroundOutputRoot is the per-user directory holding the output files of
// background commands: each MCP server writes into its own bg-<pid>-* subdirectory
// (removed when the server shuts down) one <shell id>.log per command. It lives
// under os.TempDir() — shared /tmp on Linux, the per-user $TMPDIR on macOS — so
// it is uid-scoped and created 0700.
func BackgroundOutputRoot() string {
	return filepath.Join(os.TempDir(), "lite-sandbox-"+strconv.Itoa(os.Getuid()))
}

// BackgroundOutputReadPath returns BackgroundOutputRoot when it exists as a
// directory this user owns and no one else can access, and "" otherwise. It is
// the form callers grant as a readable path, so the agent can read output files
// with the bash tool and the built-in file tools: a root another user planted in
// a shared /tmp (a symlink, or a directory they own) is never granted, since the
// grant would follow it wherever it points.
func BackgroundOutputReadPath() string {
	root := BackgroundOutputRoot()
	if checkOutputRoot(root) != nil {
		return ""
	}
	return root
}

// checkOutputRoot verifies root is a real directory (not a symlink) owned by
// this user with no group or other permissions.
func checkOutputRoot(root string) error {
	fi, err := os.Lstat(root)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", root)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by another user", root)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is accessible to other users (mode %v)", root, fi.Mode().Perm())
	}
	return nil
}

// ensureOutputRoot creates root (0700) if needed and verifies it.
func ensureOutputRoot(root string) error {
	if err := os.Mkdir(root, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("failed to create background output directory: %w", err)
	}
	if err := checkOutputRoot(root); err != nil {
		return fmt.Errorf("refusing background output directory: %w", err)
	}
	return nil
}

// sweepStaleOutputDirs removes the output directories of MCP servers that are
// no longer running — ones killed before they could clean up after themselves
// (SIGKILL, a crash). The directory name carries the owning server's pid.
func sweepStaleOutputDirs(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		rest, ok := strings.CutPrefix(e.Name(), "bg-")
		if !ok || !e.IsDir() {
			continue
		}
		pidStr, _, _ := strings.Cut(rest, "-")
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 0 || pid == os.Getpid() {
			continue
		}
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			os.RemoveAll(filepath.Join(root, e.Name()))
		}
	}
}

// outputFile is the goroutine-safe, size-capped writer a background process's
// stdout and stderr are written to. Writes after Close are dropped, so a runner
// abandoned after a kill cannot fail on a closed file.
type outputFile struct {
	mu     sync.Mutex
	f      *os.File
	size   int64
	cap    int64
	closed bool
}

func createOutputFile(path string, cap int64) (*outputFile, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to create background output file: %w", err)
	}
	return &outputFile{f: f, cap: cap}, nil
}

// Write appends p, compacting the file first if the cap would be exceeded.
func (o *outputFile) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return len(p), nil
	}
	if o.cap > 0 && o.size+int64(len(p)) > o.cap {
		if err := o.compact(p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	n, err := o.f.Write(p)
	o.size += int64(n)
	return n, err
}

// compact rewrites the file as the truncation marker followed by the most
// recent cap/2 bytes of its content plus p. Keeping half (rather than exactly
// cap) leaves room for new output, so a chatty process compacts rarely.
func (o *outputFile) compact(p []byte) error {
	keep := o.cap / 2
	var tail []byte
	if int64(len(p)) >= keep {
		tail = p[int64(len(p))-keep:]
	} else {
		fromFile := min(keep-int64(len(p)), o.size)
		tail = make([]byte, fromFile, fromFile+int64(len(p)))
		if _, err := o.f.ReadAt(tail, o.size-fromFile); err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		tail = append(tail, p...)
	}
	if err := o.f.Truncate(0); err != nil {
		return err
	}
	// O_APPEND puts these writes at the new end of the file, offset 0.
	n, err := o.f.Write(append([]byte(outputTruncatedMarker), tail...))
	o.size = int64(n)
	return err
}

// Close closes the file; later writes are dropped.
func (o *outputFile) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	return o.f.Close()
}

// BackgroundProcess represents a single command launched in the background.
type BackgroundProcess struct {
	ID      string
	Command string
	// OutputPath is the file the process's stdout and stderr are written to.
	OutputPath string

	output *outputFile
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

// BackgroundStatus is a lightweight summary used when listing processes.
type BackgroundStatus struct {
	ID         string
	Command    string
	Status     string
	ExitCode   int
	OutputPath string
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

	// outputRoot is the parent of outputDir (BackgroundOutputRoot); outputDir
	// is this manager's own subdirectory, created on the first background
	// command and removed by removeOutputDir. Guarded by mu.
	outputRoot string
	outputDir  string
}

func newBackgroundManager() *backgroundManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &backgroundManager{
		procs:        make(map[string]*BackgroundProcess),
		parentCtx:    ctx,
		parentCancel: cancel,
		outputRoot:   BackgroundOutputRoot(),
	}
}

// outputDirLocked returns this manager's output directory, creating it (and
// sweeping directories left behind by dead servers) on first use. m.mu must
// be held.
func (m *backgroundManager) outputDirLocked() (string, error) {
	if m.outputDir != "" {
		return m.outputDir, nil
	}
	if err := ensureOutputRoot(m.outputRoot); err != nil {
		return "", err
	}
	sweepStaleOutputDirs(m.outputRoot)
	dir, err := os.MkdirTemp(m.outputRoot, fmt.Sprintf("bg-%d-", os.Getpid()))
	if err != nil {
		return "", fmt.Errorf("failed to create background output directory: %w", err)
	}
	m.outputDir = dir
	return dir, nil
}

// removeOutputDir deletes the output directory and every output file in it.
// Called on shutdown, after killAll.
func (m *backgroundManager) removeOutputDir() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.outputDir != "" {
		os.RemoveAll(m.outputDir)
		m.outputDir = ""
	}
}

// create registers a new process, with its output file, and returns it
// together with the context its goroutine should run under. The context derives
// from parentCtx (so shutdown cancels it) and its cancel is stored on the process
// before it becomes reachable, so a concurrent get/kill can never observe a nil
// cancel.
func (m *backgroundManager) create(command string) (*BackgroundProcess, context.Context, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	dir, err := m.outputDirLocked()
	if err != nil {
		return nil, nil, err
	}
	m.counter++
	id := fmt.Sprintf("bash_%d", m.counter)
	path := filepath.Join(dir, id+".log")
	out, err := createOutputFile(path, maxBackgroundOutputBytes)
	if err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithCancel(m.parentCtx)
	p := &BackgroundProcess{
		ID:         id,
		Command:    command,
		OutputPath: path,
		output:     out,
		cancel:     cancel,
	}
	m.procs[id] = p
	return p, ctx, nil
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
// surfaced later via ListBackground. The command's stdout and stderr are
// written to the process's OutputPath, which the agent reads like any other
// file. This mirrors the Claude Code Bash tool's run_in_background option.
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
		if err := s.validateFileCtx(withAuditScope(context.Background(), command, workDir, "bash"), f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}
	}

	// create derives the run context from the manager's shared parent (so
	// shutdown cancels it) and stores its cancel before the process becomes
	// reachable. Cancellation is driven by KillBackground / Close.
	proc, ctx, err := s.bg.create(command)
	if err != nil {
		return nil, err
	}
	ctx = withAuditScope(ctx, command, workDir, "bash")

	// Track the runner goroutine so shutdown (killAll) can wait for it to finish
	// tearing down its OS process. Add before launching so a concurrent shutdown
	// cannot miss it.
	s.bg.wg.Add(1)
	go func() {
		defer s.bg.wg.Done()
		defer proc.cancel()
		// Runs before cancel: the terminal state is recorded by then, and any
		// write from a runner abandoned after a kill is dropped.
		defer proc.output.Close()

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
			ID:         p.ID,
			Command:    p.Command,
			Status:     p.statusLocked(),
			ExitCode:   p.exitCode,
			OutputPath: p.OutputPath,
		})
		p.mu.Unlock()
	}
	return out
}
