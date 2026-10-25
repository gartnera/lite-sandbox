package bash_sandboxed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"time"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// Session is an interactive shell session over the sandbox: one interpreter
// whose state — variables, functions, the working directory, $? — carries
// over from one command to the next the way a real shell's does, with the
// command's standard streams wired straight to the caller's (the terminal,
// for `lite-sandbox shell`) instead of captured. Every command is validated
// exactly as Execute validates it, against the session's current directory
// and the read/write sets fixed when the session was created.
//
// A Session is not safe for concurrent use: Run one command at a time.
type Session struct {
	s          *Sandbox
	readPaths  []string
	writePaths []string
	stdin      *os.File
	stdout     io.Writer
	stderr     io.Writer
	runner     *interp.Runner
	// dir is the working directory as of the last Run that returned, read
	// back from the runner then; it seeds a replacement runner when a Run
	// had to be abandoned (see Run).
	dir string
}

// NewSession starts a session in workDir. stdin may be nil (no input); a
// terminal is handed to host commands as is, and its reads are pumped to the
// OS sandbox worker only while a worker command runs.
func (s *Sandbox) NewSession(workDir string, readAllowedPaths, writeAllowedPaths []string, stdin *os.File, stdout, stderr io.Writer) (*Session, error) {
	ss := &Session{
		s:          s,
		readPaths:  readAllowedPaths,
		writePaths: writeAllowedPaths,
		stdin:      stdin,
		stdout:     stdout,
		stderr:     stderr,
		dir:        workDir,
	}
	if err := ss.reset(workDir); err != nil {
		return nil, err
	}
	return ss, nil
}

// reset replaces the session's interpreter with a fresh one in dir, built
// with the same options runInterpToWriter uses for a one-shot command.
func (ss *Session) reset(dir string) error {
	s := ss.s
	s.mu.RLock()
	useOSSandbox := s.cfg.OSSandboxEnabled()
	imdsEndpoint := s.imdsEndpoint
	imdsRegion := s.imdsRegion
	s.mu.RUnlock()

	var stdin io.Reader
	if ss.stdin != nil {
		stdin = ss.stdin
	}
	opts := []interp.RunnerOption{
		interp.Dir(dir),
		interp.StdIO(stdin, ss.stdout, ss.stderr),
		interp.Env(expand.ListEnviron(awsBaseEnv(os.Environ(), imdsEndpoint, imdsRegion)...)),
	}
	opts = append(opts, s.buildSecurityHandlers(ss.readPaths, ss.writePaths, useOSSandbox)...)
	runner, err := interp.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to create interpreter: %w", err)
	}
	// Run never resets a runner that has been reset once, so state persists
	// from here on.
	runner.Reset()
	ss.runner = runner
	ss.dir = dir
	return nil
}

// Dir returns the session's current working directory.
func (ss *Session) Dir() string {
	return ss.dir
}

// Functions returns the names of the functions the session has defined, sorted.
func (ss *Session) Functions() []string {
	names := make([]string, 0, len(ss.runner.Funcs))
	for name := range ss.runner.Funcs {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Run validates and runs one command line in the session. It returns the
// command's exit status and whether the line asked the shell to exit (the
// exit builtin). err is non-nil when the line did not run (a parse or
// validation error) or a runtime check refused part of it; a non-zero exit
// status alone is not an error. Cancelling ctx stops the command, as Ctrl-C
// does in a shell.
func (ss *Session) Run(ctx context.Context, command string) (status int, exited bool, err error) {
	s := ss.s
	ctx = withAuditScope(ctx, command, ss.dir, "shell")

	// A bare allow runs in real bash, as Execute runs it; nothing it does
	// carries over to the session's state.
	if s.isExtraCommandInvocation(command) {
		if err := s.checkRawAsk(ctx, command); err != nil {
			return 1, false, fmt.Errorf("validation failed: %w", err)
		}
		status, err := exitStatus(s.runRawToWriter(ctx, command, ss.dir, ss.stdout, false, s.isUnsandboxedInvocation(command)))
		return status, false, err
	}

	f, err := ParseBash(command)
	if err != nil {
		return 2, false, err
	}
	if err := ss.validate(ctx, f); err != nil {
		return 1, false, fmt.Errorf("validation failed: %w", err)
	}

	ctx = context.WithValue(ctx, sandboxPathsKey, &sandboxPaths{
		readAllowedPaths:  ss.readPaths,
		writeAllowedPaths: ss.writePaths,
	})

	// Statements run one at a time rather than as a *syntax.File, which the
	// interpreter treats as a whole script ending (running the EXIT trap).
	runner := ss.runner
	done := make(chan error, 1)
	go func() {
		var err error
		for _, stmt := range f.Stmts {
			err = runner.Run(ctx, stmt)
			if runner.Exited() || ctx.Err() != nil {
				break
			}
		}
		done <- err
	}()

	select {
	case err = <-done:
	case <-ctx.Done():
		timer := time.NewTimer(runnerKillGracePeriod)
		defer timer.Stop()
		select {
		case err = <-done:
		case <-timer.C:
			// The runner is stuck (see executeWithInterp) and may still touch
			// its state, so it cannot run the next command: start over with a
			// fresh one where the session last was.
			if rerr := ss.reset(ss.dir); rerr != nil {
				return 130, false, rerr
			}
			return 130, false, errors.New("command did not stop; shell state was reset")
		}
	}
	ss.dir = runner.Dir
	status, err = exitStatus(err)
	// The interpreter stops on a runtime check's refusal as it does on the
	// exit builtin; in a session the refusal ends only the command line.
	exited = runner.Exited() && err == nil
	if ctx.Err() != nil && !exited {
		return 130, false, nil
	}
	return status, exited, err
}

// validate is Execute's static preflight, with the functions earlier commands
// defined counting as declared: their bodies were validated when they were
// defined, and every command in them is checked again at runtime.
func (ss *Session) validate(ctx context.Context, f *syntax.File) error {
	known := make(map[string]bool, len(ss.runner.Funcs))
	for name := range ss.runner.Funcs {
		known[name] = true
	}
	return ss.s.validateFileWithFuncsCtx(ctx, f, ss.dir, ss.readPaths, ss.writePaths, known)
}

// exitStatus splits a run's error into its exit status and the error, if any,
// that is more than a status: a runtime check's refusal or a failure to start.
func exitStatus(err error) (int, error) {
	if err == nil {
		return 0, nil
	}
	if code, ok := interp.IsExitStatus(err); ok {
		return int(code), nil
	}
	var exitErr interface{ ExitCode() int }
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), nil
	}
	return 1, err
}

// CommandNames returns, sorted, the command names the config lets a command
// line run: the whitelist (built-in and config-added) and the allows. The
// shell completes the first word of a command from them.
func (s *Sandbox) CommandNames() []string {
	seen := make(map[string]bool)
	for name := range allowedCommands {
		seen[name] = true
	}
	for name := range s.getWhitelistedCommands() {
		seen[name] = true
	}
	for name := range s.getExtraCommands() {
		seen[name] = true
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
