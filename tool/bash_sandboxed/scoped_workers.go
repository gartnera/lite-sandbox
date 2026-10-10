package bash_sandboxed

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"mvdan.cc/sh/v3/interp"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/os_sandbox"
)

// Scoped workers run the commands a scoped grant names (paths entries with
// internal: true and a commands list; config.CommandScope). Each scope gets
// an OS sandbox worker of its own that has the granted paths, while the
// shared worker every other command runs in hides them. So a credential
// granted to gh is readable by gh and by nothing else: not by a program the
// agent writes and runs (go run, python), and not by a gh that program
// launches itself, which runs in the shared worker.
//
// Only a direct invocation of the command, by its bare name, is routed here
// (`gh pr list`, not `./gh`, `/usr/bin/gh`, `timeout 60 gh` or `xargs gh`;
// those run in the shared worker, without the grant). The command keeps its
// argument validators, and three things keep the agent from running code of
// its own inside the worker:
//
//   - the binary is resolved against the server's PATH and refused when it
//     lies somewhere the agent can write (scopedBinary);
//   - the command gets the server's environment, not the variables the agent
//     set (GH_CONFIG_DIR, GIT_*, a pager, an editor);
//   - a bare allow, which runs the whole command line through `bash -c`,
//     never reaches a scoped worker: it runs in the shared one.
//
// What it cannot do is limit the CLI itself: once it has the credential it
// can do anything the credential allows, within what its validators refuse.
// So only grant this to CLIs that never run code from the project.

// scopedWorkerIdleTTL is how long a scoped worker stays up after its last
// command finishes. A scope's commands tend to come in bursts (a few gh calls
// while preparing a PR), so the worker is kept for the next one, and closed
// when the burst is over rather than held for the whole session.
var scopedWorkerIdleTTL = 5 * time.Minute

// scopedWorker is one scope's worker. active counts the commands running in
// it; the idle timer runs only while it is zero.
type scopedWorker struct {
	w      *os_sandbox.Worker
	active int
	idle   *time.Timer
}

// commandScope returns the scope whose worker runs the command invoked as
// name, if a scoped grant names it. Only the bare name matches.
func (s *Sandbox) commandScope(name string) (config.CommandScope, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scope, ok := s.scopes[name]
	return scope, ok
}

// execInScopedWorker runs args in the scope's worker.
func (s *Sandbox) execInScopedWorker(ctx context.Context, scope config.CommandScope, args []string) error {
	hc := interp.HandlerCtx(ctx)

	bin, err := s.scopedBinary(args[0])
	if err != nil {
		return err
	}
	w, release, err := s.acquireScopedWorker(scope)
	if err != nil {
		return fmt.Errorf("failed to get worker for %s: %w", scope.Key, err)
	}
	defer release()

	// The server's environment, as a bare allow gets it (ambient AWS profile
	// selectors stripped, the brokered endpoint injected), and none of the
	// agent's variables.
	s.mu.RLock()
	imdsEndpoint, imdsRegion := s.imdsEndpoint, s.imdsRegion
	s.mu.RUnlock()
	env := envSliceToMap(awsBaseEnv(os.Environ(), imdsEndpoint, imdsRegion))

	argv := append([]string{bin}, args[1:]...)
	exitCode, err := w.Exec(ctx, argv, hc.Dir, env, hc.Stdin, hc.Stdout, hc.Stderr)
	if err != nil {
		return fmt.Errorf("worker communication failed: %w", err)
	}
	if exitCode != 0 {
		return interp.ExitStatus(exitCode)
	}
	return nil
}

// scopedBinary resolves the command name to the binary its scoped worker
// runs: looked up on the server's PATH (the agent cannot change it, and its
// own PATH is not consulted), symlinks resolved, and refused when the agent
// could have written it — a binary under the working directory, a writable
// grant, or any other path the shared worker may write. Otherwise the agent
// could replace the binary and have its own program run with the grant.
func (s *Sandbox) scopedBinary(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()
	shared := s.workerOptions(cfg)
	for _, p := range []string{abs, resolved} {
		if dir := agentWritableDir(p, shared); dir != "" {
			return "", fmt.Errorf("%s resolves to %s, under %s, which sandboxed commands can write; a command granted paths of its own only runs from a binary they cannot replace", name, p, dir)
		}
	}
	return resolved, nil
}

// agentWritableDir returns the directory through which a command in a worker
// started with opts could write path, or "" when it cannot: the working
// directory, the writable binds, the temporary directories macOS leaves
// writable (on Linux /tmp is the worker's own tmpfs), and in denylist mode
// the home directory outside the write-denied paths.
func agentWritableDir(path string, opts os_sandbox.WorkerOptions) string {
	dirs := append([]string{opts.WorkDir}, opts.ExtraBinds...)
	if runtime.GOOS == "darwin" {
		dirs = append(dirs, "/tmp", "/private/tmp", "/private/var/tmp", "/var/folders", "/private/var/folders")
	}
	for _, d := range dirs {
		if d != "" && underAny(path, d) {
			return d
		}
	}
	if opts.HomeWritable {
		if home, err := os.UserHomeDir(); err == nil && underAny(path, home) {
			for _, d := range opts.DeniedWritePaths {
				if underAny(path, d.Path) {
					return ""
				}
			}
			return home
		}
	}
	return ""
}

// underAny reports whether path is dir or inside it, comparing dir both as
// given and with its symlinks resolved.
func underAny(path, dir string) bool {
	for _, d := range []string{dir, resolveIfExists(dir)} {
		d = filepath.Clean(d)
		if path == d || strings.HasPrefix(path, d+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func resolveIfExists(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return p
}

// acquireScopedWorker returns the scope's worker, starting it when there is
// none (or it died), and counts the caller as running in it until release is
// called. The last release arms the idle timer that closes it.
func (s *Sandbox) acquireScopedWorker(scope config.CommandScope) (*os_sandbox.Worker, func(), error) {
	s.mu.Lock()
	if sw := s.scopedWorkers[scope.Key]; sw != nil && !sw.w.IsDead() {
		sw.active++
		if sw.idle != nil {
			sw.idle.Stop()
			sw.idle = nil
		}
		s.mu.Unlock()
		return sw.w, s.scopedReleaser(scope.Key, sw), nil
	}
	cfg := s.cfg
	s.mu.Unlock()

	opts := s.workerOptions(cfg.ForScope(scope))

	s.mu.Lock()
	defer s.mu.Unlock()
	if sw := s.scopedWorkers[scope.Key]; sw != nil && !sw.w.IsDead() {
		sw.active++
		if sw.idle != nil {
			sw.idle.Stop()
			sw.idle = nil
		}
		return sw.w, s.scopedReleaser(scope.Key, sw), nil
	}
	slog.Info("starting scoped sandbox worker", "commands", scope.Key, "workDir", opts.WorkDir, "mode", cfg.EffectiveMode())
	w, err := os_sandbox.StartWorker(context.Background(), opts)
	if err != nil {
		return nil, nil, err
	}
	sw := &scopedWorker{w: w, active: 1}
	if s.cfg != cfg {
		// The config changed while the worker started; UpdateConfig already
		// closed the old scoped workers. Run this one command in it, then
		// close it, rather than keep a worker built from the old policy.
		return w, func() { w.Close() }, nil
	}
	if s.scopedWorkers == nil {
		s.scopedWorkers = make(map[string]*scopedWorker)
	}
	s.scopedWorkers[scope.Key] = sw
	return w, s.scopedReleaser(scope.Key, sw), nil
}

// scopedReleaser returns the release func for one acquisition of sw.
func (s *Sandbox) scopedReleaser(key string, sw *scopedWorker) func() {
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		sw.active--
		if sw.active > 0 || s.scopedWorkers[key] != sw {
			return
		}
		sw.idle = time.AfterFunc(scopedWorkerIdleTTL, func() {
			s.mu.Lock()
			if s.scopedWorkers[key] != sw || sw.active > 0 {
				s.mu.Unlock()
				return
			}
			delete(s.scopedWorkers, key)
			s.mu.Unlock()
			slog.Info("closing idle scoped sandbox worker", "commands", key)
			sw.w.Close()
		})
	}
}

// closeScopedWorkersLocked closes every scoped worker. Called with s.mu held,
// on a config update (their policy is baked in at start, like the shared
// worker's) and on Close.
func (s *Sandbox) closeScopedWorkersLocked() {
	for key, sw := range s.scopedWorkers {
		if sw.idle != nil {
			sw.idle.Stop()
		}
		sw.w.Close()
		delete(s.scopedWorkers, key)
	}
}
