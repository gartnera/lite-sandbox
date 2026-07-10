package os_sandbox

import (
	"bufio"
	"context"
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
)

// gracefulKillTimeout is how long a process is given to exit after a SIGTERM
// before it (and its group) is forcibly SIGKILLed.
const gracefulKillTimeout = 3 * time.Second

// HostMsgType identifies messages sent from host to worker.
type HostMsgType int

const (
	HostMsgExec     HostMsgType = iota // Start a command (Args, Dir, Env)
	HostMsgStdin                       // Stdin data chunk (Data)
	HostMsgStdinEOF                    // No more stdin
	HostMsgCancel                      // Kill a running command (ID)
)

// HostMsg is a message sent from the MCP server to a worker process.
type HostMsg struct {
	ID   uint64
	Type HostMsgType
	Args []string          // For HostMsgExec
	Dir  string            // For HostMsgExec
	Env  map[string]string // For HostMsgExec
	Data []byte            // For HostMsgStdin
}

// WorkerMsgType identifies messages sent from worker to host.
type WorkerMsgType int

const (
	WorkerMsgReady  WorkerMsgType = iota // Worker ready (startup signal)
	WorkerMsgStdout                      // Stdout data chunk (Data)
	WorkerMsgStderr                      // Stderr data chunk (Data)
	WorkerMsgDone                        // Command finished (ExitCode, Error)
)

// WorkerMsg is a message sent from a worker process back to the MCP server.
type WorkerMsg struct {
	ID       uint64
	Type     WorkerMsgType
	Data     []byte
	ExitCode int
	Error    string
}

// hostLockedEncoder wraps a gob.Encoder with a mutex and buffered writer for concurrent HostMsg sends.
type hostLockedEncoder struct {
	mu  sync.Mutex
	buf *bufio.Writer
	enc *gob.Encoder
}

func newHostLockedEncoder(w io.Writer) *hostLockedEncoder {
	buf := bufio.NewWriter(w)
	return &hostLockedEncoder{buf: buf, enc: gob.NewEncoder(buf)}
}

func (e *hostLockedEncoder) send(msg HostMsg) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.enc.Encode(msg); err != nil {
		return err
	}
	return e.buf.Flush()
}

// Worker manages a single bwrap sandbox process communicating via gob over stdin/stdout.
// It supports multiplexed concurrent executions via per-execution IDs.
type Worker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	enc    *hostLockedEncoder
	dec    *gob.Decoder

	mu   sync.Mutex
	dead bool

	nextID    uint64
	pending   map[uint64]chan WorkerMsg
	pendingMu sync.Mutex
}

// sshAllowedFiles are the non-key files in ~/.ssh that remain accessible in the sandbox.
var sshAllowedFiles = map[string]bool{
	"known_hosts":      true,
	"known_hosts.old":  true,
	"config":           true,
	"authorized_keys":  true,
	"authorized_keys2": true,
}

// getSSHPrivateKeyPaths returns paths to files in sshDir that look like private keys.
// It allows known_hosts, config, authorized_keys, and *.pub files through.
func getSSHPrivateKeyPaths(sshDir string) []string {
	entries, err := os.ReadDir(sshDir)
	if err != nil {
		return nil
	}
	var keys []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if sshAllowedFiles[name] || strings.HasSuffix(name, ".pub") {
			continue
		}
		keys = append(keys, filepath.Join(sshDir, name))
	}
	return keys
}

// StartWorker starts a new sandbox worker process.
// The worker runs the "lite-sandbox sandbox-worker" subcommand inside a platform-specific sandbox.
// On Linux, this uses bwrap. On macOS, this uses sandbox-exec with SBPL profiles.
// extraBinds specifies additional writable paths to bind mount (e.g., for runtimes).
// blockAWSCredentials specifies whether to block ~/.aws directory.
// Note: ~/.ssh private keys are ALWAYS blocked regardless of this parameter.
// maskPaths are filesystem paths made unreachable inside the worker (e.g. the
// real Docker daemon socket), so a sandboxed command cannot bypass a broker by
// connecting to the underlying resource directly.
func StartWorker(ctx context.Context, workDir string, extraBinds []string, blockAWSCredentials bool, maskPaths []string) (*Worker, error) {
	// Find our own binary path to pass to the sandbox
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	// If running from a test binary, try to find the actual binary
	baseName := filepath.Base(self)
	isTestBinary := baseName != "lite-sandbox" && (filepath.Ext(self) == ".test" || filepath.Ext(baseName) == ".test")
	if isTestBinary {
		found := false
		// Try to find lite-sandbox in current working directory
		cwd, err := os.Getwd()
		if err == nil {
			candidatePath := filepath.Join(cwd, "lite-sandbox")
			if _, err := os.Stat(candidatePath); err == nil {
				self = candidatePath
				found = true
			} else {
				// Try two levels up (for tests in tool/bash_sandboxed)
				candidatePath = filepath.Join(cwd, "../..", "lite-sandbox")
				if absPath, err := filepath.Abs(candidatePath); err == nil {
					if _, err := os.Stat(absPath); err == nil {
						self = absPath
						found = true
					}
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("lite-sandbox binary not found (required for OS sandbox tests, run 'go build -o lite-sandbox' first)")
		}
	}

	// Resolve symlinks in workDir (e.g., /tmp might be a symlink)
	realWorkDir, err := filepath.EvalSymlinks(workDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve workDir symlinks: %w", err)
	}

	// Ensure workDir exists
	if err := os.MkdirAll(realWorkDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workDir: %w", err)
	}

	slog.InfoContext(ctx, "starting worker", "binary", self, "workDir", realWorkDir, "platform", runtime.GOOS)

	// Platform-specific sandbox command setup
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		// Create runtime bind dirs up front and keep the ones that exist; a
		// path we can't create can't be bind-mounted, so drop it.
		var binds []string
		for _, path := range extraBinds {
			if err := os.MkdirAll(path, 0755); err != nil {
				slog.WarnContext(ctx, "failed to create runtime bind path", "path", path, "error", err)
				continue
			}
			binds = append(binds, path)
		}

		// Gather the credential/socket masks. These are applied last (see
		// buildBwrapArgs) so an overlapping writable bind cannot re-expose them.
		var sshKeyPaths []string
		var awsTmpfsDir string
		homeDir, err := os.UserHomeDir()
		if err == nil {
			// Block SSH private keys but allow known_hosts and config.
			sshKeyPaths = getSSHPrivateKeyPaths(filepath.Join(homeDir, ".ssh"))

			// Conditionally block ~/.aws (only if it exists).
			if blockAWSCredentials {
				awsDir := filepath.Join(homeDir, ".aws")
				if _, err := os.Stat(awsDir); err == nil {
					awsTmpfsDir = awsDir
				}
			}
		}

		args := buildBwrapArgs(self, realWorkDir, binds, sshKeyPaths, maskPaths, awsTmpfsDir)
		cmd = exec.CommandContext(ctx, "bwrap", args...)

	case "darwin":
		// Build sandbox-exec command
		// Generate SBPL profile that allows read-only root and writable workDir + extraBinds
		profile := generateSBPLProfile(realWorkDir, extraBinds, blockAWSCredentials, maskPaths)

		// sandbox-exec -p <profile> <binary> <args>
		cmd = exec.CommandContext(ctx, "sandbox-exec", "-p", profile, self, "sandbox-worker")
		cmd.Dir = realWorkDir

	default:
		return nil, fmt.Errorf("os sandbox not supported on %s", runtime.GOOS)
	}

	cmd.Stderr = os.Stderr // Pass through stderr for worker logs

	// Put the worker in its own process group. On macOS this is what makes the
	// seatbelt "(deny signal (target others))" rule meaningful — sandbox-spawned
	// processes share this group while the host MCP process does not — and it
	// lets Close() signal the whole group to reap leaked background processes.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		stdin.Close()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		stdin.Close()
		stdout.Close()
		return nil, fmt.Errorf("failed to start sandbox: %w", err)
	}

	slog.InfoContext(ctx, "started sandbox worker", "platform", runtime.GOOS, "pid", cmd.Process.Pid)

	bufStdout := bufio.NewReader(stdout)

	w := &Worker{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		enc:     newHostLockedEncoder(stdin),
		dec:     gob.NewDecoder(bufStdout),
		pending: make(map[uint64]chan WorkerMsg),
	}

	// Wait for ready signal from worker
	var ready WorkerMsg
	if err := w.dec.Decode(&ready); err != nil {
		w.Close()
		return nil, fmt.Errorf("failed to receive ready signal: %w", err)
	}
	if ready.Type != WorkerMsgReady {
		w.Close()
		return nil, fmt.Errorf("expected ready signal, got type %d", ready.Type)
	}

	slog.InfoContext(ctx, "worker ready", "pid", cmd.Process.Pid)

	// Start the dispatcher goroutine to route incoming messages to pending executions.
	go w.runDispatcher()

	return w, nil
}

// buildBwrapArgs assembles the ordered bwrap argument list for the Linux
// sandbox worker.
//
// The invariant that makes this secure is ORDERING: bwrap applies mounts in the
// order given and a later overlapping mount wins. All writable binds (the extra
// runtime/writable_paths binds and the workDir bind) are emitted first; the
// credential and broker-socket masks are emitted AFTER them. If a mask were
// emitted before an overlapping bind — e.g. workDir under $HOME, or
// writable_paths containing "~" which binds $HOME writable — the bind would
// override the mask and re-expose ~/.ssh private keys, ~/.aws, or a broker
// socket, silently breaking the "always denied" guarantee. Masking last closes
// that hole regardless of what the binds cover.
//
//   - --ro-bind / / : read-only root filesystem
//   - --tmpfs /tmp : writable /tmp (Go and other tools need it for build cache)
//   - --bind <path> <path> : writable runtime/config directories
//   - --bind <workDir> <workDir> : writable working directory (overrides the
//     /tmp tmpfs when workDir is under /tmp, e.g. in tests)
//   - --ro-bind /dev/null <ssh-key> : mask each SSH private key
//   - --tmpfs <~/.aws> : empty overlay hiding AWS credentials
//   - --ro-bind /dev/null <socket> : mask broker sockets (e.g. the real
//     /var/run/docker.sock); overlaying /dev/null turns the path into a char
//     device so connect() fails, defeating `unset DOCKER_HOST`/`-H` bypasses
//   - --dev /dev / --proc /proc : fresh devtmpfs and procfs
//   - --unshare-all --share-net : unshare everything except the network
//   - --die-with-parent : kill the worker if the parent dies
//   - --chdir <workDir> : start in the working directory
func buildBwrapArgs(self, realWorkDir string, binds, sshKeyPaths, maskPaths []string, awsTmpfsDir string) []string {
	args := []string{
		"--ro-bind", "/", "/",
		"--tmpfs", "/tmp",
	}

	// Writable binds first, so the masks below can override any overlap.
	for _, path := range binds {
		args = append(args, "--bind", path, path)
	}
	args = append(args, "--bind", realWorkDir, realWorkDir)

	// Credential/socket masks last: no later mount may override them.
	for _, keyPath := range sshKeyPaths {
		args = append(args, "--ro-bind", "/dev/null", keyPath)
	}
	if awsTmpfsDir != "" {
		args = append(args, "--tmpfs", awsTmpfsDir)
	}
	for _, p := range maskPaths {
		args = append(args, "--ro-bind", "/dev/null", p)
	}

	args = append(args,
		"--dev", "/dev",
		"--proc", "/proc",
		"--unshare-all",
		"--share-net",
		"--die-with-parent",
		"--chdir", realWorkDir,
		"--",
		self, "sandbox-worker",
	)
	return args
}

// generateSBPLProfile generates a Scheme-based sandbox profile for macOS sandbox-exec.
// The profile allows read-only access to the entire filesystem, but restricts writes
// to specific directories (workDir, extraBinds, and system temp directories).
// blockAWSCredentials controls whether ~/.aws is blocked.
// Note: ~/.ssh private keys are ALWAYS blocked regardless of blockAWSCredentials.
func generateSBPLProfile(workDir string, extraBinds []string, blockAWSCredentials bool, maskPaths []string) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(allow default)\n")

	// Get home directory for credential blocking
	homeDir, err := os.UserHomeDir()
	if err != nil {
		// Fall back to not blocking if we can't get home dir
		slog.Warn("failed to get home directory for SBPL profile", "error", err)
		return sb.String()
	}

	// Deny access to credential files (must come after allow default)
	// Block SSH private keys but allow known_hosts and config
	sshDir := filepath.Join(homeDir, ".ssh")
	for _, keyPath := range getSSHPrivateKeyPaths(sshDir) {
		sb.WriteString(fmt.Sprintf("(deny file-read* (literal \"%s\"))\n", keyPath))
	}

	// Conditionally block ~/.aws
	if blockAWSCredentials {
		awsDir := filepath.Join(homeDir, ".aws")
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath \"%s\"))\n", awsDir))
	}

	// Mask broker sockets (e.g. the real Docker daemon socket): deny both file
	// access and outbound connection so a sandboxed command can only reach the
	// proxy, not the underlying socket directly.
	for _, p := range maskPaths {
		sb.WriteString(fmt.Sprintf("(deny file-read* file-write* (literal \"%s\"))\n", p))
		sb.WriteString(fmt.Sprintf("(deny network-outbound (literal \"%s\"))\n", p))
	}

	// Confine writes to the allowed subpaths below. Without this catch-all deny
	// the leading "(allow default)" would permit writes everywhere the OS itself
	// allows (e.g. the user's home directory), contradicting the documented
	// policy that only the working directory, extra binds, and temp dirs are
	// writable. SBPL applies the last matching rule, so this deny is overridden
	// by the specific "(allow file-write* ...)" rules that follow.
	sb.WriteString("(deny file-write* (subpath \"/\"))\n")

	// Allow write access to workDir and its resolved path
	sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", workDir))

	// If workDir is a symlink, also allow the resolved path
	if resolvedWorkDir, err := filepath.EvalSymlinks(workDir); err == nil && resolvedWorkDir != workDir {
		sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", resolvedWorkDir))
	}

	// Allow write access to extra bind paths (e.g., GOPATH, configured
	// writable_paths). As with workDir, Seatbelt enforces on the real path, so
	// emit the symlink-resolved path too — otherwise a write to a symlinked bind
	// (e.g. an fvm-managed SDK dir) is denied even though the rule "looks" right.
	for _, path := range extraBinds {
		sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", path))
		if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != path {
			sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", resolved))
		}
	}

	// Allow write access to system temp directories
	// /private/tmp is the canonical path, but allow both /tmp and /private/tmp
	sb.WriteString("(allow file-write* (subpath \"/tmp\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/private/tmp\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/private/var/tmp\"))\n")

	// Allow write access to /var/folders (macOS user temp directories)
	// This is where TMPDIR points to on macOS and where Go creates build caches
	sb.WriteString("(allow file-write* (subpath \"/var/folders\"))\n")
	sb.WriteString("(allow file-write* (subpath \"/private/var/folders\"))\n")

	// Allow write access to /dev for standard streams
	sb.WriteString("(allow file-write* (subpath \"/dev\"))\n")

	// Allow process execution
	sb.WriteString("(allow process-exec (subpath \"/\"))\n")
	sb.WriteString("(allow process-fork)\n")

	// Allow network access
	sb.WriteString("(allow network*)\n")

	// Allow mach lookups (required for macOS services)
	sb.WriteString("(allow mach-lookup)\n")

	// Restrict signaling so kill/pkill cannot reach host processes. The SBPL
	// signal operation classifies targets as self, pgrp (same process group), or
	// others (everything else). The worker is started in its own process group
	// (Setpgid), so denying "others" confines signals to the processes this
	// sandbox spawned while leaving self/pgrp (allowed by "allow default") intact.
	sb.WriteString("(deny signal (target others))\n")

	// Allow sysctl reads (required for many tools)
	sb.WriteString("(allow sysctl-read)\n")

	return sb.String()
}

// Exec runs a command in the worker, streaming stdin/stdout/stderr.
// Multiple Exec calls may run concurrently; each gets a unique ID for multiplexing.
// stdin, stdout, stderr may be nil.
// Returns the command exit code and any protocol error.
func (w *Worker) Exec(ctx context.Context, args []string, dir string, env map[string]string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	w.mu.Lock()
	if w.dead {
		w.mu.Unlock()
		return 1, fmt.Errorf("worker is dead")
	}
	if w.cmd.ProcessState != nil {
		w.dead = true
		w.mu.Unlock()
		return 1, fmt.Errorf("worker process has exited")
	}
	w.mu.Unlock()

	// Generate unique ID and register a response channel.
	w.pendingMu.Lock()
	id := w.nextID
	w.nextID++
	ch := make(chan WorkerMsg, 64)
	w.pending[id] = ch
	w.pendingMu.Unlock()

	slog.DebugContext(ctx, "sending exec to worker", "args", args, "id", id)

	// Send exec message via locked encoder (safe for concurrent callers).
	if err := w.enc.send(HostMsg{ID: id, Type: HostMsgExec, Args: args, Dir: dir, Env: env}); err != nil {
		w.pendingMu.Lock()
		delete(w.pending, id)
		w.pendingMu.Unlock()
		w.mu.Lock()
		w.dead = true
		w.mu.Unlock()
		return 1, fmt.Errorf("failed to send exec: %w", err)
	}

	// Pump stdin in a background goroutine.
	stdinDone := make(chan error, 1)
	go func() {
		stdinDone <- w.pumpStdinForID(id, stdin)
	}()

	// Read responses from the per-execution channel until WorkerMsgDone (channel
	// closed by dispatcher). If ctx is cancelled, tell the worker to kill this
	// execution's process and keep draining until it reports done — the worker
	// owns the process, so cancellation must round-trip through it.
	var exitCode int
	var execErr error
	ctxDone := ctx.Done()
loop:
	for {
		select {
		case msg, ok := <-ch:
			if !ok {
				break loop
			}
			switch msg.Type {
			case WorkerMsgStdout:
				if stdout != nil && len(msg.Data) > 0 {
					stdout.Write(msg.Data) //nolint:errcheck
				}
			case WorkerMsgStderr:
				if stderr != nil && len(msg.Data) > 0 {
					stderr.Write(msg.Data) //nolint:errcheck
				}
			case WorkerMsgDone:
				exitCode = msg.ExitCode
				if msg.Error != "" {
					execErr = fmt.Errorf("%s", msg.Error)
				}
			}
		case <-ctxDone:
			// Disable this case after firing once so we don't busy-loop while
			// waiting for the worker's done message.
			ctxDone = nil
			_ = w.enc.send(HostMsg{ID: id, Type: HostMsgCancel})
		}
	}

	// Wait for stdin pump to finish.
	if pumpErr := <-stdinDone; pumpErr != nil && execErr == nil {
		execErr = pumpErr
	}

	return exitCode, execErr
}

// pumpStdinForID reads from r in 4096-byte chunks and sends them to the worker with the given ID,
// then sends HostMsgStdinEOF. If r is nil, only the EOF is sent.
func (w *Worker) pumpStdinForID(id uint64, r io.Reader) error {
	if r != nil {
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				chunk := make([]byte, n)
				copy(chunk, buf[:n])
				if encErr := w.enc.send(HostMsg{ID: id, Type: HostMsgStdin, Data: chunk}); encErr != nil {
					return fmt.Errorf("failed to send stdin chunk: %w", encErr)
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("stdin read error: %w", err)
			}
		}
	}
	if err := w.enc.send(HostMsg{ID: id, Type: HostMsgStdinEOF}); err != nil {
		return fmt.Errorf("failed to send stdin EOF: %w", err)
	}
	return nil
}

// runDispatcher continuously reads WorkerMsg from the decoder and routes each message
// to the appropriate pending execution channel. On decode error, all pending channels
// receive a synthetic done-with-error message and are closed.
func (w *Worker) runDispatcher() {
	for {
		var msg WorkerMsg
		if err := w.dec.Decode(&msg); err != nil {
			w.mu.Lock()
			w.dead = true
			w.mu.Unlock()

			// Drain all pending channels with a synthetic error.
			w.pendingMu.Lock()
			for _, ch := range w.pending {
				ch <- WorkerMsg{Type: WorkerMsgDone, ExitCode: 1, Error: "worker connection lost: " + err.Error()}
				close(ch)
			}
			w.pending = make(map[uint64]chan WorkerMsg)
			w.pendingMu.Unlock()
			return
		}

		w.pendingMu.Lock()
		ch, ok := w.pending[msg.ID]
		if ok && msg.Type == WorkerMsgDone {
			delete(w.pending, msg.ID)
		}
		w.pendingMu.Unlock()

		if ok {
			ch <- msg
			if msg.Type == WorkerMsgDone {
				close(ch)
			}
		}
	}
}

// Close terminates the worker process.
func (w *Worker) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.dead {
		return nil
	}

	w.dead = true

	if w.cmd.Process != nil {
		pid := w.cmd.Process.Pid
		// The worker leads its own process group (Setpgid at start). Signal the
		// whole group so any background processes it spawned (e.g. servers) are
		// torn down too, not just the worker leader. Give them a grace period to
		// exit cleanly on SIGTERM, then SIGKILL whatever is left.
		_ = syscall.Kill(-pid, syscall.SIGTERM)

		done := make(chan struct{})
		go func() {
			w.cmd.Wait() // Reap the process
			close(done)
		}()

		select {
		case <-done:
		case <-time.After(gracefulKillTimeout):
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			_ = w.cmd.Process.Kill()
			<-done
		}
	}

	w.stdin.Close()
	w.stdout.Close()

	return nil
}

// IsDead returns true if the worker is known to be dead.
func (w *Worker) IsDead() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.dead
}
