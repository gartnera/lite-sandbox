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

// streamChunkSize is the read buffer size used by the stdin/stdout/stderr
// pumps. Each read becomes one gob message, so a larger buffer means fewer
// messages and flushes on high-volume streams. The read buffer is handed
// straight to the encoder: lockedEncoder.send serializes the message fully
// (into the buffered writer, under its lock) before returning, so the buffer is
// free to be reused for the next read.
const streamChunkSize = 64 * 1024

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

// lockedEncoder wraps a gob.Encoder with a mutex and buffered writer so
// concurrent goroutines can send messages of type T over one stream. Used with
// HostMsg on the host side and WorkerMsg inside the worker.
type lockedEncoder[T any] struct {
	mu  sync.Mutex
	buf *bufio.Writer
	enc *gob.Encoder
}

func newLockedEncoder[T any](w io.Writer) *lockedEncoder[T] {
	buf := bufio.NewWriter(w)
	return &lockedEncoder[T]{buf: buf, enc: gob.NewEncoder(buf)}
}

// send encodes and flushes msg. The lock is held across both, so a message is
// never interleaved with another and msg is fully serialized before send
// returns (callers may reuse any buffer it references afterwards).
func (e *lockedEncoder[T]) send(msg T) error {
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
	enc    *lockedEncoder[HostMsg]
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

// credentialMasks are the home-relative credential paths hidden from a sandbox
// worker. They are resolved once per worker start and applied by both platform
// backends (bwrap mounts on Linux, SBPL deny rules on macOS).
type credentialMasks struct {
	// sshKeyPaths are the ~/.ssh private keys, which are always masked.
	sshKeyPaths []string
	// awsDir is ~/.aws when AWS credential blocking is on, otherwise empty.
	awsDir string
	// homeErr is non-nil when the home directory could not be resolved, in
	// which case no credential path could be determined at all.
	homeErr error
}

// resolveCredentialMasks locates the credential paths to hide from the worker.
func resolveCredentialMasks(blockAWSCredentials bool) credentialMasks {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return credentialMasks{homeErr: err}
	}
	// Block SSH private keys but allow known_hosts and config.
	masks := credentialMasks{sshKeyPaths: getSSHPrivateKeyPaths(filepath.Join(homeDir, ".ssh"))}
	if blockAWSCredentials {
		masks.awsDir = filepath.Join(homeDir, ".aws")
	}
	return masks
}

// WorkerOptions configures a sandbox worker's filesystem policy. Both platform
// backends (bwrap mounts on Linux, SBPL rules on macOS) enforce the same
// policy from these fields.
type WorkerOptions struct {
	// WorkDir is the working directory; always writable.
	WorkDir string
	// ExtraBinds are additional writable paths (runtime caches, writable_paths,
	// internal_writable_paths, the worktree parent, the docker proxy socket dir).
	ExtraBinds []string
	// ROBinds are additional read-only paths (internal_readable_paths). Reads
	// inside the sandbox are broadly allowed already, so on Linux these only
	// matter for host paths hidden by the worker's /tmp overlay; on macOS they
	// are a no-op.
	ROBinds []string
	// BlockAWSCredentials hides ~/.aws (IMDS broker mode). ~/.ssh private keys
	// are ALWAYS hidden regardless.
	BlockAWSCredentials bool
	// MaskPaths are made unreachable (e.g. the real Docker daemon socket) so a
	// sandboxed command cannot bypass a broker by reaching the resource directly.
	MaskPaths []string

	// HomeWritable binds the user's home directory writable (denylist mode).
	// Developer tooling writes caches and state all over $HOME; rather than
	// enumerating them, denylist mode accepts broad writes there and relies on
	// DeniedReadPaths/DeniedWritePaths for the paths that matter.
	HomeWritable bool
	// DeniedReadPaths are hidden entirely: a directory becomes an empty,
	// unreadable (mode 000) tmpfs; a file is replaced by an empty mode-000 file.
	// Non-root processes get EACCES, which is a legible, classifiable signal;
	// root sees empty content. Missing paths are skipped.
	DeniedReadPaths []string
	// DeniedWritePaths stay readable but are mounted read-only over themselves
	// (bwrap) or denied file-write* (SBPL). Missing paths are skipped.
	DeniedWritePaths []string
}

// StartWorker starts a new sandbox worker process.
// The worker runs the "lite-sandbox sandbox-worker" subcommand inside a platform-specific sandbox.
// On Linux, this uses bwrap. On macOS, this uses sandbox-exec with SBPL profiles.
// See WorkerOptions for the filesystem policy.
func StartWorker(ctx context.Context, opts WorkerOptions) (*Worker, error) {
	workDir := opts.WorkDir
	extraBinds := opts.ExtraBinds
	roBinds := opts.ROBinds
	blockAWSCredentials := opts.BlockAWSCredentials
	maskPaths := opts.MaskPaths

	// Find our own binary path to pass to the sandbox
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	// If running from a test binary, try to find the actual binary
	baseName := filepath.Base(self)
	isTestBinary := baseName != "lite-sandbox" && (filepath.Ext(self) == ".test" || filepath.Ext(baseName) == ".test")
	if isTestBinary {
		// Look for lite-sandbox next to the test's working directory, then two
		// levels up (for tests in tool/bash_sandboxed).
		found := ""
		if cwd, err := os.Getwd(); err == nil {
			for _, candidate := range []string{
				filepath.Join(cwd, "lite-sandbox"),
				filepath.Join(cwd, "../..", "lite-sandbox"),
			} {
				if _, err := os.Stat(candidate); err == nil {
					found = candidate
					break
				}
			}
		}
		if found == "" {
			return nil, fmt.Errorf("lite-sandbox binary not found (required for OS sandbox tests, run 'go build -o lite-sandbox' first)")
		}
		self = found
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

	// Gather the credential masks once; both platform backends apply the same
	// set, each in its own form.
	masks := resolveCredentialMasks(blockAWSCredentials)

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

		// Read-only binds must exist to be mountable, but are not created: a
		// missing internal_readable_paths entry is the user's to fix, not ours
		// to materialize.
		var roMounts []string
		for _, path := range roBinds {
			if _, err := os.Stat(path); err != nil {
				slog.WarnContext(ctx, "skipping missing read-only bind path", "path", path, "error", err)
				continue
			}
			roMounts = append(roMounts, path)
		}

		// The credential/socket masks are applied last (see buildBwrapArgs) so
		// an overlapping writable bind cannot re-expose them. bwrap can only
		// overlay a path that exists, so drop an absent ~/.aws.
		awsTmpfsDir := masks.awsDir
		if awsTmpfsDir != "" {
			if _, err := os.Stat(awsTmpfsDir); err != nil {
				awsTmpfsDir = ""
			}
		}

		plan := bwrapPlan{
			self:        self,
			workDir:     realWorkDir,
			binds:       binds,
			roBinds:     roMounts,
			sshKeyPaths: masks.sshKeyPaths,
			maskPaths:   maskPaths,
			awsTmpfsDir: awsTmpfsDir,
			maskFile:    maskSourceFile(),
		}
		if opts.HomeWritable {
			if home, err := os.UserHomeDir(); err == nil {
				if real, err := filepath.EvalSymlinks(home); err == nil {
					home = real
				}
				if err := os.MkdirAll(home, 0755); err == nil {
					plan.homeDir = home
				}
			}
		}
		// Deny lists: only paths that exist can be overlaid, and a directory and
		// a file are masked differently (see WorkerOptions).
		for _, p := range opts.DeniedReadPaths {
			switch fi, err := os.Stat(p); {
			case err != nil:
				continue
			case fi.IsDir():
				if p != awsTmpfsDir { // already masked
					plan.deniedReadDirs = append(plan.deniedReadDirs, p)
				}
			default:
				plan.deniedReadFiles = append(plan.deniedReadFiles, p)
			}
		}
		for _, p := range opts.DeniedWritePaths {
			if _, err := os.Stat(p); err == nil {
				plan.deniedWritePaths = append(plan.deniedWritePaths, p)
			}
		}
		args := buildBwrapArgs(plan)
		cmd = exec.CommandContext(ctx, "bwrap", args...)

	case "darwin":
		// Build sandbox-exec command
		// Generate SBPL profile that allows read-only root and writable workDir + extraBinds.
		// roBinds are not needed here: the profile's "(allow default)" already
		// permits reads everywhere except the credential/socket masks.
		profile := generateSBPLProfile(realWorkDir, extraBinds, masks, maskPaths, sbplDenylist{
			homeWritable:     opts.HomeWritable,
			deniedReadPaths:  opts.DeniedReadPaths,
			deniedWritePaths: opts.DeniedWritePaths,
		})

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
		enc:     newLockedEncoder[HostMsg](stdin),
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

// bwrapPlan is the input to buildBwrapArgs: everything the mount layout
// depends on, already existence-filtered and symlink-resolved by StartWorker.
type bwrapPlan struct {
	self    string
	workDir string
	// binds are writable, roBinds read-only (both bind-mounted over themselves).
	binds, roBinds []string
	// homeDir, when set, is bound writable before every other bind (denylist
	// mode). Empty in allowlist mode.
	homeDir string
	// Masks, applied last so no bind can re-expose them.
	sshKeyPaths      []string // --ro-bind <maskFile> <key>
	awsTmpfsDir      string   // --tmpfs ~/.aws ("" when off/absent)
	maskPaths        []string // --ro-bind /dev/null <socket>
	deniedReadDirs   []string // --perms 000 --tmpfs <dir>
	deniedReadFiles  []string // --ro-bind <maskFile> <file>
	deniedWritePaths []string // --ro-bind <p> <p>, before the read masks
	// maskFile is the source bound over masked files: an empty mode-000 file
	// (see maskSourceFile), or /dev/null when one cannot be created.
	maskFile string
}

// buildBwrapArgs assembles the ordered bwrap argument list for the Linux
// sandbox worker.
//
// Order matters: bwrap applies mounts in sequence and the last overlapping
// mount wins. All writable and read-only binds come first, and every mask
// (credentials, deny lists, broker sockets) is emitted AFTER them. If a mask
// were emitted before a bind that overlaps it (e.g. workDir under $HOME, a
// writable_paths entry of "~", or $HOME itself in denylist mode), the later
// bind would override the mask and re-expose the secret.
//
// Layout:
//   - --ro-bind / / : read-only root filesystem
//   - --tmpfs /tmp : writable /tmp (Go and other tools need it for build cache)
//   - --bind <home> <home> : writable home directory (denylist mode only)
//   - --ro-bind <path> <path> : read-only internal_readable_paths (mostly
//     relevant for host paths the /tmp tmpfs would otherwise hide)
//   - --bind <path> <path> : writable runtime/config directories
//   - --bind <workDir> <workDir> : writable working directory (overrides the
//     /tmp tmpfs when workDir is under /tmp, e.g. in tests)
//   - --ro-bind <p> <p> : write-denied paths (readable, not modifiable)
//   - --ro-bind <maskFile> <ssh-key> : mask each SSH private key
//   - --tmpfs <~/.aws> : empty overlay hiding AWS credentials (IMDS mode)
//   - --perms 000 --tmpfs <dir> : read-denied directories
//   - --ro-bind <maskFile> <file> : read-denied files
//   - --ro-bind /dev/null <socket> : mask broker sockets (e.g. the real
//     Docker daemon socket)
//   - --dev /dev / --proc /proc : fresh devtmpfs and procfs
//   - --unshare-all --share-net : isolate everything but the network
//   - --die-with-parent : the worker dies with the MCP server
func buildBwrapArgs(p bwrapPlan) []string {
	args := []string{
		"--ro-bind", "/", "/",
		"--tmpfs", "/tmp",
	}
	if p.homeDir != "" {
		args = append(args, "--bind", p.homeDir, p.homeDir)
	}

	// Writable and read-only binds first, so the masks below can override any
	// overlap — an internal_readable_paths entry covering ~/.ssh or ~/.aws must
	// not re-expose the masked secrets.
	for _, path := range p.roBinds {
		args = append(args, "--ro-bind", path, path)
	}
	for _, path := range p.binds {
		args = append(args, "--bind", path, path)
	}
	args = append(args, "--bind", p.workDir, p.workDir)

	// Write-denied paths: read-only over themselves. These precede the read
	// masks so a read-denied file inside a write-denied directory (an SSH key
	// under ~/.ssh) ends up masked, not merely read-only.
	for _, path := range p.deniedWritePaths {
		args = append(args, "--ro-bind", path, path)
	}

	maskFile := p.maskFile
	if maskFile == "" {
		maskFile = "/dev/null"
	}
	// Credential/socket masks last: no later mount may override them.
	for _, keyPath := range p.sshKeyPaths {
		args = append(args, "--ro-bind", maskFile, keyPath)
	}
	if p.awsTmpfsDir != "" {
		args = append(args, "--tmpfs", p.awsTmpfsDir)
	}
	for _, dir := range p.deniedReadDirs {
		args = append(args, "--perms", "000", "--tmpfs", dir)
	}
	for _, file := range p.deniedReadFiles {
		args = append(args, "--ro-bind", maskFile, file)
	}
	for _, m := range p.maskPaths {
		args = append(args, "--ro-bind", "/dev/null", m)
	}

	args = append(args,
		"--dev", "/dev",
		"--proc", "/proc",
		"--unshare-all",
		"--share-net",
		"--die-with-parent",
		"--chdir", p.workDir,
		"--",
		p.self, "sandbox-worker",
	)
	return args
}

// maskSourceFile returns the path of an empty, mode-000 file to bind over
// masked files. Unlike /dev/null it yields EACCES to a non-root reader, which
// is both a clearer error for the agent's tools and a signal that can be
// attributed to the sandbox. Falls back to /dev/null if it cannot be created.
func maskSourceFile() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "/dev/null"
	}
	path := filepath.Join(dir, "lite-sandbox", "mask-empty")
	if fi, err := os.Stat(path); err == nil && fi.Mode().IsRegular() && fi.Size() == 0 && fi.Mode().Perm() == 0 {
		return path
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return "/dev/null"
	}
	// Recreate so the content is certainly empty, then drop every permission.
	_ = os.Remove(path)
	if err := os.WriteFile(path, nil, 0600); err != nil {
		return "/dev/null"
	}
	if err := os.Chmod(path, 0); err != nil {
		return "/dev/null"
	}
	return path
}

// sbplDenylist carries the denylist-mode filesystem policy into the SBPL
// profile generator.
type sbplDenylist struct {
	homeWritable     bool
	deniedReadPaths  []string
	deniedWritePaths []string
}

// generateSBPLProfile generates a Scheme-based sandbox profile for macOS sandbox-exec.
// The profile allows read-only access to the entire filesystem, but restricts writes
// to specific directories (workDir, extraBinds, and system temp directories).
// masks carries the credential paths to deny (see resolveCredentialMasks):
// ~/.ssh private keys are ALWAYS blocked, ~/.aws only when AWS blocking is on.
func generateSBPLProfile(workDir string, extraBinds []string, masks credentialMasks, maskPaths []string, dl sbplDenylist) string {
	var sb strings.Builder

	sb.WriteString("(version 1)\n")
	sb.WriteString("(allow default)\n")

	if masks.homeErr != nil {
		// Fall back to not blocking if we can't get home dir
		slog.Warn("failed to get home directory for SBPL profile", "error", masks.homeErr)
		return sb.String()
	}

	// Deny access to credential files (must come after allow default)
	// Block SSH private keys but allow known_hosts and config
	for _, keyPath := range masks.sshKeyPaths {
		sb.WriteString(fmt.Sprintf("(deny file-read* (literal \"%s\"))\n", keyPath))
	}

	// Conditionally block ~/.aws
	if masks.awsDir != "" {
		sb.WriteString(fmt.Sprintf("(deny file-read* (subpath \"%s\"))\n", masks.awsDir))
	}

	// Mask broker sockets (e.g. the real Docker daemon socket): deny both file
	// access and outbound connection so a sandboxed command can only reach the
	// proxy, not the underlying socket directly.
	for _, p := range maskPaths {
		sb.WriteString(fmt.Sprintf("(deny file-read* file-write* (literal \"%s\"))\n", p))
		sb.WriteString(fmt.Sprintf("(deny network-outbound (literal \"%s\"))\n", p))
	}

	// Denylist mode: read-denied paths are hidden outright. Seatbelt matches
	// on the real path, so emit the symlink-resolved form too.
	for _, p := range dl.deniedReadPaths {
		for _, rp := range withResolved(p) {
			sb.WriteString(fmt.Sprintf("(deny file-read* (%s \"%s\"))\n", sbplScope(rp), rp))
		}
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

	// Denylist mode: the home directory is writable, then the write-denied
	// paths are carved back out. Last matching rule wins, so the denies must
	// follow the home allow.
	if dl.homeWritable {
		if home, err := os.UserHomeDir(); err == nil {
			for _, h := range withResolved(home) {
				sb.WriteString(fmt.Sprintf("(allow file-write* (subpath \"%s\"))\n", h))
			}
		}
	}
	for _, p := range dl.deniedWritePaths {
		for _, rp := range withResolved(p) {
			sb.WriteString(fmt.Sprintf("(deny file-write* (%s \"%s\"))\n", sbplScope(rp), rp))
		}
	}

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

// sbplScope returns the SBPL path filter for p: "subpath" for a directory (or
// a path that does not exist yet), "literal" for a file.
func sbplScope(p string) string {
	if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
		return "literal"
	}
	return "subpath"
}

// withResolved returns p and, when it differs, its symlink-resolved form.
func withResolved(p string) []string {
	if r, err := filepath.EvalSymlinks(p); err == nil && r != p {
		return []string{p, r}
	}
	return []string{p}
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

// pumpStdinForID reads from r in streamChunkSize chunks and sends them to the worker with the given ID,
// then sends HostMsgStdinEOF. If r is nil, only the EOF is sent.
func (w *Worker) pumpStdinForID(id uint64, r io.Reader) error {
	if r != nil {
		buf := make([]byte, streamChunkSize)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				if encErr := w.enc.send(HostMsg{ID: id, Type: HostMsgStdin, Data: buf[:n]}); encErr != nil {
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
