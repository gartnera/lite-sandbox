package bash_sandboxed

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/os_sandbox"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// CommandFailedError is returned when a command passes validation and starts
// executing but exits with a non-zero status or fails during execution.
// Use errors.As to distinguish this from validation errors.
type CommandFailedError struct {
	Err    error
	Output string
}

func (e *CommandFailedError) Error() string {
	return fmt.Sprintf("command failed: %v\noutput: %s", e.Err, e.Output)
}

func (e *CommandFailedError) Unwrap() error {
	return e.Err
}

// Sandbox executes bash commands after parsing and validating them against
// the built-in allowlist plus any extra commands from config.
type Sandbox struct {
	mu            sync.RWMutex
	cfg           *config.Config
	extraCommands map[string]bool
	// extraSubCommands holds per-command argument-prefix restrictions parsed
	// from extra_commands entries that contain a space (e.g. "pnpx prettier"
	// or "uv run pyright"). Each inner slice is one allowed prefix of
	// non-flag arguments; an invocation matches when its leading non-flag
	// args start with any of those sequences.
	extraSubCommands map[string][][]string
	// bareExtraCommands tracks commands that have a bare entry in extra_commands
	// (i.e., the entry has no subcommand restriction). These commands bypass
	// bash AST parsing and are executed directly with the real bash.
	bareExtraCommands map[string]bool
	// bareExtraScriptPaths is the set of absolute paths corresponding to
	// path-like bare entries in extra_commands (e.g., "./scripts/foo.sh"
	// resolved against workDir at config-update time). The ExecHandler uses
	// this so that invoking the same script from a different cwd (after a
	// `cd`) still hits the bare-extra bypass — interp tracks cwd in
	// HandlerContext, so the lookup is done with the post-`cd` directory.
	bareExtraScriptPaths map[string]bool
	// unsandboxed_commands entries are treated exactly like extra_commands for
	// validation (merged into the maps above so they are allowed and bare entries
	// skip AST parsing); the only difference is that matching invocations execute
	// directly on the host, bypassing the OS sandbox worker even when it is
	// enabled. The maps below mirror bareExtraCommands / bareExtraScriptPaths /
	// extraSubCommands but only for the unsandboxed subset, so routing is decided
	// per invocation (a subcommand-restricted entry like "git push" unsandboxes
	// only matching calls, not every use of the binary).
	unsandboxedBare            map[string]bool
	unsandboxedBareScriptPaths map[string]bool
	unsandboxedSub             map[string][][]string
	imdsEndpoint               string
	// dockerHost is the DOCKER_HOST value (unix://… proxy socket) injected into
	// sandboxed commands when the docker proxy is running. dockerSocketDir is the
	// directory holding that socket, bind-mounted into the OS sandbox worker so
	// the worker can connect to it.
	dockerHost      string
	dockerSocketDir string
	// dockerMaskPaths are real daemon socket paths to mask inside the OS sandbox
	// worker (e.g. /var/run/docker.sock) so the proxy is the only reachable
	// daemon and cannot be bypassed.
	dockerMaskPaths []string
	// runtimeReadPaths is the lazily computed result of detectRuntimeBinds for
	// the current config; runtimeDetected marks it as valid. Detection spawns
	// subprocesses (go, pnpm), so it is deferred until a caller actually needs
	// the paths rather than run eagerly on every UpdateConfig.
	runtimeReadPaths []string
	runtimeDetected  bool
	// worktreeParentCache memoizes detectWorktreeParent per working directory
	// so long-lived callers (the MCP server) don't fork git on every command.
	worktreeParentCache map[string]string
	osSandbox           bool
	worker              *os_sandbox.Worker
	workerWorkDir       string
	workerBlockAWS      bool
	// argValidators holds a reference to commandArgValidators so that
	// validateSubCommand can look up per-command validators at runtime
	// without creating a package-level initialization cycle.
	argValidators map[string]func(s *Sandbox, args []*syntax.Word) error
	// bg tracks background ("run_in_background") processes started via
	// ExecuteBackground, mirroring the Claude Code Bash/BashOutput/KillShell tools.
	bg *backgroundManager
}

// NewSandbox creates a Sandbox with no extra commands.
func NewSandbox() *Sandbox {
	return &Sandbox{
		cfg:           &config.Config{},
		argValidators: commandArgValidators,
		bg:            newBackgroundManager(),
	}
}

// UpdateConfig replaces the sandbox configuration with the provided config.
func (s *Sandbox) UpdateConfig(cfg *config.Config, workDir string) {
	m := make(map[string]bool, len(cfg.ExtraCommands)+len(cfg.UnsandboxedCommands))
	sub := make(map[string][][]string)
	bare := make(map[string]bool)
	bareScripts := make(map[string]bool)
	unsandboxedBare := make(map[string]bool)
	unsandboxedBareScripts := make(map[string]bool)
	unsandboxedSub := make(map[string][][]string)
	// processEntry parses one whitespace-separated entry into the command maps.
	// A single token (e.g. "fvm") is a bare entry that allows the command with
	// any arguments; multiple tokens (e.g. "pnpx prettier", "uv run pyright")
	// restrict the command so that its leading non-flag arguments must match the
	// remaining tokens as a prefix. When fromUnsandboxed is set the same parse is
	// also recorded in the unsandboxed maps so matching invocations bypass the OS
	// sandbox worker.
	processEntry := func(c string, fromUnsandboxed bool) {
		fields := strings.Fields(c)
		if len(fields) == 0 {
			return
		}
		cmd := fields[0]
		m[cmd] = true
		if len(fields) == 1 {
			bare[cmd] = true
			if isScriptPath(cmd) && workDir != "" {
				bareScripts[absPath(cmd, workDir)] = true
			}
			if fromUnsandboxed {
				unsandboxedBare[cmd] = true
				if isScriptPath(cmd) && workDir != "" {
					unsandboxedBareScripts[absPath(cmd, workDir)] = true
				}
			}
		} else {
			sub[cmd] = append(sub[cmd], fields[1:])
			if fromUnsandboxed {
				unsandboxedSub[cmd] = append(unsandboxedSub[cmd], fields[1:])
			}
		}
	}
	for _, c := range cfg.ExtraCommands {
		processEntry(c, false)
	}
	for _, c := range cfg.UnsandboxedCommands {
		processEntry(c, true)
	}
	// Determine if AWS credentials should be blocked, resolving any
	// per-directory override for the worker's working directory.
	blockAWSCredentials := shouldBlockAWSCredentials(cfg.AWS.ForDirectory(workDir))

	s.mu.Lock()
	s.cfg = cfg
	s.extraCommands = m
	s.extraSubCommands = sub
	s.bareExtraCommands = bare
	s.bareExtraScriptPaths = bareScripts
	s.unsandboxedBare = unsandboxedBare
	s.unsandboxedBareScriptPaths = unsandboxedBareScripts
	s.unsandboxedSub = unsandboxedSub

	// Invalidate lazily computed state derived from the previous config.
	// Runtime paths (GOPATH, GOCACHE, pnpm store, ...) are detected on first
	// use via RuntimeReadPaths, since detection spawns subprocesses.
	s.runtimeReadPaths = nil
	s.runtimeDetected = false
	s.worktreeParentCache = nil

	// Store worker config for lazy start / restart.
	s.workerWorkDir = workDir
	s.workerBlockAWS = blockAWSCredentials

	// Close any live worker on every config update: the AWS credential mask,
	// writable_paths, worktree-parent grant, runtime binds, and more are all
	// baked into the worker's mount setup / SBPL profile at start time, so a
	// stale worker would keep enforcing the old policy. Rather than tracking
	// which of those inputs changed, recycle unconditionally — UpdateConfig only
	// fires when the config actually changed, and the next command lazily starts
	// a replacement with the new settings.
	newOSSandbox := cfg.OSSandboxEnabled()
	if s.worker != nil {
		slog.Info("closing existing worker after config update")
		s.worker.Close()
		s.worker = nil
	}
	if newOSSandbox && !s.osSandbox {
		slog.Info("enabling OS sandbox", "block_aws_credentials", blockAWSCredentials)
	}
	s.osSandbox = newOSSandbox
	s.mu.Unlock()
}

// shouldBlockAWSCredentials determines if ~/.aws/ should be blocked.
// Returns true if AWS is configured to use IMDS (force_profile set).
// Returns false if AWS allows raw credentials or is not configured.
// Note: ~/.ssh/ private keys are ALWAYS blocked regardless of this setting.
func shouldBlockAWSCredentials(awsCfg *config.AWSConfig) bool {
	if awsCfg == nil {
		return false
	}
	// Block AWS credentials only when using IMDS (force_profile is set)
	return awsCfg.UsesIMDS()
}

// getConfig returns a snapshot of the current config.
func (s *Sandbox) getConfig() *config.Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

// awsConfigForWorker returns the AWS config resolved for the worker's working
// directory, so per-directory overrides apply to command validation the same
// way they apply to the IMDS server and credential blocking.
func (s *Sandbox) awsConfigForWorker() *config.AWSConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.cfg == nil {
		return nil
	}
	return s.cfg.AWS.ForDirectory(s.workerWorkDir)
}

// osSandboxEnabled reports whether the OS sandbox (bwrap/sandbox-exec worker)
// is currently active. Used to gate process-control commands that are only
// safe when execution is contained.
func (s *Sandbox) osSandboxEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.osSandbox
}

// getExtraCommands returns a snapshot of the current extra commands.
func (s *Sandbox) getExtraCommands() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.extraCommands
}

// getExtraSubCommands returns the per-command argument-prefix restriction map.
// A nil entry for a command means no restriction (any args allowed).
// A non-nil entry means the invocation's leading non-flag args must match
// one of the recorded token sequences as a prefix.
func (s *Sandbox) getExtraSubCommands() map[string][][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.extraSubCommands
}

// SetIMDSEndpoint sets the IMDS endpoint URL for AWS credential fetching.
func (s *Sandbox) SetIMDSEndpoint(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.imdsEndpoint = endpoint
}

// DockerHostConfigured reports whether a docker proxy endpoint has been wired
// in via SetDockerHost. Command gating uses this so the "docker" command is
// only allowed when the filtering proxy is actually running and DOCKER_HOST
// will be injected — otherwise a command would fall back to the real daemon
// socket, bypassing the proxy.
func (s *Sandbox) DockerHostConfigured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dockerHost != ""
}

// SetDockerHost sets the DOCKER_HOST value (the docker proxy socket) and the
// directory holding that socket. The directory is bind-mounted into the OS
// sandbox worker so sandboxed commands can reach the proxy, and maskSockets are
// the real daemon socket paths masked inside the worker so the proxy cannot be
// bypassed (e.g. via `unset DOCKER_HOST`). Passing an empty host disables
// docker access for subsequent commands.
func (s *Sandbox) SetDockerHost(host, socketDir string, maskSockets ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dockerHost = host
	s.dockerSocketDir = socketDir
	s.dockerMaskPaths = dedupeMaskPaths(maskSockets)
}

// dedupeMaskPaths returns the non-empty, de-duplicated socket paths to mask,
// always including the conventional /var/run/docker.sock so a sandboxed command
// cannot reach the default socket even when a custom upstream is configured.
func dedupeMaskPaths(sockets []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range sockets {
		add(p)
	}
	add("/var/run/docker.sock")
	return out
}

// RuntimeReadPaths returns the detected runtime paths that should be
// readable (but not writable) by sandboxed commands. These include paths
// like GOPATH, GOCACHE, and pnpm store directories.
//
// Detection runs lazily on first use (it spawns subprocesses) and the result
// is cached until the next UpdateConfig. Concurrent first calls may detect
// twice; both store the same result.
func (s *Sandbox) RuntimeReadPaths() []string {
	s.mu.RLock()
	if s.runtimeDetected {
		paths := s.runtimeReadPaths
		s.mu.RUnlock()
		return paths
	}
	runtimes := s.cfg.Runtimes
	s.mu.RUnlock()

	paths := detectRuntimeBinds(runtimes)

	s.mu.Lock()
	// Only cache if the config didn't change while detection ran without the
	// lock held; a stale result must not outlive an UpdateConfig.
	if s.cfg.Runtimes == runtimes {
		s.runtimeReadPaths = paths
		s.runtimeDetected = true
	}
	s.mu.Unlock()
	return paths
}

// ConfigReadPaths returns the user-configured readable paths (with ~ expanded).
func (s *Sandbox) ConfigReadPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ExpandedReadablePaths()
}

// ConfigWritePaths returns the user-configured writable paths (with ~ expanded).
func (s *Sandbox) ConfigWritePaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg.ExpandedWritablePaths()
}

// Close shuts down the sandbox, killing any background processes and closing
// the worker if running.
func (s *Sandbox) Close() error {
	if s.bg != nil {
		s.bg.killAll()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.worker != nil {
		return s.worker.Close()
	}
	return nil
}

// detectRuntimeBinds detects paths needed by enabled runtimes and returns them
// as a list of directories to bind mount as writable in the OS sandbox.
func detectRuntimeBinds(runtimes *config.RuntimesConfig) []string {
	if runtimes == nil {
		return nil
	}

	var binds []string

	// Detect Go paths if Go runtime is enabled. Detection shells out to
	// `go env`, so results are persisted across processes (see runtime_cache.go).
	if runtimes.Go != nil && runtimes.Go.GoEnabled() {
		goBinds := cachedDetect("go", []string{"GOPATH", "GOCACHE", "GOENV", "HOME"}, detectGoBinds)
		binds = append(binds, goBinds...)
	}

	// Detect pnpm paths if pnpm runtime is enabled. `pnpm store path` boots
	// node and costs hundreds of milliseconds, so it is cached persistently.
	if runtimes.Pnpm != nil && runtimes.Pnpm.PnpmEnabled() {
		pnpmBinds := cachedDetect("pnpm", []string{"PNPM_HOME", "XDG_DATA_HOME", "HOME"}, detectPnpmBinds)
		binds = append(binds, pnpmBinds...)
	}

	// Detect Rust paths if Rust runtime is enabled
	if runtimes.Rust != nil && runtimes.Rust.RustEnabled() {
		rustBinds := detectRustBinds()
		binds = append(binds, rustBinds...)
	}

	// Detect Deno paths if Deno runtime is enabled
	if runtimes.Deno != nil && runtimes.Deno.DenoEnabled() {
		denoBinds := detectDenoBinds()
		binds = append(binds, denoBinds...)
	}

	// Detect Flutter/Dart/fvm paths if the Flutter runtime is enabled
	if runtimes.Flutter != nil && runtimes.Flutter.FlutterEnabled() {
		flutterBinds := detectFlutterBinds()
		binds = append(binds, flutterBinds...)
	}

	// Detect uv paths if uv runtime is enabled. `uv cache dir` (and friends)
	// shell out, so results are persisted across processes (see runtime_cache.go).
	if runtimes.Uv != nil && runtimes.Uv.UvEnabled() {
		uvBinds := cachedDetect("uv", []string{
			"UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "UV_TOOL_DIR",
			"XDG_CACHE_HOME", "XDG_DATA_HOME", "XDG_BIN_HOME", "HOME",
		}, detectUvBinds)
		binds = append(binds, uvBinds...)
	}

	return binds
}

// detectGoBinds detects Go environment paths that need to be writable.
// Returns GOPATH and GOCACHE (build cache) directories.
func detectGoBinds() []string {
	cmd := exec.Command("go", "env", "GOPATH", "GOCACHE")
	output, err := cmd.Output()
	if err != nil {
		slog.Warn("failed to detect Go paths", "error", err)
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var paths []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "off" {
			paths = append(paths, line)
		}
	}

	if len(paths) > 0 {
		slog.Info("detected Go runtime paths", "paths", paths)
	}

	return paths
}

// detectPnpmBinds detects pnpm paths that need to be writable.
// Returns the pnpm store directory where packages are cached.
func detectPnpmBinds() []string {
	cmd := exec.Command("pnpm", "store", "path")
	output, err := cmd.Output()
	if err != nil {
		slog.Warn("failed to detect pnpm paths", "error", err)
		return nil
	}

	storePath := strings.TrimSpace(string(output))
	if storePath == "" {
		return nil
	}

	paths := []string{storePath}
	slog.Info("detected pnpm runtime paths", "paths", paths)
	return paths
}

// detectRustBinds detects Rust/Cargo paths that need to be writable.
// Returns CARGO_HOME (registry, git) and RUSTUP_HOME directories.
func detectRustBinds() []string {
	var paths []string

	// Detect CARGO_HOME (defaults to ~/.cargo)
	cargoHome := os.Getenv("CARGO_HOME")
	if cargoHome == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			cargoHome = home + "/.cargo"
		}
	}
	if cargoHome != "" {
		if _, err := os.Stat(cargoHome); err == nil {
			paths = append(paths, cargoHome)
		}
	}

	// Detect RUSTUP_HOME (defaults to ~/.rustup)
	rustupHome := os.Getenv("RUSTUP_HOME")
	if rustupHome == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			rustupHome = home + "/.rustup"
		}
	}
	if rustupHome != "" {
		if _, err := os.Stat(rustupHome); err == nil {
			paths = append(paths, rustupHome)
		}
	}

	if len(paths) > 0 {
		slog.Info("detected Rust runtime paths", "paths", paths)
	}

	return paths
}

// detectDenoBinds detects Deno paths that need to be writable.
// Returns DENO_DIR (module/npm cache) and DENO_INSTALL_ROOT (global scripts
// installed via `deno install -g`).
//
// Unlike the other runtimes, deno creates its cache lazily on first run, so
// these directories frequently do not exist yet. We create them up front: a
// bind mount source must exist for the OS sandbox to mount it writable, and
// the sandbox cannot create the directory itself (its parent is not bound), so
// without this the very first `deno run` would fail to populate its cache.
func detectDenoBinds() []string {
	var paths []string

	// Detect DENO_DIR (module and npm cache). Defaults to the OS cache dir
	// joined with "deno" (e.g. ~/.cache/deno on Linux).
	denoDir := os.Getenv("DENO_DIR")
	if denoDir == "" {
		if cacheDir, err := os.UserCacheDir(); err == nil {
			denoDir = filepath.Join(cacheDir, "deno")
		}
	}
	if p := ensureDir(denoDir); p != "" {
		paths = append(paths, p)
	}

	// Detect DENO_INSTALL_ROOT (global executables). Defaults to ~/.deno.
	installRoot := os.Getenv("DENO_INSTALL_ROOT")
	if installRoot == "" {
		if home, err := os.UserHomeDir(); err == nil {
			installRoot = filepath.Join(home, ".deno")
		}
	}
	if p := ensureDir(installRoot); p != "" {
		paths = append(paths, p)
	}

	if len(paths) > 0 {
		slog.Info("detected Deno runtime paths", "paths", paths)
	}

	return paths
}

// detectUvBinds detects the uv (Python package manager) paths that need to be
// writable. uv downloads and builds wheels into its cache, installs Python
// interpreters, and stores tool environments; all live outside the working
// directory, so they must be bound in for uv to function under the OS sandbox:
//   - `uv cache dir`  — the package/wheel cache (default ~/.cache/uv)
//   - `uv python dir` — uv-managed Python interpreters (default ~/.local/share/uv/python)
//   - `uv tool dir`   — tool environments from `uv tool install` (default ~/.local/share/uv/tools)
//
// The tool *bin* directory (`uv tool dir --bin`, default ~/.local/bin) is
// deliberately NOT bound: it lives on the user's PATH, so binding it writable
// would let a sandboxed command install executables that persist and run
// outside the sandbox boundary. `uv tool install` therefore cannot place its
// launcher and fails, which is the intended restriction; `uvx` (ephemeral tool
// runs cached under `uv cache dir`) still works.
//
// Like Deno, uv creates these lazily on first use, so they frequently do not
// exist yet. We create them up front because a bind-mount source must exist for
// the OS sandbox to mount it, and the sandbox cannot create the directory
// itself (its parent is not bound).
func detectUvBinds() []string {
	var paths []string
	seen := map[string]bool{}
	for _, sub := range [][]string{
		{"cache", "dir"},
		{"python", "dir"},
		{"tool", "dir"},
	} {
		cmd := exec.Command("uv", sub...)
		output, err := cmd.Output()
		if err != nil {
			slog.Warn("failed to detect uv path", "subcommand", strings.Join(sub, " "), "error", err)
			continue
		}
		dir := strings.TrimSpace(string(output))
		if p := ensureDir(dir); p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	if len(paths) > 0 {
		slog.Info("detected uv runtime paths", "paths", paths)
	}

	return paths
}

// ensureDir creates dir (and parents) if needed and returns it, or "" if dir
// is empty or cannot be created. Used to materialize runtime cache directories
// so they exist as bind-mount sources for the OS sandbox.
func ensureDir(dir string) string {
	if dir == "" {
		return ""
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		slog.Warn("failed to create runtime directory", "path", dir, "error", err)
		return ""
	}
	return dir
}

// detectFlutterBinds detects the paths that Flutter, Dart, and fvm read and
// write, so the sandbox can grant access to them automatically (mirroring the
// Go runtime's GOPATH/GOCACHE handling). The paths are:
//
//   - the fvm cache (FVM_CACHE_PATH / legacy FVM_HOME, default ~/fvm), where fvm
//     stores each managed Flutter SDK version;
//   - the pub cache (PUB_CACHE, default ~/.pub-cache), where Dart/Flutter
//     packages are downloaded;
//   - the active Flutter SDK root (FLUTTER_ROOT, or resolved from a flutter
//     binary on PATH), which Flutter writes to under bin/cache;
//   - the Flutter/Dart config directories, where the tools persist settings.
//
// Like the caches for other runtimes these directories are frequently created
// lazily on first run, so cache directories are materialized up front (a bind
// mount source must exist for the OS sandbox to mount it). Only directories that
// exist (or can be created) are returned, so a partial toolchain still works.
func detectFlutterBinds() []string {
	var paths []string
	home, _ := os.UserHomeDir()

	// fvm cache: FVM_CACHE_PATH is the current override, FVM_HOME the legacy one.
	fvmCache := cmp.Or(os.Getenv("FVM_CACHE_PATH"), os.Getenv("FVM_HOME"))
	if fvmCache == "" && home != "" {
		fvmCache = filepath.Join(home, "fvm")
	}
	if p := ensureDir(fvmCache); p != "" {
		paths = append(paths, p)
	}

	// pub cache: PUB_CACHE overrides the default ~/.pub-cache.
	pubCache := os.Getenv("PUB_CACHE")
	if pubCache == "" && home != "" {
		pubCache = filepath.Join(home, ".pub-cache")
	}
	if p := ensureDir(pubCache); p != "" {
		paths = append(paths, p)
	}

	// Active Flutter SDK root (for a non-fvm global install). fvm-managed SDKs
	// live under the fvm cache above, or the project's .fvm/flutter_sdk symlink,
	// which is already under the working directory.
	if sdk := detectFlutterSDKRoot(); sdk != "" {
		paths = append(paths, sdk)
	}

	// Config directories where Flutter and Dart persist settings and analytics
	// state. These already exist on a configured machine; create them so the
	// tools can write on a fresh one.
	if home != "" {
		for _, rel := range []string{
			filepath.Join(".config", "flutter"),
			filepath.Join(".config", "dart"),
			".flutter",
			".dart",
		} {
			if p := ensureDir(filepath.Join(home, rel)); p != "" {
				paths = append(paths, p)
			}
		}
	}

	if len(paths) > 0 {
		slog.Info("detected Flutter runtime paths", "paths", paths)
	}
	return paths
}

// detectFlutterSDKRoot returns the root directory of the active Flutter SDK, or
// "" if it cannot be located. FLUTTER_ROOT wins when set; otherwise a flutter
// binary on PATH is resolved (following symlinks) to <root>/bin/flutter and the
// grandparent is returned. The candidate is only accepted when it looks like a
// Flutter SDK checkout (it contains a packages directory), so a stray binary in
// a system directory like /usr/bin never widens access to /usr.
func detectFlutterSDKRoot() string {
	if root := os.Getenv("FLUTTER_ROOT"); root != "" {
		if isFlutterSDKRoot(root) {
			return root
		}
	}
	bin, err := exec.LookPath("flutter")
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(bin); err == nil {
		bin = resolved
	}
	root := filepath.Dir(filepath.Dir(bin))
	if isFlutterSDKRoot(root) {
		return root
	}
	return ""
}

// isFlutterSDKRoot reports whether dir looks like a Flutter SDK checkout. Every
// SDK ships a top-level packages directory alongside bin/, which distinguishes a
// real SDK from an ordinary bin directory such as /usr/bin.
func isFlutterSDKRoot(dir string) bool {
	if dir == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(dir, "packages"))
	return err == nil && info.IsDir()
}

// ParseBash parses a command string as bash and returns the AST.
func ParseBash(command string) (*syntax.File, error) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	f, err := parser.Parse(strings.NewReader(command), "")
	if err != nil {
		return nil, fmt.Errorf("failed to parse bash: %w", err)
	}
	return f, nil
}

// blockedEnvVars lists environment variables that cannot be assigned in sandboxed commands.
// PATH is inherited but cannot be mutated (prevents command whitelist bypass).
// Others prevent shared library injection, auto-sourced scripts, and unexpected behavior.
var blockedEnvVars = map[string]string{
	"PATH":            "mutating PATH could bypass the command whitelist",
	"LD_PRELOAD":      "shared library injection",
	"LD_LIBRARY_PATH": "shared library injection",
	"BASH_ENV":        "auto-sourced script injection",
	"ENV":             "auto-sourced script injection",
	"CDPATH":          "unexpected directory resolution",
	"PROMPT_COMMAND":  "arbitrary command execution",
}

// validateAssigns checks that none of the assignments target a blocked environment variable.
func validateAssigns(assigns []*syntax.Assign) error {
	for _, a := range assigns {
		if a.Name == nil {
			continue
		}
		if reason, blocked := blockedEnvVars[a.Name.Value]; blocked {
			return fmt.Errorf("setting %s is not allowed: %s", a.Name.Value, reason)
		}
	}
	return nil
}

// collectDeclaredFunctions walks the AST and collects function names from:
// 1. FuncDecl nodes (inline function declarations)
// 2. source/. commands with literal file paths (read and extract FuncDecl names)
// This allows validate() to permit calls to user-defined functions.
func collectDeclaredFunctions(f *syntax.File, workDir string) map[string]bool {
	funcs := make(map[string]bool)
	syntax.Walk(f, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.FuncDecl:
			funcs[n.Name.Value] = true
		case *syntax.CallExpr:
			if len(n.Args) >= 2 {
				cmdName := extractCommandName(n.Args[0])
				if cmdName == "source" || cmdName == "." {
					filePath := n.Args[1].Lit()
					if filePath != "" && workDir != "" {
						extractFunctionsFromFile(filePath, workDir, funcs)
					}
				}
			}
		}
		return true
	})
	return funcs
}

// extractFunctionsFromFile reads a shell script file and adds any function
// declarations to the funcs set. Errors are silently ignored (fail-open).
func extractFunctionsFromFile(filePath, workDir string, funcs map[string]bool) {
	path := absPath(filePath, workDir)
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	script := string(data)
	if strings.HasPrefix(script, "#!") {
		if idx := strings.IndexByte(script, '\n'); idx >= 0 {
			script = script[idx+1:]
		}
	}
	sf, err := ParseBash(script)
	if err != nil {
		return
	}
	syntax.Walk(sf, func(node syntax.Node) bool {
		if fd, ok := node.(*syntax.FuncDecl); ok {
			funcs[fd.Name.Value] = true
		}
		return true
	})
}

// validate walks the parsed AST and enforces:
// 1. All commands must be in the allowedCommands whitelist, extra commands, or declared functions
// 2. Redirections must pass validateRedirect (safe subset only)
// 3. No process substitutions are permitted
// 4. Per-command argument validators (e.g., blocking find -exec)
// 5. Blocked environment variable assignments (PATH, LD_PRELOAD, etc.)
func (s *Sandbox) validate(f *syntax.File) error {
	return s.validateWithFunctions(f, nil)
}

// validateWithWorkDir validates the AST, also collecting function declarations
// from inline FuncDecl nodes and sourced files to allow calls to user-defined functions.
func (s *Sandbox) validateWithWorkDir(f *syntax.File, workDir string) error {
	funcs := collectDeclaredFunctions(f, workDir)
	return s.validateWithFunctions(f, funcs)
}

// validateWithFunctions is the core validation logic, optionally accepting
// a set of declared function names to allow in addition to the command whitelist.
func (s *Sandbox) validateWithFunctions(f *syntax.File, declaredFuncs map[string]bool) error {
	extra := s.getExtraCommands()
	extraSub := s.getExtraSubCommands()
	bare := s.getBareExtraCommands()
	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		switch n := node.(type) {
		case *syntax.Stmt:
			for _, r := range n.Redirs {
				if err := validateRedirect(r); err != nil {
					validationErr = err
					return false
				}
			}
		case *syntax.CallExpr:
			if err := validateAssigns(n.Assigns); err != nil {
				validationErr = err
				return false
			}
			if len(n.Args) > 0 {
				cmdName := extractCommandName(n.Args[0])
				if cmdName == "" {
					validationErr = fmt.Errorf("dynamic command names are not allowed")
					return false
				}
				// Check whether this command is allowed via extra_commands.
				// Bare entries (no subcommand restriction) always match.
				// Restricted entries (e.g. "pnpx prettier") only match when the
				// first non-flag argument matches the restriction.
				inExtra := extra[cmdName] && (bare[cmdName] || extraSubCommandMatches(extraSub, cmdName, n.Args))
				// Process-control commands (kill, pkill) are allowed only when the
				// OS sandbox is active, where they are contained to sandbox-spawned
				// processes.
				osOnly := osSandboxOnlyCommands[cmdName] && s.osSandboxEnabled()
				if !allowedCommands[cmdName] && !inExtra && !declaredFuncs[cmdName] && !osOnly {
					if !s.getConfig().LocalBinaryExecution.IsEnabled() || !isScriptPath(cmdName) {
						validationErr = fmt.Errorf("command %q is not allowed", cmdName)
						return false
					}
				}
				// Skip per-command validators for commands allowed via extra_commands —
				// the user has explicitly opted in to those commands.
				if !inExtra {
					if validator, ok := commandArgValidators[cmdName]; ok {
						if err := validator(s, n.Args); err != nil {
							validationErr = err
							return false
						}
					}
				}
			}
		case *syntax.DeclClause:
			if err := validateAssigns(n.Args); err != nil {
				validationErr = err
				return false
			}
		case *syntax.ProcSubst:
			// Allowed: the walker recurses into the substitution's statements,
			// so all commands inside are validated against the whitelist.
		case *syntax.CoprocClause:
			validationErr = fmt.Errorf("coprocesses are not allowed")
			return false
		}
		return true
	})
	return validationErr
}

// extractCommandName returns the literal name of a command from a Word node.
// Returns empty string if the command name cannot be statically determined.
func extractCommandName(w *syntax.Word) string {
	return w.Lit()
}

// extraSubCommandMatches reports whether a command invocation satisfies any
// subcommand restriction registered for cmdName in extraSub.
//
//   - If extraSub has no entry for cmdName, the bare command is in extra_commands
//     with no restriction, so it always matches (returns true).
//   - If extraSub has an entry, the invocation's leading non-flag arguments
//     must match one of the recorded token sequences as a prefix.
//   - If the invocation has no non-flag arguments at all, it is allowed
//     (typically prints help).
func extraSubCommandMatches(extraSub map[string][][]string, cmdName string, args []*syntax.Word) bool {
	allowed, hasRestriction := extraSub[cmdName]
	if !hasRestriction {
		return true // bare "cmd" entry, no subcommand restriction
	}
	// Collect non-flag arguments in order.
	var nonFlag []string
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" || strings.HasPrefix(lit, "-") {
			continue
		}
		nonFlag = append(nonFlag, lit)
	}
	if len(nonFlag) == 0 {
		return true // no subcommand argument — safe (prints help)
	}
	for _, seq := range allowed {
		if len(seq) > len(nonFlag) {
			continue
		}
		match := true
		for i, tok := range seq {
			if nonFlag[i] != tok {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ValidateCommand parses and validates a bash command without executing it.
// It mirrors the validation in Execute() but skips execution.
// workDir is the working directory for resolving relative paths.
// readAllowedPaths are absolute directories that read-only commands may access.
// writeAllowedPaths are absolute directories that write commands may access.
func (s *Sandbox) ValidateCommand(command string, workDir string, readAllowedPaths, writeAllowedPaths []string) error {
	// Bare extra_commands entries bypass AST parsing; treat as valid.
	if s.isExtraCommandInvocation(command) {
		return nil
	}
	f, err := ParseBash(command)
	if err != nil {
		return err
	}
	if err := s.validateWithWorkDir(f, workDir); err != nil {
		return err
	}
	if err := validatePaths(f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return err
	}
	if err := validateRedirectPaths(f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return err
	}
	if err := s.validateScriptContents(f, workDir, readAllowedPaths, writeAllowedPaths, 0); err != nil {
		return err
	}
	return nil
}

// validateScriptContents walks the AST looking for script invocations
// (direct script paths like ./script.sh or bash/sh with a script file),
// reads the script contents, and validates them recursively. This catches
// cases where a script file contains blocked commands that would otherwise
// only fail once reached at runtime, rejecting the command up front instead.
// Errors reading files are silently ignored (fail-open) since the file may
// not exist yet at validation time.
func (s *Sandbox) validateScriptContents(f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string, depth int) error {
	if depth >= maxBashDepth {
		return fmt.Errorf("script nesting depth exceeded (max %d)", maxBashDepth)
	}

	var validationErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if validationErr != nil {
			return false
		}
		ce, ok := node.(*syntax.CallExpr)
		if !ok || len(ce.Args) == 0 {
			return true
		}

		cmdName := extractCommandName(ce.Args[0])
		if cmdName == "" {
			return true
		}

		switch {
		case isScriptPath(cmdName):
			validationErr = s.validateScriptFile(cmdName, workDir, readAllowedPaths, writeAllowedPaths, depth)
		case cmdName == "bash" || cmdName == "sh":
			validationErr = s.validateBashScriptArg(ce.Args, workDir, readAllowedPaths, writeAllowedPaths, depth)
		case cmdName == "source" || cmdName == ".":
			validationErr = s.validateSourceFileArg(ce.Args, workDir, readAllowedPaths, writeAllowedPaths, depth)
		}

		return validationErr == nil
	})
	return validationErr
}

// validateScriptFile reads a script file path, parses and validates its contents.
func (s *Sandbox) validateScriptFile(scriptPath, workDir string, readAllowedPaths, writeAllowedPaths []string, depth int) error {
	path := absPath(scriptPath, workDir)
	// Bare extra_commands script entries are an explicit trust opt-in; skip
	// body validation regardless of how the script is reached (directly,
	// `bash <script>`, or `source <script>`). This mirrors the runtime
	// ExecHandler bypass so static preflight does not reject a script the user
	// deliberately opted out of validation for.
	if s.getBareExtraCommands()[scriptPath] || s.getBareExtraScriptPaths()[path] {
		return nil
	}
	if isBinaryExecutable(path) {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // fail-open: file may not exist at validation time
	}
	script := string(data)
	if strings.HasPrefix(script, "#!") {
		if idx := strings.IndexByte(script, '\n'); idx >= 0 {
			script = script[idx+1:]
		} else {
			script = ""
		}
	}
	sf, err := ParseBash(script)
	if err != nil {
		return nil // fail-open: unparseable scripts handled at runtime
	}
	if err := s.validateWithWorkDir(sf, workDir); err != nil {
		return fmt.Errorf("script %s: %w", scriptPath, err)
	}
	if err := validatePaths(sf, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return fmt.Errorf("script %s: %w", scriptPath, err)
	}
	if err := validateRedirectPaths(sf, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return fmt.Errorf("script %s: %w", scriptPath, err)
	}
	return s.validateScriptContents(sf, workDir, readAllowedPaths, writeAllowedPaths, depth+1)
}

// validateBashScriptArg extracts the script file argument from bash/sh args
// (when not using -c) and validates the script contents.
func (s *Sandbox) validateBashScriptArg(args []*syntax.Word, workDir string, readAllowedPaths, writeAllowedPaths []string, depth int) error {
	i := 1
	foundC := false
	for i < len(args) {
		text := wordText(args[i])
		if text == "" {
			i++
			continue
		}
		if text == "-c" {
			foundC = true
			break
		}
		if text == "-o" {
			i += 2
			continue
		}
		// Combined short flags
		if len(text) > 1 && text[0] == '-' && text[1] != '-' {
			for _, ch := range text[1:] {
				if string(ch) == "c" {
					foundC = true
				}
			}
			if foundC {
				break
			}
			i++
			continue
		}
		// Known flags
		if strings.HasPrefix(text, "-") || strings.HasPrefix(text, "+") {
			i++
			continue
		}
		// First non-flag argument is the script file
		if !foundC {
			return s.validateScriptFile(text, workDir, readAllowedPaths, writeAllowedPaths, depth)
		}
		i++
	}
	return nil
}

// validateSourceFileArg extracts the file argument from source/. args
// and validates the file contents recursively.
func (s *Sandbox) validateSourceFileArg(args []*syntax.Word, workDir string, readAllowedPaths, writeAllowedPaths []string, depth int) error {
	if len(args) < 2 {
		return nil
	}
	filePath := wordText(args[1])
	if filePath == "" {
		return nil // dynamic path, can't validate statically
	}
	return s.validateScriptFile(filePath, workDir, readAllowedPaths, writeAllowedPaths, depth)
}

// firstCommandWord extracts the first word from a command string, stopping at
// the first whitespace or shell metacharacter. Returns empty string if the
// command starts with a metacharacter or is empty.
func firstCommandWord(s string) string {
	s = strings.TrimLeft(s, " \t\n")
	for i, ch := range s {
		switch ch {
		case ' ', '\t', '\n', '|', '&', ';', '(', ')', '<', '>', '`', '$', '#', '!':
			return s[:i]
		}
	}
	return s
}

// getBareExtraCommands returns a snapshot of the bare (unrestricted) extra commands.
func (s *Sandbox) getBareExtraCommands() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bareExtraCommands
}

// getBareExtraScriptPaths returns a snapshot of the absolute paths of
// path-like bare extra commands (entries like "./scripts/foo.sh" resolved
// against the sandbox's workDir at config-update time). The ExecHandler uses
// this to recognize the same script invoked from a different cwd, since
// interp's HandlerContext tracks the post-`cd` directory.
func (s *Sandbox) getBareExtraScriptPaths() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bareExtraScriptPaths
}

// isExtraCommandInvocation reports whether the command string should bypass
// bash AST parsing because its leading command is a bare extra_commands entry
// (i.e., added without a subcommand restriction).
func (s *Sandbox) isExtraCommandInvocation(command string) bool {
	word := firstCommandWord(command)
	if word == "" {
		return false
	}
	return s.getBareExtraCommands()[word]
}

// isUnsandboxedInvocation reports whether the command string's leading command
// is a bare unsandboxed_commands entry, meaning it must run directly on the host
// (bypassing the OS sandbox worker). Used by the top-level raw-execution path,
// which only ever handles bare entries.
func (s *Sandbox) isUnsandboxedInvocation(command string) bool {
	word := firstCommandWord(command)
	if word == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unsandboxedBare[word]
}

// execIsUnsandboxed reports whether an exec invocation (from the interpreter's
// ExecHandler) should run on the host instead of the OS sandbox worker because
// it matches an unsandboxed_commands entry. Bare script-path entries are matched
// by absolute path (resolved against the post-`cd` directory tracked in the
// interp HandlerContext) so a script survives a working-directory change.
// Subcommand-restricted entries match only when the invocation's leading
// arguments match the restriction, so e.g. "git push" unsandboxes only pushes
// and not every git command.
func (s *Sandbox) execIsUnsandboxed(ctx context.Context, args []string) bool {
	if len(args) == 0 {
		return false
	}
	cmdName := args[0]
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.unsandboxedBare[cmdName] {
		return true
	}
	if len(s.unsandboxedBareScriptPaths) > 0 && isScriptPath(cmdName) {
		hc := interp.HandlerCtx(ctx)
		if s.unsandboxedBareScriptPaths[absPath(cmdName, hc.Dir)] {
			return true
		}
	}
	if restrictions, ok := s.unsandboxedSub[cmdName]; ok {
		return argsMatchSubCommand(restrictions, args[1:])
	}
	return false
}

// argsMatchSubCommand reports whether the expanded arguments (already stripped
// of the command name) satisfy any recorded subcommand-prefix restriction. It
// mirrors extraSubCommandMatches but operates on plain strings from the
// ExecHandler rather than AST words. An invocation with no non-flag arguments
// matches (typically prints help).
func argsMatchSubCommand(restrictions [][]string, args []string) bool {
	var nonFlag []string
	for _, a := range args {
		if a == "" || strings.HasPrefix(a, "-") {
			continue
		}
		nonFlag = append(nonFlag, a)
	}
	if len(nonFlag) == 0 {
		return true
	}
	for _, seq := range restrictions {
		if len(seq) > len(nonFlag) {
			continue
		}
		match := true
		for i, tok := range seq {
			if nonFlag[i] != tok {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// dispatchExec runs an exec invocation inside the OS sandbox worker or directly
// on the host. Commands go to the worker when the OS sandbox is enabled and the
// command is not an unsandboxed_commands entry. Host execution injects the
// docker filtering proxy's DOCKER_HOST only for non-unsandboxed commands, so
// unsandboxed ones reach the real docker daemon (or the host's own DOCKER_HOST).
func (s *Sandbox) dispatchExec(ctx context.Context, args []string, useOSSandbox bool) error {
	unsandboxed := s.execIsUnsandboxed(ctx, args)
	if useOSSandbox && !unsandboxed {
		return s.execInWorker(ctx, args)
	}
	return s.execOnHost(ctx, args, !unsandboxed)
}

// execOnHost runs a command directly on the host, mirroring
// interp.DefaultExecHandler. When injectDockerProxy is true and a docker
// filtering proxy is configured, DOCKER_HOST is set to the proxy socket so the
// command is routed through it; when false the command inherits whatever
// DOCKER_HOST the interpreter environment already carries (the host's, or none).
func (s *Sandbox) execOnHost(ctx context.Context, args []string, injectDockerProxy bool) error {
	hc := interp.HandlerCtx(ctx)

	var env []string
	hc.Env.Each(func(name string, vr expand.Variable) bool {
		if !vr.IsSet() {
			return true
		}
		env = append(env, name+"="+vr.String())
		return true
	})
	if injectDockerProxy {
		s.mu.RLock()
		proxyHost := s.dockerHost
		s.mu.RUnlock()
		if proxyHost != "" {
			env = append(env, "DOCKER_HOST="+proxyHost)
		}
	}

	path, err := interp.LookPathDir(hc.Dir, hc.Env, args[0])
	if err != nil {
		fmt.Fprintln(hc.Stderr, err)
		return interp.ExitStatus(127)
	}

	cmd := &exec.Cmd{
		Path:   path,
		Args:   args,
		Env:    env,
		Dir:    hc.Dir,
		Stdin:  hc.Stdin,
		Stdout: hc.Stdout,
		Stderr: hc.Stderr,
	}
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(hc.Stderr, "%v\n", err)
		return interp.ExitStatus(127)
	}
	// Cancellation mirrors interp.DefaultExecHandler(gracefulKillTimeout):
	// SIGINT, then SIGKILL after the grace period.
	stopf := context.AfterFunc(ctx, func() {
		if runtime.GOOS == "windows" {
			_ = cmd.Process.Signal(os.Kill)
			return
		}
		_ = cmd.Process.Signal(os.Interrupt)
		time.Sleep(gracefulKillTimeout)
		_ = cmd.Process.Signal(os.Kill)
	})
	defer stopf()

	err = cmd.Wait()
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return interp.ExitStatus(exitErr.ExitCode())
	}
	return err
}

// executeRaw executes a command string directly using the system bash without
// going through AST parsing or validation. Used for bare extra_commands entries.
// When forceHost is true (bare unsandboxed_commands entries) the command runs on
// the host even if the OS sandbox is enabled.
func (s *Sandbox) executeRaw(ctx context.Context, command string, workDir string, forceHost bool) (string, error) {
	var out bytes.Buffer
	if err := s.runRawToWriter(ctx, command, workDir, &out, false, forceHost); err != nil {
		output := out.String()
		return output, &CommandFailedError{Err: err, Output: output}
	}
	return out.String(), nil
}

// runRawToWriter executes a command string directly with the system bash,
// streaming combined stdout/stderr to out. It performs no AST parsing or
// validation and is used both by executeRaw (bare extra_commands) and by
// background execution of those commands.
//
// When newProcessGroup is true the bash process leads its own process group and
// cancellation SIGKILLs the whole group, so children the command forked (a dev
// server, a daemon, `something &`) are reaped too — not just bash itself. This
// is used for background runs; foreground runs keep the default behavior where
// CommandContext kills only the direct process.
//
// When forceHost is true the command always runs on the host even if the OS
// sandbox is enabled — used for bare unsandboxed_commands entries.
func (s *Sandbox) runRawToWriter(ctx context.Context, command string, workDir string, out io.Writer, newProcessGroup, forceHost bool) error {
	s.mu.RLock()
	useOSSandbox := s.osSandbox && !forceHost
	imdsEndpoint := s.imdsEndpoint
	dockerHost := s.dockerHost
	s.mu.RUnlock()

	// The AST bypass skips validation, not confinement: when the OS sandbox is
	// enabled the raw bash still runs inside the worker, so filesystem
	// restrictions apply to extra_commands like any other command. The worker
	// runs each command in its own process group and kills the whole subtree on
	// cancellation, so newProcessGroup is only needed for the host path below.
	if useOSSandbox {
		return s.runRawInWorker(ctx, command, workDir, imdsEndpoint, dockerHost, out)
	}

	env := os.Environ()
	if imdsEndpoint != "" {
		env = append(env, fmt.Sprintf("AWS_EC2_METADATA_SERVICE_ENDPOINT=%s", imdsEndpoint))
	}
	// Skip the docker filtering proxy for unsandboxed commands (forceHost) so
	// they reach the real docker daemon rather than the proxy socket.
	if dockerHost != "" && !forceHost {
		env = append(env, fmt.Sprintf("DOCKER_HOST=%s", dockerHost))
	}

	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Dir = workDir
	cmd.Stdout = out
	cmd.Stderr = out
	cmd.Env = env

	var finished atomic.Bool
	if newProcessGroup {
		setProcessGroup(cmd)
		// Override CommandContext's default Cancel (which kills only bash) so
		// cancellation tears down the whole group. Escalate gracefully: SIGTERM
		// first, then SIGKILL the group after a grace period if it has not
		// exited. The finished guard avoids signaling a recycled pid/group once
		// the command has returned.
		cmd.Cancel = func() error {
			terminateProcessGroup(cmd)
			time.AfterFunc(gracefulKillTimeout, func() {
				if !finished.Load() {
					killProcessGroup(cmd)
				}
			})
			return nil
		}
	}

	// Bound how long Wait blocks on I/O after the context is cancelled. Without
	// this, a backgrounded grandchild (e.g. `npm run dev &`) inherits the stdout
	// pipe's write end and keeps it open after bash exits, so cmd.Run would block
	// until that child exits — pinning the calling MCP worker indefinitely and
	// ignoring the timeout entirely. WaitDelay makes the runtime close the pipes
	// and return once the delay elapses after cancellation. CommandContext has
	// already installed a Cancel func that kills bash on ctx.Done(). It must
	// exceed gracefulKillTimeout so the graceful SIGKILL lands before WaitDelay's
	// force-kill of the direct process.
	cmd.WaitDelay = runnerKillGracePeriod

	err := cmd.Run()
	finished.Store(true)
	return err
}

// runRawInWorker executes a bare extra_commands string with `bash -c` inside
// the OS sandbox worker, streaming combined stdout/stderr to out. No AST
// parsing or validation is performed — trust comes from the user's explicit
// opt-in plus the worker's bwrap/sandbox-exec confinement.
func (s *Sandbox) runRawInWorker(ctx context.Context, command, workDir, imdsEndpoint, dockerHost string, out io.Writer) error {
	w, err := s.getOrCreateWorker()
	if err != nil {
		return fmt.Errorf("failed to get worker: %w", err)
	}

	env := make(map[string]string)
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	if imdsEndpoint != "" {
		env["AWS_EC2_METADATA_SERVICE_ENDPOINT"] = imdsEndpoint
	}
	if dockerHost != "" {
		env["DOCKER_HOST"] = dockerHost
	}

	exitCode, err := w.Exec(ctx, []string{"bash", "-c", command}, workDir, env, nil, out, out)
	if err != nil {
		return fmt.Errorf("worker communication failed: %w", err)
	}
	if exitCode != 0 {
		return interp.ExitStatus(exitCode)
	}
	return nil
}

// Execute parses, validates, and executes a bash command.
// workDir is the working directory for the command and for resolving relative paths.
// readAllowedPaths are absolute directories that read-only commands may access.
// writeAllowedPaths are absolute directories that write commands may access.
// It returns the combined stdout and stderr output.
func (s *Sandbox) Execute(ctx context.Context, command string, workDir string, readAllowedPaths, writeAllowedPaths []string) (string, error) {
	slog.InfoContext(ctx, "executing sandboxed bash", "command", command)

	// Bare extra_commands entries bypass bash AST parsing entirely and are
	// executed directly with the real bash for maximum compatibility. When the
	// OS sandbox is enabled the raw bash runs inside the worker, so filesystem
	// confinement still applies — unless the entry came from unsandboxed_commands,
	// which runs on the host regardless.
	if s.isExtraCommandInvocation(command) {
		return s.executeRaw(ctx, command, workDir, s.isUnsandboxedInvocation(command))
	}

	// Parse and validate
	f, err := ParseBash(command)
	if err != nil {
		return "", err
	}

	if err := s.validateWithWorkDir(f, workDir); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	if err := validatePaths(f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	if err := validateRedirectPaths(f, workDir, readAllowedPaths, writeAllowedPaths); err != nil {
		return "", fmt.Errorf("validation failed: %w", err)
	}

	// Always execute using interp
	// If OS sandbox is enabled, ExecHandler will send commands to worker
	return s.executeWithInterp(ctx, f, workDir, readAllowedPaths, writeAllowedPaths)
}

// syncBuffer is a goroutine-safe bytes.Buffer for capturing interpreter output.
// It is needed because executeWithInterp may return before runner.Run completes
// (when the context is cancelled and the runner is stuck on blocked io.Pipe ops).
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (n int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// runnerKillGracePeriod is the extra time allowed for runner.Run to return
// after the context is already cancelled. mvdan.cc/sh pipelines can have
// internal goroutines blocked on io.Pipe that SIGKILL cannot unblock; this
// grace period bounds how long we wait before giving up and returning a timeout
// error to the caller.
const runnerKillGracePeriod = 5 * time.Second

// runInterpToWriter builds a sandboxed interpreter and runs the parsed command,
// streaming combined stdout/stderr to out. It applies the same security
// handlers as the foreground path and is shared by executeWithInterp and
// background execution. It blocks until the runner returns (which honors ctx
// cancellation for OS-level subprocesses).
func (s *Sandbox) runInterpToWriter(ctx context.Context, f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string, out io.Writer) error {
	s.mu.RLock()
	useOSSandbox := s.osSandbox
	imdsEndpoint := s.imdsEndpoint
	s.mu.RUnlock()

	// Build environment with IMDS endpoint if AWS is enabled. The interpreter
	// hands this env to every spawned subprocess (e.g. aws cli), so there is
	// no need — and no safe way — to mutate the host process's environment.
	// The docker filtering proxy's DOCKER_HOST is intentionally NOT set here:
	// it is injected per command at dispatch time (execInWorker / execOnHost)
	// so unsandboxed_commands can reach the real daemon while everything else is
	// routed through the proxy. The host's own DOCKER_HOST (if any) flows through
	// untouched via os.Environ().
	env := os.Environ()
	if imdsEndpoint != "" {
		env = append(env, fmt.Sprintf("AWS_EC2_METADATA_SERVICE_ENDPOINT=%s", imdsEndpoint))
	}

	// Store sandbox paths in context so nested bash/sh can access them
	ctx = context.WithValue(ctx, sandboxPathsKey, &sandboxPaths{
		readAllowedPaths:  readAllowedPaths,
		writeAllowedPaths: writeAllowedPaths,
	})

	// Build interpreter options
	opts := []interp.RunnerOption{
		interp.Dir(workDir),
		interp.StdIO(nil, out, out),
		interp.Env(expand.ListEnviron(env...)),
	}

	// Add security handlers (CallHandler, OpenHandler, ExecHandler)
	opts = append(opts, s.buildSecurityHandlers(readAllowedPaths, writeAllowedPaths, useOSSandbox)...)

	runner, err := interp.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to create interpreter: %w", err)
	}

	return runner.Run(ctx, f)
}

// executeWithInterp executes the parsed command using interp.
// If OS sandbox is enabled, ExecHandler delegates to the worker.
func (s *Sandbox) executeWithInterp(ctx context.Context, f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) (string, error) {
	var out syncBuffer

	// Run the interpreter in a goroutine so we can enforce a hard deadline.
	// runner.Run(ctx, f) may not return promptly after context cancellation when
	// a pipeline stage fails inside the CallHandler (before becoming an OS process):
	// the adjacent stages' io.Pipe copy goroutines block indefinitely because
	// io.Pipe operations are not context-aware and SIGKILL only kills OS processes.
	type runResult struct{ err error }
	done := make(chan runResult, 1)
	go func() {
		done <- runResult{s.runInterpToWriter(ctx, f, workDir, readAllowedPaths, writeAllowedPaths, &out)}
	}()

	select {
	case r := <-done:
		output := out.String()
		if r.err != nil {
			return output, &CommandFailedError{Err: r.err, Output: output}
		}
		return output, nil
	case <-ctx.Done():
		// Context cancelled (timeout). Give the runner a short grace period to
		// clean up before we abandon it.
		timer := time.NewTimer(runnerKillGracePeriod)
		defer timer.Stop()
		select {
		case r := <-done:
			output := out.String()
			if r.err != nil {
				return output, &CommandFailedError{Err: r.err, Output: output}
			}
			return output, nil
		case <-timer.C:
			// runner.Run is stuck (blocked io.Pipe goroutines). Return the
			// timeout error; the goroutine may leak but is otherwise harmless.
			return out.String(), fmt.Errorf("command timed out: %w", ctx.Err())
		}
	}
}

// execInWorker sends a command to the worker for execution in the OS sandbox.
func (s *Sandbox) execInWorker(ctx context.Context, args []string) error {
	w, err := s.getOrCreateWorker()
	if err != nil {
		return fmt.Errorf("failed to get worker: %w", err)
	}

	hc := interp.HandlerCtx(ctx)

	// Convert environment
	envMap := make(map[string]string)
	hc.Env.Each(func(name string, vr expand.Variable) bool {
		if !vr.IsSet() {
			return true
		}
		envMap[name] = vr.String()
		return true
	})

	// Route docker through the filtering proxy. DOCKER_HOST is injected here
	// rather than into the interpreter's base env so that unsandboxed_commands
	// (which never reach the worker) can talk to the real daemon instead.
	s.mu.RLock()
	proxyHost := s.dockerHost
	s.mu.RUnlock()
	if proxyHost != "" {
		envMap["DOCKER_HOST"] = proxyHost
	}

	exitCode, err := w.Exec(ctx, args, hc.Dir, envMap, hc.Stdin, hc.Stdout, hc.Stderr)
	if err != nil {
		return fmt.Errorf("worker communication failed: %w", err)
	}

	if exitCode != 0 {
		return interp.ExitStatus(exitCode)
	}

	return nil
}

// getOrCreateWorker returns the current worker, starting a new one if the worker
// is nil or dead. Must be called without holding s.mu.
func (s *Sandbox) getOrCreateWorker() (*os_sandbox.Worker, error) {
	s.mu.Lock()
	if s.worker != nil && !s.worker.IsDead() {
		w := s.worker
		s.mu.Unlock()
		return w, nil
	}
	s.mu.Unlock()

	// Resolve the worker's writable extra binds outside the lock; runtime
	// detection may run lazily here. The worker is writable in the working
	// directory by default; every other directory a command may legitimately
	// write to must be added here or the OS sandbox denies the write (EPERM)
	// even though the Go validator permitted it.
	extraBinds := s.RuntimeReadPaths()

	// User-configured writable_paths are enforced by the Go validator via
	// Execute(..., writeAllowedPaths), but that only gates the interpreter — the
	// OS sandbox worker has its own profile. Without adding them here, a write
	// the validator allows is still denied by bwrap/seatbelt with EPERM.
	extraBinds = append(extraBinds, s.ConfigWritePaths()...)

	// Same for the main worktree when the session runs in a linked git worktree
	// with git.allow_worktree_parent: git writes index/lock files under the main
	// repo's .git/worktrees/<name>/, which is outside the worker's workDir.
	s.mu.RLock()
	workerWorkDir := s.workerWorkDir
	s.mu.RUnlock()
	if parent := s.WorktreeParentPath(workerWorkDir); parent != "" {
		extraBinds = append(extraBinds, parent)
	}

	// Bind the docker proxy socket dir into the worker so sandboxed commands
	// can reach the proxy via DOCKER_HOST, and mask the real daemon socket(s)
	// so the proxy cannot be bypassed.
	s.mu.RLock()
	dockerSocketDir := s.dockerSocketDir
	var dockerMaskPaths []string
	if dockerSocketDir != "" {
		dockerMaskPaths = append([]string(nil), s.dockerMaskPaths...)
	}
	s.mu.RUnlock()
	if dockerSocketDir != "" {
		extraBinds = append(extraBinds, dockerSocketDir)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.worker != nil && !s.worker.IsDead() {
		return s.worker, nil
	}

	slog.Info("starting new sandbox worker", "workDir", s.workerWorkDir, "blockAWS", s.workerBlockAWS)
	w, err := os_sandbox.StartWorker(context.Background(), s.workerWorkDir, extraBinds, s.workerBlockAWS, dockerMaskPaths)
	if err != nil {
		return nil, fmt.Errorf("failed to start worker: %w", err)
	}
	s.worker = w
	return w, nil
}
