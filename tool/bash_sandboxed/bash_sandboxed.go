package bash_sandboxed

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"

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
	mu               sync.RWMutex
	cfg              *config.Config
	extraCommands    map[string]bool
	// extraSubCommands holds per-command first-arg restrictions parsed from
	// extra_commands entries that contain a space (e.g. "pnpx prettier").
	// A nil slice means no restriction (bare command entry); a non-nil slice
	// means only those first args are allowed.
	extraSubCommands map[string][]string
	// bareExtraCommands tracks commands that have a bare entry in extra_commands
	// (i.e., the entry has no subcommand restriction). These commands bypass
	// bash AST parsing and are executed directly with the real bash.
	bareExtraCommands map[string]bool
	imdsEndpoint     string
	runtimeReadPaths []string
	osSandbox        bool
	worker           *os_sandbox.Worker
	workerWorkDir    string
	workerRuntimeBinds []string
	workerBlockAWS   bool
	// argValidators holds a reference to commandArgValidators so that
	// validateSubCommand can look up per-command validators at runtime
	// without creating a package-level initialization cycle.
	argValidators map[string]func(s *Sandbox, args []*syntax.Word) error
}

// NewSandbox creates a Sandbox with no extra commands.
func NewSandbox() *Sandbox {
	return &Sandbox{
		cfg:           &config.Config{},
		argValidators: commandArgValidators,
	}
}

// UpdateConfig replaces the sandbox configuration with the provided config.
func (s *Sandbox) UpdateConfig(cfg *config.Config, workDir string) {
	m := make(map[string]bool, len(cfg.ExtraCommands))
	sub := make(map[string][]string)
	bare := make(map[string]bool)
	for _, c := range cfg.ExtraCommands {
		// Entries may be "command" or "command subcommand" (space-separated).
		// The latter restricts the command to only that first argument.
		if idx := strings.IndexByte(c, ' '); idx > 0 {
			cmd, firstArg := c[:idx], c[idx+1:]
			m[cmd] = true
			sub[cmd] = append(sub[cmd], firstArg)
		} else {
			m[c] = true
			bare[c] = true
		}
	}
	// Detect runtime paths for read-only access (e.g., GOPATH, GOCACHE, pnpm store)
	runtimeReadPaths := detectRuntimeBinds(cfg.Runtimes)

	// Determine if AWS credentials should be blocked
	blockAWSCredentials := shouldBlockAWSCredentials(cfg.AWS)

	s.mu.Lock()
	s.cfg = cfg
	s.extraCommands = m
	s.extraSubCommands = sub
	s.bareExtraCommands = bare
	s.runtimeReadPaths = runtimeReadPaths

	// Store worker config for lazy start / restart.
	s.workerWorkDir = workDir
	s.workerRuntimeBinds = runtimeReadPaths
	s.workerBlockAWS = blockAWSCredentials

	// Handle OS sandbox enable/disable
	newOSSandbox := cfg.OSSandboxEnabled()
	if newOSSandbox != s.osSandbox {
		// OS sandbox setting changed
		if s.worker != nil {
			slog.Info("closing existing worker")
			s.worker.Close()
			s.worker = nil
		}
		if newOSSandbox {
			slog.Info("enabling OS sandbox", "block_aws_credentials", blockAWSCredentials)
		}
		s.osSandbox = newOSSandbox
	}
	s.mu.Unlock()
}

// shouldBlockAWSCredentials determines if ~/.aws/ should be blocked.
// Returns true if AWS is configured to use IMDS (force_profile set).
// Returns false if AWS allows raw credentials or is not configured.
// Note: ~/.ssh/ is ALWAYS blocked regardless of this setting.
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

// getExtraCommands returns a snapshot of the current extra commands.
func (s *Sandbox) getExtraCommands() map[string]bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.extraCommands
}

// getExtraSubCommands returns the per-command first-arg restriction map.
// A nil slice for a command means no restriction (any first arg allowed).
// A non-nil slice means only those first args are permitted.
func (s *Sandbox) getExtraSubCommands() map[string][]string {
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

// RuntimeReadPaths returns the detected runtime paths that should be
// readable (but not writable) by sandboxed commands. These include paths
// like GOPATH, GOCACHE, and pnpm store directories.
func (s *Sandbox) RuntimeReadPaths() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.runtimeReadPaths
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

// Close shuts down the sandbox, closing the worker if running.
func (s *Sandbox) Close() error {
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

	// Detect Go paths if Go runtime is enabled
	if runtimes.Go != nil && runtimes.Go.GoEnabled() {
		goBinds := detectGoBinds()
		binds = append(binds, goBinds...)
	}

	// Detect pnpm paths if pnpm runtime is enabled
	if runtimes.Pnpm != nil && runtimes.Pnpm.PnpmEnabled() {
		pnpmBinds := detectPnpmBinds()
		binds = append(binds, pnpmBinds...)
	}

	// Detect Rust paths if Rust runtime is enabled
	if runtimes.Rust != nil && runtimes.Rust.RustEnabled() {
		rustBinds := detectRustBinds()
		binds = append(binds, rustBinds...)
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
				// If extra_commands has subcommand restrictions (e.g. "pnpx prettier"),
				// the command only matches when the first non-flag argument matches.
				inExtra := extra[cmdName] && extraSubCommandMatches(extraSub, cmdName, n.Args)
				if !allowedCommands[cmdName] && !inExtra && !declaredFuncs[cmdName] {
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
//   - If extraSub has an entry, the first non-flag argument in args must appear
//     in the allowed list.
func extraSubCommandMatches(extraSub map[string][]string, cmdName string, args []*syntax.Word) bool {
	allowed, hasRestriction := extraSub[cmdName]
	if !hasRestriction {
		return true // bare "cmd" entry, no subcommand restriction
	}
	// Find first non-flag argument (the subcommand / package name).
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" || strings.HasPrefix(lit, "-") {
			continue
		}
		for _, a := range allowed {
			if a == lit {
				return true
			}
		}
		return false // first non-flag arg not in allowed list
	}
	return true // no subcommand argument — safe (prints help)
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
// cases where a script file contains blocked commands that would fail at
// runtime, allowing the preflight hook to let Bash handle the command directly.
// Errors reading files are silently ignored (fail-open) since the file may
// not exist yet at preflight time.
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
	if isBinaryExecutable(path) {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil // fail-open: file may not exist at preflight time
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

// executeRaw executes a command string directly using the system bash without
// going through AST parsing or validation. Used for bare extra_commands entries.
func (s *Sandbox) executeRaw(ctx context.Context, command string, workDir string) (string, error) {
	s.mu.RLock()
	imdsEndpoint := s.imdsEndpoint
	s.mu.RUnlock()

	env := os.Environ()
	if imdsEndpoint != "" {
		env = append(env, fmt.Sprintf("AWS_EC2_METADATA_SERVICE_ENDPOINT=%s", imdsEndpoint))
	}

	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "bash", "-c", command)
	cmd.Dir = workDir
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.Env = env

	if err := cmd.Run(); err != nil {
		output := out.String()
		return output, &CommandFailedError{Err: err, Output: output}
	}
	return out.String(), nil
}

// Execute parses, validates, and executes a bash command.
// workDir is the working directory for the command and for resolving relative paths.
// readAllowedPaths are absolute directories that read-only commands may access.
// writeAllowedPaths are absolute directories that write commands may access.
// It returns the combined stdout and stderr output.
func (s *Sandbox) Execute(ctx context.Context, command string, workDir string, readAllowedPaths, writeAllowedPaths []string) (string, error) {
	slog.InfoContext(ctx, "executing sandboxed bash", "command", command)

	// Bare extra_commands entries bypass bash AST parsing entirely and are
	// executed directly with the real bash for maximum compatibility.
	if s.isExtraCommandInvocation(command) {
		return s.executeRaw(ctx, command, workDir)
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

// executeWithInterp executes the parsed command using interp.
// If OS sandbox is enabled, ExecHandler delegates to the worker.
func (s *Sandbox) executeWithInterp(ctx context.Context, f *syntax.File, workDir string, readAllowedPaths, writeAllowedPaths []string) (string, error) {
	s.mu.RLock()
	useOSSandbox := s.osSandbox
	imdsEndpoint := s.imdsEndpoint
	s.mu.RUnlock()

	var out bytes.Buffer

	// Build environment with IMDS endpoint if AWS is enabled
	// IMPORTANT: Set as actual environment variable so subprocesses (like aws cli) can see it
	env := os.Environ()
	if imdsEndpoint != "" {
		envVar := fmt.Sprintf("AWS_EC2_METADATA_SERVICE_ENDPOINT=%s", imdsEndpoint)
		env = append(env, envVar)
		// Also set in actual process environment so it's visible in shell sessions
		os.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imdsEndpoint)
	}

	// Store sandbox paths in context so nested bash/sh can access them
	ctx = context.WithValue(ctx, sandboxPathsKey, &sandboxPaths{
		readAllowedPaths:  readAllowedPaths,
		writeAllowedPaths: writeAllowedPaths,
	})

	// Build interpreter options
	opts := []interp.RunnerOption{
		interp.Dir(workDir),
		interp.StdIO(nil, &out, &out),
		interp.Env(expand.ListEnviron(env...)),
	}

	// Add security handlers (CallHandler, OpenHandler, ExecHandler)
	opts = append(opts, s.buildSecurityHandlers(readAllowedPaths, writeAllowedPaths, useOSSandbox)...)

	runner, err := interp.New(opts...)
	if err != nil {
		return "", fmt.Errorf("failed to create interpreter: %w", err)
	}

	err = runner.Run(ctx, f)
	output := out.String()
	if err != nil {
		return output, &CommandFailedError{Err: err, Output: output}
	}
	return output, nil
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
	defer s.mu.Unlock()

	if s.worker != nil && !s.worker.IsDead() {
		return s.worker, nil
	}

	slog.Info("starting new sandbox worker", "workDir", s.workerWorkDir, "blockAWS", s.workerBlockAWS)
	w, err := os_sandbox.StartWorker(context.Background(), s.workerWorkDir, s.workerRuntimeBinds, s.workerBlockAWS)
	if err != nil {
		return nil, fmt.Errorf("failed to start worker: %w", err)
	}
	s.worker = w
	return w, nil
}
