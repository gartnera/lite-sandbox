package bash_sandboxed

import (
	"fmt"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// allowedCommands is the whitelist of commands that are permitted to execute.
// Only non-destructive, non-code-execution commands are included.
// Excluded categories:
//   - Code execution: python, node, ruby, perl, go, java, gcc, etc. (trivial sandbox bypass)
//   - Networking: curl, wget, ping, nmap, etc. (data exfiltration / remote code fetch)
//   - Archive write: gzip, etc. (arbitrary file writes to sensitive locations)
//   - tar, unzip, ar are allowed with arg validators restricting to read-only operations
//   - Shell escape: eval, exec, source (bypass command whitelist)
//   - xargs, env, timeout are allowed with arg validators that recursively validate the wrapped command
//   - Version control: gh (can execute hooks, fetch remote code)
//   - git is allowed with arg validator restricting to read-only subcommands
//   - Package managers: npm, pip, cargo, etc. (arbitrary code execution via install scripts)
//
// When in doubt, commands are excluded.
var allowedCommands = map[string]bool{
	// Output / display (pure readers, no write capability)
	"echo":     true,
	"printf":   true,
	"cat":      true,
	"head":     true,
	"tail":     true,
	"less":     true,
	"more":     true,
	"wc":       true,
	"column":   true,
	"fold":     true,
	"paste":    true,
	"rev":      true,
	"tac":      true,
	"nl":       true,
	"pr":       true,
	"expand":   true,
	"unexpand": true,
	"col":      true,
	"colrm":    true,
	"vis":      true,
	"unvis":    true,
	"fmt":      true,

	// Search / find (read-only)
	"grep":    true,
	"egrep":   true,
	"fgrep":   true,
	"rg":      true,
	"find":    true,
	"locate":  true,
	"which":   true,
	"whereis": true,
	"type":    true,
	"look":    true,

	// Navigation / directory management
	"cd":    true,
	"mkdir": true,

	// File info (read-only, no modification capability)
	"ls":        true,
	"stat":      true,
	"file":      true,
	"du":        true,
	"df":        true,
	"readlink":  true,
	"realpath":  true,
	"basename":  true,
	"dirname":   true,
	"pathchk":   true,
	"pwd":       true,
	"sha256sum": true,
	"sha1sum":   true,
	"md5sum":    true,
	"shasum":    true,
	"cksum":     true,
	"b2sum":     true,

	// Text processing (stdin/stdout only, no file write capability)
	"sort":    true,
	"uniq":    true,
	"cut":     true,
	"tr":      true,
	"diff":    true,
	"comm":    true,
	"join":    true,
	"tsort":   true,
	"strings": true,
	"od":      true,
	"hexdump": true,
	"xxd":     true,
	"iconv":   true,

	// JSON/structured data and text processing (stdin/stdout processors)
	"jq": true,
	"yq": true,
	// awk is executed via goawk with system() and file-writes disabled.
	"awk":    true,
	"base64": true,

	// Shell sourcing (file validated via OpenHandler + arg validators)
	"source": true,
	".":      true,

	// Shell builtins (non-destructive, no escape capability)
	"test":     true,
	"[":        true,
	":":        true,
	"true":     true,
	"false":    true,
	"read":     true,
	"set":      true,
	"unset":    true,
	"export":   true,
	"local":    true,
	"declare":  true,
	"typeset":  true,
	"readonly": true,
	"shift":    true,
	"getopts":  true,
	"let":      true,
	"expr":     true,

	// Process / system info (read-only)
	"ps":       true,
	"uptime":   true,
	"uname":    true,
	"hostname": true,
	"whoami":   true,
	"id":       true,
	"groups":   true,
	"env":      true, // arg validator recursively validates the wrapped command
	"printenv": true,
	"date":     true,
	"cal":      true,
	// cygpath translates path strings between Windows and POSIX formats. It is
	// Cygwin/MSYS-only and does not exist on macOS or Linux, so it is inert
	// here. It is allowlisted because npm/pnpm cmd-shim launchers
	// (node_modules/.bin/*) all include a `case *CYGWIN*|*MINGW*|*MSYS*) ...
	// cygpath ...` branch that is dead code off Windows; without this the static
	// validator rejects every such launcher. Its path argument is still
	// path-validated like any other command.
	"cygpath": true,

	// Math / calculation (pure computation)
	"bc":      true,
	"dc":      true,
	"seq":     true,
	"factor":  true,
	"numfmt":  true,
	"uuidgen": true,

	// Compressed file readers (read-only, no extraction)
	"zcat":  true,
	"zless": true,
	"zgrep": true,
	"bzcat": true,
	"xzcat": true,

	// Archive inspection (read-only, with arg validators for tar/unzip/ar)
	"tar":     true,
	"unzip":   true,
	"zipinfo": true,
	"ar":      true,

	// Version control (read-only, with arg validator for git)
	"git": true,

	// Nested shell (intercepted in ExecHandler, executed via sandbox interpreter)
	"bash": true,
	"sh":   true,

	// Runtimes (config-gated, validated by commandArgValidators)
	"go":      true,
	"gofmt":   true,
	"pnpm":    true,
	"cargo":   true,
	"rustc":   true,
	"deno":    true,
	"flutter": true,
	"dart":    true,
	"fvm":     true,
	"uv":      true,
	"uvx":     true,

	// Python, served by the embedded monty interpreter rather than any python
	// on PATH (dispatched in ExecHandler, see python.go). Unlike the runtimes
	// above this one is on by default; runtimes.montypython.enabled turns it off.
	"python":  true,
	"python3": true,

	// Cloud CLI tools (config-gated, credentials via IMDS)
	"aws": true,

	// Container tooling (config-gated, daemon access via filtering proxy)
	"docker": true,

	// Scoped write commands (path-validated to stay within allowedPaths)
	"cp":    true,
	"mv":    true,
	"rm":    true,
	"touch": true,
	"chmod": true,
	"ln":    true,
	"sed":   true,
	"tee":   true,

	// Control flow / job control
	"sleep":    true,
	"wait":     true,
	"trap":     true,
	"return":   true,
	"exit":     true,
	"break":    true,
	"continue": true,
	"timeout":  true, // arg validator recursively validates the wrapped command
	"time":     true,
	"yes":      true,

	// Safe introspection
	"command": true,
	"builtin": true,
	"hash":    true,
	"help":    true,
	"man":     true,
	"info":    true,
	"apropos": true,

	// Pipe utilities (allowed with arg validator for recursive whitelist enforcement)
	"xargs": true,
}

// osSandboxOnlyCommands are process-control commands that are permitted ONLY
// when the OS sandbox is enabled. On the bare host they are unsafe because they
// can signal arbitrary processes, but inside the OS sandbox they are contained:
// on Linux the worker runs in its own PID namespace (so only sandbox-spawned
// processes are visible/signalable), and on macOS the seatbelt profile denies
// signaling any process outside the worker's process group. This lets an agent
// start a background server and then stop it (e.g. `srv & ...; pkill -f srv`)
// without being able to reach host processes.
//
// Note: since mvdan.cc/sh v3.13 the interpreter claims kill as a builtin but
// does not implement it, so `kill` fails with "unsupported builtin" and never
// reaches the worker; pkill is the working form.
var osSandboxOnlyCommands = map[string]bool{
	"kill":  true,
	"pkill": true,
}

// writeCommands is the set of commands that perform write operations.
// Path arguments to these commands are validated against writeAllowedPaths
// rather than readAllowedPaths. This matches the "Scoped write commands"
// category in allowedCommands, plus mkdir.
var writeCommands = map[string]bool{
	"cp":    true,
	"mv":    true,
	"rm":    true,
	"touch": true,
	"chmod": true,
	"ln":    true,
	"sed":   true,
	"tee":   true,
	"mkdir": true,
}

// commandArgValidators is a registry of per-command argument validation functions.
// Commands with dangerous flags (e.g., find -exec, find -delete) register a
// validator here to block those flags while still allowing the command itself.
// Validators receive the *Sandbox so they can access config (e.g., runtimes, git).
var commandArgValidators = map[string]func(s *Sandbox, args []*syntax.Word) error{
	"awk":    validateAwkArgs,
	"bash":   validateBashArgs,
	"sh":     validateBashArgs,
	"source": validateSourceArgs,
	".":      validateSourceArgs,
	"rg":     validateRgArgs,
	"find":   validateFindArgs,
	"tar":    validateTarArgs,
	"unzip":  validateUnzipArgs,
	"ar":     validateArArgs,
	"rm":     validateRmArgs,
	"sed":    validateSedArgs,
	"git":    validateGitCommand,
	"go":     runtimeGate("go", "runtimes.go.enabled", goRuntimeEnabled, validateGoRuntimeArgs),
	// gofmt is the standalone formatter binary, gated behind the Go runtime.
	// It is a pure source formatter with no code-execution path, so beyond the
	// runtime check there are no arguments to validate; its only side effect
	// (-w writing files in place) is confined by the OS sandbox like go fmt.
	"gofmt": runtimeGate("gofmt", "runtimes.go.enabled", goRuntimeEnabled, nil),
	"pnpm":  runtimeGate("pnpm", "runtimes.pnpm.enabled", pnpmRuntimeEnabled, validatePnpmRuntimeArgs),
	"cargo": runtimeGate("cargo", "runtimes.rust.enabled", rustRuntimeEnabled, validateCargoRuntimeArgs),
	"rustc": runtimeGate("rustc", "runtimes.rust.enabled", rustRuntimeEnabled, nil),
	"deno":  runtimeGate("deno", "runtimes.deno.enabled", denoRuntimeEnabled, validateDenoRuntimeArgs),
	// flutter/dart/fvm are code-execution runtimes (like go/cargo/deno): their
	// containment relies on the OS sandbox rather than argument validation, so
	// once the runtime is enabled all subcommands are permitted. dart ships
	// with the Flutter SDK and fvm proxies both against a cached SDK version,
	// so one switch covers all three; the paths they read and write (SDK cache,
	// pub cache, config dirs) are made accessible via detectFlutterBinds.
	"flutter": runtimeGate("flutter", "runtimes.flutter.enabled", flutterRuntimeEnabled, nil),
	"dart":    runtimeGate("dart", "runtimes.flutter.enabled", flutterRuntimeEnabled, nil),
	"fvm":     runtimeGate("fvm", "runtimes.flutter.enabled", flutterRuntimeEnabled, nil),
	"uv":      runtimeGate("uv", "runtimes.uv.enabled", uvRuntimeEnabled, validateUvRuntimeArgs),
	// uvx is an alias of `uv tool run`: it takes a tool name rather than a uv
	// subcommand, so beyond the runtime check there is nothing to gate —
	// running the tool is confined by the OS sandbox like `uv run`.
	"uvx":     runtimeGate("uvx", "runtimes.uv.enabled", uvRuntimeEnabled, nil),
	"python":  validatePythonArgs,
	"python3": validatePythonArgs,
	"aws":     validateAWSCommand,
	"docker":  validateDockerCommand,
	"xargs":   validateXargsArgs,
	"env":     validateEnvArgs,
	"timeout": validateTimeoutArgs,
}

// runtimeGateInfo describes a config-gated runtime command: which config
// switch enables it and how to read that switch. Sites consult runtimeGates
// (via Sandbox.runtimeDisabledError) before running the command's validator, so
// the enable check is mode-aware: enforced in allowlist mode, advisory (audited,
// then ignored) in denylist and open mode.
type runtimeGateInfo struct {
	configKey string
	enabled   func(*config.RuntimesConfig) bool
}

// runtimeGates is populated by runtimeGate as commandArgValidators is built.
var runtimeGates = map[string]runtimeGateInfo{}

// runtimeGate registers name as a config-gated runtime command and returns the
// validator that runs the runtime's own argument checks. The enable switch
// itself is NOT checked here — callers do that first through
// runtimeDisabledError, so it can be gated on the mode and audited — which is
// also why validate must tolerate a nil runtime section: in denylist mode the
// runtime may run without ever having been configured.
//
// name is the command as it appears in error messages and configKey the config
// field the user must set. validate may be nil when there is nothing further to
// check. Every per-runtime accessor (GoGenerate, PnpmPublish, ...) is nil-safe
// on its section, so validate runs safely against an unconfigured runtime.
func runtimeGate(
	name, configKey string,
	enabled func(*config.RuntimesConfig) bool,
	validate func(*config.RuntimesConfig, []*syntax.Word) error,
) func(*Sandbox, []*syntax.Word) error {
	runtimeGates[name] = runtimeGateInfo{configKey: configKey, enabled: enabled}
	return func(s *Sandbox, args []*syntax.Word) error {
		if validate == nil {
			return nil
		}
		rt := s.getConfig().Runtimes
		if rt == nil {
			rt = &config.RuntimesConfig{}
		}
		return validate(rt, args)
	}
}

// runtimeDisabledError returns the tagged runtime-disabled error when name is a
// config-gated runtime command whose runtime is not enabled, and nil otherwise
// (not gated, or enabled). Callers pass it through Sandbox.report so it is
// enforced only in allowlist mode.
func (s *Sandbox) runtimeDisabledError(name string) error {
	info, ok := runtimeGates[name]
	if !ok {
		return nil
	}
	cfg := s.getConfig()
	if cfg.Runtimes != nil && info.enabled(cfg.Runtimes) {
		return nil
	}
	// runtimes.<x>.enabled -> `lite-sandbox config runtimes <x> enable`
	fix, hint := "", ""
	if k, ok := strings.CutPrefix(info.configKey, "runtimes."); ok {
		if rt, ok := strings.CutSuffix(k, ".enabled"); ok {
			fix = fmt.Sprintf("lite-sandbox config runtimes %s enable", rt)
			hint = fmt.Sprintf("; the user can enable it with `%s`", fix)
		}
	}
	return tagRuleFix(ruleRuntimeDisabled, name, fix, fmt.Errorf("command %q is not allowed (%s is disabled)%s", name, info.configKey, hint))
}

// Runtime enable accessors and argument-validation adapters used by runtimeGate.
// Each accessor is nil-safe on its runtime section (see runtimeGate).

func goRuntimeEnabled(r *config.RuntimesConfig) bool      { return r.Go.GoEnabled() }
func pnpmRuntimeEnabled(r *config.RuntimesConfig) bool    { return r.Pnpm.PnpmEnabled() }
func rustRuntimeEnabled(r *config.RuntimesConfig) bool    { return r.Rust.RustEnabled() }
func denoRuntimeEnabled(r *config.RuntimesConfig) bool    { return r.Deno.DenoEnabled() }
func flutterRuntimeEnabled(r *config.RuntimesConfig) bool { return r.Flutter.FlutterEnabled() }
func uvRuntimeEnabled(r *config.RuntimesConfig) bool      { return r.Uv.UvEnabled() }

func validateGoRuntimeArgs(r *config.RuntimesConfig, args []*syntax.Word) error {
	return validateGoArgs(args, r.Go)
}

func validatePnpmRuntimeArgs(r *config.RuntimesConfig, args []*syntax.Word) error {
	return validatePnpmArgs(args, r.Pnpm)
}

func validateCargoRuntimeArgs(r *config.RuntimesConfig, args []*syntax.Word) error {
	return validateCargoArgs(args, r.Rust)
}

func validateDenoRuntimeArgs(r *config.RuntimesConfig, args []*syntax.Word) error {
	return validateDenoArgs(args, r.Deno)
}

func validateUvRuntimeArgs(r *config.RuntimesConfig, args []*syntax.Word) error {
	return validateUvArgs(args, r.Uv)
}

func validateGitCommand(s *Sandbox, args []*syntax.Word) error {
	return validateGitArgs(args, s.getConfig().Git)
}

func validateAWSCommand(s *Sandbox, args []*syntax.Word) error {
	// s.cfg was already resolved for the working directory by the caller of
	// UpdateConfig, so any per-directory override applies to command validation
	// the same way it applies to the IMDS server and credential blocking.
	awsCfg := s.getConfig().AWS
	if awsCfg == nil || !awsCfg.AWSEnabled() {
		return fmt.Errorf("command \"aws\" is not allowed (aws.enabled is disabled)")
	}
	// AWS CLI credentials will come from IMDS endpoint, not files
	// No additional argument validation needed - all aws subcommands allowed
	return nil
}

func validateDockerCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig()
	if cfg.Docker == nil || !cfg.Docker.DockerEnabled() {
		return fmt.Errorf("command \"docker\" is not allowed (docker.enabled is disabled)")
	}
	// Require the OS sandbox: only it can mask the real daemon socket so the
	// proxy is unbypassable. Without it a command can just `unset DOCKER_HOST`
	// (or pass -H) and talk to /var/run/docker.sock directly. allow_unsandboxed
	// opts into that weaker, bypassable boundary explicitly.
	if !s.osSandboxEnabled() && !cfg.Docker.AllowsUnsandboxed() {
		return fmt.Errorf("command \"docker\" is not allowed without the OS sandbox (enable os_sandbox, or set docker.allow_unsandboxed to accept a bypassable boundary)")
	}
	// Fail closed: only allow docker when the filtering proxy is actually wired
	// in (DOCKER_HOST will be injected). Without this, a command run before the
	// proxy is started — e.g. docker enabled via a live config reload, which
	// does not start the proxy — would fall back to the real /var/run/docker.sock
	// and bypass the privileged/bind-mount policy entirely.
	if !s.DockerHostConfigured() {
		return fmt.Errorf("command \"docker\" is not allowed (docker proxy is not running; restart required after enabling docker)")
	}
	// The docker CLI talks to the filtering proxy via DOCKER_HOST; the proxy
	// enforces the privileged and bind-mount policy on the wire, so no
	// argument-level validation is needed here.
	return nil
}
