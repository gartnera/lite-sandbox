package bash_sandboxed

import (
	"fmt"

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

	// Archive inspection, extraction, and zip creation (arg validators for
	// tar/unzip/zip/ar; what tar/unzip extract into and the archive zip writes
	// are write-checked, see validators_archive.go)
	"tar":     true,
	"unzip":   true,
	"zip":     true,
	"zipinfo": true,
	"ar":      true,

	// Version control (read-only, with arg validator for git)
	"git": true,

	// Nested shell (intercepted in ExecHandler, executed via sandbox interpreter)
	"bash": true,
	"sh":   true,

	// The toolchains (go, cargo, uv, ...) and python are not listed here: each
	// comes from a profile (config/profiles.go), which adds its commands to
	// the whitelist through the config's commands list when it is enabled.
	// Their validators are the profile's hooks, in profiles.go.

	// Cloud CLI tools (config-gated, credentials via IMDS)
	"aws": true,

	// Container tooling (config-gated, daemon access via filtering proxy)
	"docker": true,

	// Temp file/dir creation. mktemp writes to $TMPDIR (/tmp) by default; those
	// writes are contained by the OS sandbox's private /tmp when it is enabled.
	// With the OS sandbox off, temp files land in the host /tmp. Template/-p
	// arguments that name a path are still path-validated like any other command.
	"mktemp": true,

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
// Validators receive the *Sandbox so they can access config (e.g., profile options, git).
var commandArgValidators = map[string]func(s *Sandbox, args []*syntax.Word) error{
	"awk":     validateAwkArgs,
	"bash":    validateBashArgs,
	"sh":      validateBashArgs,
	"source":  validateSourceArgs,
	".":       validateSourceArgs,
	"rg":      validateRgArgs,
	"find":    validateFindArgs,
	"tar":     validateTarArgs,
	"unzip":   validateUnzipArgs,
	"zip":     validateZipArgs,
	"ar":      validateArArgs,
	"rm":      validateRmArgs,
	"sed":     validateSedArgs,
	"git":     validateGitCommand,
	"aws":     validateAWSCommand,
	"docker":  validateDockerCommand,
	"xargs":   validateXargsArgs,
	"env":     validateEnvArgs,
	"timeout": validateTimeoutArgs,
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
