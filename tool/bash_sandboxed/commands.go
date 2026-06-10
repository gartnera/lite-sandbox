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
//   - xargs is allowed with an arg validator that recursively validates the embedded command
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
	"jq":  true,
	"yq":  true,
	// awk is executed via goawk with system() and file-writes disabled.
	"awk":    true,
	"base64": true,

	// Shell sourcing (file validated via OpenHandler + arg validators)
	"source": true,
	".":      true,

	// Shell builtins (non-destructive, no escape capability)
	"test":     true,
	"[":        true,
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
	"env":      true,
	"printenv": true,
	"date":     true,
	"cal":      true,

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
	"go":    true,
	"gofmt": true,
	"pnpm":  true,
	"cargo": true,
	"rustc": true,

	// Cloud CLI tools (config-gated, credentials via IMDS)
	"aws": true,

	// Token-reducing command proxy (config-gated; proxied command validated recursively)
	"rtk": true,

	// Scoped write commands (path-validated to stay within allowedPaths)
	"cp":    true,
	"mv":    true,
	"rm":    true,
	"touch": true,
	"chmod": true,
	"ln":    true,
	"sed":   true,

	// Control flow / job control
	"sleep":    true,
	"wait":     true,
	"trap":     true,
	"return":   true,
	"exit":     true,
	"break":    true,
	"continue": true,
	"timeout":  true,
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
	"mkdir": true,
}

// commandArgValidators is a registry of per-command argument validation functions.
// Commands with dangerous flags (e.g., find -exec, find -delete) register a
// validator here to block those flags while still allowing the command itself.
// Validators receive the *Sandbox so they can access config (e.g., runtimes, git).
var commandArgValidators = map[string]func(s *Sandbox, args []*syntax.Word) error{
	"awk":    validateAwkArgs,
	"bash":   validateBashCommand,
	"sh":     validateBashCommand,
	"source": validateSourceCommand,
	".":      validateSourceCommand,
	"rg":    validateRgArgs,
	"find":  validateFindArgs,
	"tar":   validateTarArgs,
	"unzip": validateUnzipArgs,
	"ar":    validateArArgs,
	"rm":    validateRmArgs,
	"sed":   validateSedArgs,
	"git":   validateGitCommand,
	"go":    validateGoCommand,
	"gofmt": validateGofmtCommand,
	"pnpm":  validatePnpmCommand,
	"cargo": validateCargoCommand,
	"rustc": validateRustcCommand,
	"aws":   validateAWSCommand,
	"rtk":   validateRtkCommand,
	"xargs": validateXargsArgs,
}

func validateGitCommand(s *Sandbox, args []*syntax.Word) error {
	return validateGitArgs(args, s.getConfig().Git)
}

func validateGoCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig()
	if cfg.Runtimes == nil || cfg.Runtimes.Go == nil || !cfg.Runtimes.Go.GoEnabled() {
		return fmt.Errorf("command \"go\" is not allowed (runtimes.go.enabled is disabled)")
	}
	return validateGoArgs(args, cfg.Runtimes.Go)
}

// validateGofmtCommand gates the standalone gofmt binary behind the Go runtime.
// gofmt is a pure source formatter with no code-execution path, so beyond the
// runtime check there are no arguments to validate; its only side effect (-w
// writing files in place) is confined by the OS sandbox like go fmt itself.
func validateGofmtCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig()
	if cfg.Runtimes == nil || cfg.Runtimes.Go == nil || !cfg.Runtimes.Go.GoEnabled() {
		return fmt.Errorf("command \"gofmt\" is not allowed (runtimes.go.enabled is disabled)")
	}
	return nil
}

func validatePnpmCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig()
	if cfg.Runtimes == nil || cfg.Runtimes.Pnpm == nil || !cfg.Runtimes.Pnpm.PnpmEnabled() {
		return fmt.Errorf("command \"pnpm\" is not allowed (runtimes.pnpm.enabled is disabled)")
	}
	return validatePnpmArgs(args, cfg.Runtimes.Pnpm)
}

func validateBashCommand(s *Sandbox, args []*syntax.Word) error {
	return validateBashArgs(s, args)
}

func validateSourceCommand(s *Sandbox, args []*syntax.Word) error {
	return validateSourceArgs(s, args)
}

func validateCargoCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig()
	if cfg.Runtimes == nil || cfg.Runtimes.Rust == nil || !cfg.Runtimes.Rust.RustEnabled() {
		return fmt.Errorf("command \"cargo\" is not allowed (runtimes.rust.enabled is disabled)")
	}
	return validateCargoArgs(args, cfg.Runtimes.Rust)
}

func validateRustcCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig()
	if cfg.Runtimes == nil || cfg.Runtimes.Rust == nil || !cfg.Runtimes.Rust.RustEnabled() {
		return fmt.Errorf("command \"rustc\" is not allowed (runtimes.rust.enabled is disabled)")
	}
	return nil
}

func validateAWSCommand(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig()
	if cfg.AWS == nil || !cfg.AWS.AWSEnabled() {
		return fmt.Errorf("command \"aws\" is not allowed (aws.enabled is disabled)")
	}
	// AWS CLI credentials will come from IMDS endpoint, not files
	// No additional argument validation needed - all aws subcommands allowed
	return nil
}
