package bash_sandboxed

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/interp"

	"mvdan.cc/sh/v3/syntax"
)

// contextKey is an unexported type for context keys in this package.
type contextKey int

const (
	// bashDepthKey tracks nesting depth of bash -c / bash script.sh calls.
	bashDepthKey contextKey = iota
	// sandboxPathsKey carries read/write allowed paths into nested interpreters.
	sandboxPathsKey
)

// maxBashDepth is the maximum nesting depth for bash/sh execution.
const maxBashDepth = 10

// sandboxPaths holds the path configuration for nested interpreters.
type sandboxPaths struct {
	readAllowedPaths  []string
	writeAllowedPaths []string
}

// isScriptPath returns true if the command name is a direct script invocation
// path: like bash, any name containing a "/" ("./x.sh", "/bin/x", "web/x.sh")
// runs that file rather than a PATH lookup. Plain names like "script.sh" are
// NOT treated as script paths (use "bash script.sh" for those).
func isScriptPath(name string) bool {
	return strings.Contains(name, "/")
}

// scriptShebangArgv returns the argv a kernel would prepend when executing a
// script with the given shebang line — the interpreter (as a bare command name,
// so it resolves through PATH and the whitelist like a typed command) followed
// by its flags — or nil when the script has no shebang. "#!/usr/bin/env X ..."
// is unwrapped to X: env's -S/--split-string and VAR=value assignments are
// dropped, so the result is what actually runs.
//
//	#!/bin/bash                 -> [bash]
//	#!/usr/bin/env python3 -u   -> [python3 -u]
//	#!/usr/bin/awk -f           -> [awk -f]
func scriptShebangArgv(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return shebangArgv(string(buf[:n]))
}

func shebangArgv(script string) []string {
	if !strings.HasPrefix(script, "#!") {
		return nil
	}
	line := script[2:]
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return nil
	}
	if filepath.Base(fields[0]) == "env" {
		rest := fields[1:]
		for len(rest) > 0 && (strings.HasPrefix(rest[0], "-") || strings.Contains(rest[0], "=")) {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return nil
		}
		fields = rest
	}
	out := append([]string{filepath.Base(fields[0])}, fields[1:]...)
	return out
}

// scriptInterpreter returns just the interpreter name from a shebang (see
// shebangArgv), or "" when there is none.
func scriptInterpreter(script string) string {
	if argv := shebangArgv(script); len(argv) > 0 {
		return argv[0]
	}
	return ""
}

// isShellInterpreter reports whether a shebang interpreter is one the sandbox
// runs through its own shell interpreter (so the script body is validated)
// rather than exec'ing as an opaque program.
func isShellInterpreter(name string) bool {
	switch name {
	case "bash", "sh", "dash", "zsh":
		return true
	}
	return false
}

// isBinaryExecutable checks if the file at path is a compiled binary
// by reading its magic bytes. Detects ELF and Mach-O formats.
func isBinaryExecutable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	var magic [4]byte
	n, err := f.Read(magic[:])
	if err != nil || n < 4 {
		return false
	}

	// ELF: \x7fELF
	if magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F' {
		return true
	}

	// Mach-O 64-bit big-endian: \xfe\xed\xfa\xcf
	if magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa && magic[3] == 0xcf {
		return true
	}

	// Mach-O 32-bit big-endian: \xfe\xed\xfa\xce
	if magic[0] == 0xfe && magic[1] == 0xed && magic[2] == 0xfa && magic[3] == 0xce {
		return true
	}

	// Mach-O 64-bit little-endian: \xcf\xfa\xed\xfe
	if magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe {
		return true
	}

	// Mach-O 32-bit little-endian: \xce\xfa\xed\xfe
	if magic[0] == 0xce && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe {
		return true
	}

	// Mach-O fat/universal binary: \xca\xfe\xba\xbe
	if magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba && magic[3] == 0xbe {
		return true
	}

	return false
}

// validateSourceArgs validates source/. command arguments at the AST level.
// Requires a file path argument (no bare "source" which would be a no-op).
// The *Sandbox parameter is unused but required by the argValidator
// function type.
func validateSourceArgs(_ *Sandbox, args []*syntax.Word) error {
	cmdName := wordText(args[0])
	if len(args) < 2 {
		return fmt.Errorf("bare %q (no file argument) is not allowed", cmdName)
	}
	return nil
}

// validateBashArgs validates bash/sh command arguments at the AST level:
// the flags parseShellArgs refuses, and a shell that would read commands
// from stdin. The -c command string's content, and a script file's, is
// validated at runtime by executeBash (parse → validate → path checks), to
// avoid an initialization cycle.
func validateBashArgs(_ *Sandbox, args []*syntax.Word) error {
	inv, err := parseShellArgs(args, blockedBashFlags)
	if err != nil {
		return err
	}
	if inv.readsStdin() {
		return fmt.Errorf("bare %q (no -c or script file) is not allowed: reads from stdin", inv.vals[0])
	}
	return nil
}

// executeBash runs a bash/sh command by parsing and executing it through
// the sandbox interpreter, applying the same security restrictions.
func (s *Sandbox) executeBash(ctx context.Context, args []string) error {
	// Check nesting depth
	depth := 0
	if v := ctx.Value(bashDepthKey); v != nil {
		depth = v.(int)
	}
	if depth >= maxBashDepth {
		return fmt.Errorf("bash nesting depth exceeded (max %d)", maxBashDepth)
	}

	// Get sandbox paths from context
	paths, ok := ctx.Value(sandboxPathsKey).(*sandboxPaths)
	if !ok || paths == nil {
		return fmt.Errorf("bash: sandbox paths not available in context")
	}

	cmdName := args[0]
	inv, err := parseShellArgs(literalWords(args), blockedBashFlags)
	if err != nil {
		return err
	}
	hc := interp.HandlerCtx(ctx)

	// Determine the script content, and the positional parameters it gets
	var script, scriptFile string
	var params []string
	switch {
	case inv.command >= 0:
		script = args[inv.command]
		if script == "" {
			return fmt.Errorf("%s -c: empty command string", cmdName)
		}
	case inv.script >= 0:
		scriptFile = args[inv.script]
		// `bash <script>` runs the script as surely as `./<script>` does, so a
		// ask entry for the script applies here too; past it, the
		// script's own commands are not covered by the call's approval.
		if _, err := s.checkAsk(ctx, scriptFile, args[inv.script+1:]); err != nil {
			if err := s.report(ctx, layerRuntime, ruleCommandAsk, err); err != nil {
				return err
			}
		}
		ctx = withoutApproval(ctx)
		path := absPath(scriptFile, hc.Dir)
		// A bare allow of the script trusts it, so invoking it via
		// `bash <script>` behaves the same as running it directly
		// (`./<script>`): it runs here with the checks a bare allow lifts not
		// enforced (withTrustedScript). Match either by the literal token or
		// by the resolved absolute path so `bash web/foo/build.sh` matches an
		// entry registered as `./web/foo/build.sh`.
		if s.trustsScript(path) {
			ctx = withTrustedScript(ctx, s.scriptUnsandboxed(path))
			// One allowed with no_sandbox runs natively on the host: this
			// invocation, with the host's own bash (or sh), given the script
			// by the path it is trusted by (see nativeScriptArgv).
			if ts, _ := trustedScriptFrom(ctx); ts.host {
				native := append([]string(nil), args...)
				native[inv.script] = filepath.Clean(path)
				return s.dispatchExec(withNativeScript(ctx), native, s.osSandboxEnabled())
			}
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: cannot read script %s: %w", cmdName, path, err)
		}
		script = string(data)
		// The words after the script are its $1, $2, ...
		params = args[inv.script+1:]
	default:
		return fmt.Errorf("%s: no command or script file specified", cmdName)
	}

	// Prepend shell flags as set commands, each quoted: an -o value is the
	// option's name, never shell syntax.
	if len(inv.set) > 0 {
		set := make([]string, len(inv.set))
		for i, w := range inv.set {
			q, err := syntax.Quote(w, syntax.LangBash)
			if err != nil {
				return fmt.Errorf("%s: option %q: %w", cmdName, w, err)
			}
			set[i] = q
		}
		// bash refuses to start (status 2) on an option it does not know;
		// stop before the script runs too.
		script = "set " + strings.Join(set, " ") + " || exit 2\n" + script
	}

	// Parse the script
	f, err := ParseBash(script)
	if err != nil {
		return fmt.Errorf("%s: %w", cmdName, err)
	}

	// Validate through the sandbox. Use the workDir-aware variant so functions
	// the script declares (or picks up via `source`) count as allowed commands,
	// matching how the top-level command string is validated.
	if err := s.validateFileCtx(ctx, f, hc.Dir, paths.readAllowedPaths, paths.writeAllowedPaths); err != nil {
		return fmt.Errorf("%s: validation failed: %w", cmdName, err)
	}

	// Create nested context with incremented depth
	nestedCtx := context.WithValue(ctx, bashDepthKey, depth+1)
	nestedCtx = context.WithValue(nestedCtx, sandboxPathsKey, paths)

	// Build and run nested interpreter
	return s.runNestedInterp(nestedCtx, f, hc, paths, scriptFile, params...)
}

// executeScript runs a script file (e.g., ./script.sh) by reading it,
// stripping any shebang line, then parsing and executing it through the
// sandbox interpreter with the same security restrictions.
func (s *Sandbox) executeScript(ctx context.Context, args []string) error {
	// Check nesting depth
	depth := 0
	if v := ctx.Value(bashDepthKey); v != nil {
		depth = v.(int)
	}
	if depth >= maxBashDepth {
		return fmt.Errorf("script nesting depth exceeded (max %d)", maxBashDepth)
	}

	// Get sandbox paths from context
	paths, ok := ctx.Value(sandboxPathsKey).(*sandboxPaths)
	if !ok || paths == nil {
		return fmt.Errorf("script: sandbox paths not available in context")
	}

	hc := interp.HandlerCtx(ctx)
	scriptPath := absPath(args[0], hc.Dir)
	// The call's approval covers the command line the user saw, not the
	// commands of the script it runs.
	ctx = withoutApproval(ctx)

	// Read the script file
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("cannot read script %s: %w", scriptPath, err)
	}
	script := stripShebang(string(data))

	// Parse and validate
	f, err := ParseBash(script)
	if err != nil {
		return fmt.Errorf("script %s: %w", args[0], err)
	}
	if err := s.validateFileCtx(ctx, f, hc.Dir, paths.readAllowedPaths, paths.writeAllowedPaths); err != nil {
		return fmt.Errorf("script %s: validation failed: %w", args[0], err)
	}

	// Set up positional parameters ($1, $2, ...) from remaining args
	nestedCtx := context.WithValue(ctx, bashDepthKey, depth+1)
	nestedCtx = context.WithValue(nestedCtx, sandboxPathsKey, paths)

	// If script has arguments, prepend a `set -- arg1 arg2 ...` to pass them
	if len(args) > 1 {
		var setArgs []string
		for _, a := range args[1:] {
			setArgs = append(setArgs, "'"+strings.ReplaceAll(a, "'", "'\\''")+"'")
		}
		script = "set -- " + strings.Join(setArgs, " ") + "\n" + script
		// Re-parse with the set command prepended
		f, err = ParseBash(script)
		if err != nil {
			return fmt.Errorf("script %s: %w", args[0], err)
		}
	}

	return s.runNestedInterp(nestedCtx, f, hc, paths, args[0])
}

// runNestedInterp creates and runs a nested interpreter with the same
// security handlers as the parent. scriptName is the script path as invoked,
// empty for `bash -c`; it becomes $0 and BASH_SOURCE, which scripts use to
// locate themselves (`cd "$(dirname "${BASH_SOURCE[0]}")"`). params, when
// given, are the script's positional parameters ($1, $2, ...).
func (s *Sandbox) runNestedInterp(ctx context.Context, f *syntax.File, hc interp.HandlerContext, paths *sandboxPaths, scriptName string, params ...string) error {
	useOSSandbox := s.osSandboxEnabled()

	// Build environment from parent context: a nested script is a child
	// process, so it inherits only the exported variables.
	var env []string
	hc.Env.Each(func(name string, vr expand.Variable) bool {
		if !isExportedEnvVar(vr) {
			return true
		}
		env = append(env, name+"="+vr.String())
		return true
	})

	environ := expand.ListEnviron(env...)
	if scriptName != "" {
		// The interpreter takes $0 from the file name and has no BASH_SOURCE
		// of its own.
		f.Name = scriptName
		environ = scriptEnviron{Environ: environ, source: scriptName}
	}

	opts := []interp.RunnerOption{
		interp.Dir(hc.Dir),
		interp.StdIO(hc.Stdin, hc.Stdout, hc.Stderr),
		interp.Env(environ),
	}
	if len(params) > 0 {
		opts = append(opts, interp.Params(append([]string{"--"}, params...)...))
	}

	opts = append(opts, s.buildSecurityHandlers(paths.readAllowedPaths, paths.writeAllowedPaths, useOSSandbox)...)

	runner, err := interp.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to create nested interpreter: %w", err)
	}

	return runner.Run(ctx, f)
}

// scriptEnviron adds a script's BASH_SOURCE to its environment. The variable is
// not exported, so the script's children do not inherit it.
type scriptEnviron struct {
	expand.Environ
	source string
}

func (e scriptEnviron) bashSource() expand.Variable {
	return expand.Variable{Set: true, Kind: expand.Indexed, List: []string{e.source}}
}

func (e scriptEnviron) Get(name string) expand.Variable {
	if name == "BASH_SOURCE" {
		return e.bashSource()
	}
	return e.Environ.Get(name)
}

func (e scriptEnviron) Each(fn func(name string, vr expand.Variable) bool) {
	if !fn("BASH_SOURCE", e.bashSource()) {
		return
	}
	e.Environ.Each(fn)
}

// literalWords wraps each expanded argv string as a single-literal *syntax.Word
// so the per-command argument validators (which operate on AST words via
// .Lit()/wordText()) can be re-run at runtime on a fully expanded, concrete
// command. This is what lets a dynamically-named command (e.g. "$CMD ...")
// still be argument-validated once its real name and arguments are known.
func literalWords(args []string) []*syntax.Word {
	words := make([]*syntax.Word, len(args))
	for i, a := range args {
		words[i] = &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: a}}}
	}
	return words
}

// execArgvMaxDepth bounds the shebang re-dispatch below: a script whose
// interpreter is itself resolved to another script must terminate.
const execArgvMaxDepth = 4

// execArgv is the body of the interpreter's ExecHandler: it gates and runs one
// external command with its fully expanded argv. sets is the caller's already
// resolved allowed-path boundary, passed through for the embedded Python
// interpreter's OS-call authorization. depth counts shebang re-dispatches (see
// the script branch).
func (s *Sandbox) execArgv(ctx context.Context, args []string, useOSSandbox bool, readAllowedPaths, writeAllowedPaths []string, sets resolvedPathSets, depth int) error {
	// Intercept `aws configure list-profiles` in brokered IMDS mode so an
	// agent can discover the profiles it may select via AWS_PROFILE (the
	// real command would read the masked ~/.aws and return nothing).
	if handled, err := s.maybeListProfiles(ctx, args); handled || err != nil {
		return err
	}
	if len(args) == 0 {
		return s.dispatchExec(ctx, args, useOSSandbox)
	}
	extra := s.getExtraCommands()
	cmdName := args[0]
	// Runtime deny-list check, before every other gate and every dispatch
	// (bash, awk, python, scripts, the OS sandbox worker): this is where a
	// dynamically-named or script-launched denied command is caught, since its
	// real name and arguments are only concrete here.
	if entry, denied := s.deniedCommand(cmdName, args[1:]); denied {
		if err := s.report(ctx, layerRuntime, ruleCommandDenylist, commandDeniedError(cmdName, entry)); err != nil {
			return err
		}
	}
	// Runtime ask check, alongside the deny list: a prompted invocation
	// whose name was dynamic, or that a script runs, is caught here.
	askApproved, askErr := s.checkAsk(ctx, cmdName, args[1:])
	if err := s.report(ctx, layerRuntime, ruleCommandAsk, askErr); err != nil {
		return err
	}
	// Runtime command whitelist check — catches blocked commands
	// introduced via source/. or other dynamic execution paths.
	// Process-control commands (kill, pkill) are permitted only when
	// the OS sandbox is active, where they are contained.
	osOnly := osSandboxOnlyCommands[cmdName] && useOSSandbox
	bareScript := s.bareAllowsScript(cmdName, interp.HandlerCtx(ctx).Dir)
	if !s.commandWhitelisted(cmdName) && !s.extraAllowsArgs(cmdName, args[1:]) && !bareScript && !osOnly && !askApproved {
		// Whitelist and local-binary gates are allowlist-only rules: in
		// denylist/open mode the finding is audited and the command runs.
		var gateErr error
		if isScriptPath(cmdName) {
			if !s.getConfig().LocalBinaryExecution.IsEnabled() {
				gateErr = directExecutionNotAllowed(cmdName)
			}
		} else {
			gateErr = commandNotAllowed(cmdName)
		}
		if err := s.report(ctx, layerRuntime, ruleCommandWhitelist, gateErr); err != nil {
			return err
		}
	}
	// Runtime per-command argument validation on the fully expanded
	// argv (bash/sh/awk are skipped: they are dispatched to dedicated
	// executors below that re-validate their contents).
	if err := s.runtimeArgValidator(ctx, cmdName, args); err != nil {
		return err
	}
	// The command's own preparation (deno's permission flags, SwiftPM's
	// nested sandbox) and in-process executor (awk, bash, sh, python); see
	// commandSpec.prepareExec and run.
	spec := lookupCommand(cmdName)
	x := execEnv{useOSSandbox: useOSSandbox, readAllowedPaths: readAllowedPaths, writeAllowedPaths: writeAllowedPaths, sets: sets}
	if spec.prepareExec != nil {
		args = spec.prepareExec(ctx, s, args, x)
	}
	if spec.run != nil {
		if handled, err := spec.run(ctx, s, args, x); handled {
			return err
		}
	}
	if isScriptPath(cmdName) {
		hc := interp.HandlerCtx(ctx)
		path := absPath(cmdName, hc.Dir)
		if bareScript {
			// A bare allow of the script trusts it (see bareAllowsScript for
			// how an invocation matches): a shell script runs through the
			// interpreter below like any other, with the checks a bare allow
			// lifts not enforced for what it runs (withTrustedScript) — unless
			// it is allowed with no_sandbox, when it runs natively on the host.
			ctx = withTrustedScript(ctx, s.scriptUnsandboxed(path))
			if ts, _ := trustedScriptFrom(ctx); ts.host {
				return s.dispatchExec(withNativeScript(ctx), nativeScriptArgv(filepath.Clean(path), args), useOSSandbox)
			}
		} else if extra[cmdName] && !s.getConfig().LocalBinaryExecution.IsEnabled() {
			// A subcommand-restricted extra_commands entry (e.g. "./gradlew
			// build") allows the invocation but, unlike a bare entry, is not
			// an opt-out of the local-binary gate, which the whitelist branch
			// above skipped because extra[cmdName] was true.
			if err := s.report(ctx, layerRuntime, ruleLocalBinary, directExecutionNotAllowed(cmdName)); err != nil {
				return err
			}
		}
		// Check if file is a compiled binary (ELF/Mach-O)
		if isBinaryExecutable(path) {
			return s.dispatchExec(ctx, args, useOSSandbox)
		}
		// A script for another interpreter (#!/usr/bin/env python3 -u) is run
		// exactly as if the agent had typed the interpreter invocation the
		// kernel would perform — "python3 -u ./x args" — so the interpreter
		// goes through the same whitelist gate, argument validator, and
		// dedicated executor (awk's, bash's) as a direct call would. One a
		// bare allow names runs as the native program its shebang names, as
		// a binary would: the sandbox has nothing of it to interpret.
		if shebang := scriptShebangArgv(path); len(shebang) > 0 && !isShellInterpreter(shebang[0]) {
			if bareScript {
				return s.dispatchExec(ctx, args, useOSSandbox)
			}
			if depth >= execArgvMaxDepth {
				return fmt.Errorf("script %q: interpreter nesting too deep", cmdName)
			}
			full := append(append(shebang, path), args[1:]...)
			return s.execArgv(ctx, full, useOSSandbox, readAllowedPaths, writeAllowedPaths, sets, depth+1)
		}
		return s.executeScript(ctx, args)
	}
	return s.dispatchExec(ctx, args, useOSSandbox)
}

// shellStartupEnv are the variables a native shell acts on that the
// sandbox's interpreter ignores: before a script's first line, BASH_ENV and
// ENV (sourced), SHELLOPTS (with xtrace, bash expands PS4, command
// substitutions included), BASHOPTS, PS4, BASH_XTRACEFD, and zsh's ZDOTDIR
// (it sources $ZDOTDIR/.zshenv); and CDPATH, which redirects the script's
// own `cd`. Assigning them is refused (blockedEnvVars), but that check sees
// only assignments it can name, so a command allowed with no_sandbox (a
// script run natively, or a program that starts a shell) gets the server's
// own values for them on the host, whatever set them (execOnHost). Exported
// bash functions (BASH_FUNC_name%%) are treated the same way.
var shellStartupEnv = []string{"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4", "BASH_XTRACEFD", "ZDOTDIR", "CDPATH"}

// nativeScriptEnv are the variables a script allowed with no_sandbox gets
// from the server's environment rather than the interpreter's (execOnHost):
// PATH, which finds its shell (`bash <script>`, `#!/usr/bin/env bash`), and
// HOME, where zsh finds .zshenv. Assigning PATH is refused, but that check
// sees only assignments it can name; HOME may be set for other commands.
var nativeScriptEnv = []string{"PATH", "HOME"}

type nativeScriptKey struct{}

// withNativeScript marks ctx as the native run of a script allowed with
// no_sandbox (see nativeScriptEnv).
func withNativeScript(ctx context.Context) context.Context {
	return context.WithValue(ctx, nativeScriptKey{}, true)
}

func isNativeScript(ctx context.Context) bool {
	v, _ := ctx.Value(nativeScriptKey{}).(bool)
	return v
}

// nativeScriptArgv is the argv that runs the script at path (the cleaned
// absolute path it is trusted by) natively, with the arguments of args (the
// invocation): the script itself, which the kernel starts through its
// shebang or as a binary, or, for a text file without a shebang (which exec
// refuses), `bash <script>`, which is what bash does with one. It is run by
// path, never by the word that named it: through a symlinked directory,
// `x/../build.sh` cleans to the trusted file but the kernel would open another.
func nativeScriptArgv(path string, args []string) []string {
	argv := append([]string{path}, args[1:]...)
	if isBinaryExecutable(path) || scriptShebangArgv(path) != nil {
		return argv
	}
	return append([]string{"bash"}, argv...)
}

// runtimeArgValidator re-runs the per-command argument validator for name
// against the fully expanded argv, shared by the runtime Call and Exec
// handlers. Static validation already runs these validators for statically
// named commands; this is the enforcement layer for a dynamically-named one
// (e.g. "$CMD push" resolving to git), whose real name and arguments are only
// concrete at runtime. An invocation a commands allow admits is user-opted-in
// and bypasses validation, matching static — and, as there, a restricted allow
// ("cargo publish") admits only the invocations it names, so the rest of the
// command's invocations keep their validator; commands that revalidate
// themselves (commandSpec.revalidatesItself) are dispatched to dedicated executors that re-validate their contents
// instead. args is the full argv.
func (s *Sandbox) runtimeArgValidator(ctx context.Context, name string, args []string) error {
	if s.allowLiftsValidator(name, args[1:]) || lookupCommand(name).revalidatesItself {
		return nil
	}
	validator, ok := s.validator(name)
	if !ok {
		return nil
	}
	return s.report(ctx, layerRuntime, ruleArgValidator, validator(s, literalWords(args)))
}

// buildSecurityHandlers returns the common CallHandler, OpenHandler, and
// ExecHandler options used by both the top-level and nested interpreters.
func (s *Sandbox) buildSecurityHandlers(readAllowedPaths, writeAllowedPaths []string, useOSSandbox bool) []interp.RunnerOption {
	// Resolve the allowed-path sets once for this interpreter. The Call and Open
	// handlers fire for every command and every file open, so resolving per
	// invocation would run EvalSymlinks over the whole allowed set thousands of
	// times in a loop. Candidate paths are still resolved individually at check
	// time, so pinning the boundary here is never less restrictive: an allowed
	// directory whose symlink is re-pointed mid-execution cannot drag the
	// boundary to its new target.
	sets := resolvePathSets(readAllowedPaths, writeAllowedPaths)
	return []interp.RunnerOption{
		interp.CallHandler(func(ctx context.Context, args []string) ([]string, error) {
			hc := interp.HandlerCtx(ctx)
			if err := s.report(ctx, layerRuntime, rulePathBoundary, validateExpandedPaths(args, hc.Dir, sets)); err != nil {
				return nil, err
			}
			// A bare cd changes to $HOME, which no argument names for the
			// check above; without this, `cd; ls` lists a directory outside
			// the boundary.
			if len(args) == 1 && args[0] == "cd" {
				if home := hc.Env.Get("HOME").String(); home != "" {
					if err := s.report(ctx, layerRuntime, rulePathBoundary, validateExpandedPaths([]string{"cd", home}, hc.Dir, sets)); err != nil {
						return nil, err
					}
				}
			}
			// The CallHandler runs for every command — functions, builtins, and
			// externals — before the interpreter resolves which it is, so it is
			// the only runtime layer that sees builtins (the ExecHandler runs
			// solely for externals). Enforce the command whitelist for builtins
			// here so a dynamically-named builtin (e.g. "$X" resolving to
			// eval/exec/shopt, none whitelisted) cannot escape validation now
			// that static analysis defers dynamic names to runtime. Functions
			// and externals (IsBuiltin == false) are left untouched: functions
			// run as user code and externals are gated by the ExecHandler.
			//
			// Process-control commands get the same OS-sandbox exemption as in
			// the ExecHandler. The interpreter lists kill as a builtin it does
			// not implement, so letting it through here surfaces the
			// interpreter's own "unsupported builtin" error rather than a
			// misleading "not allowed"; agents fall back to pkill.
			if len(args) > 0 && interp.IsBuiltin(args[0]) {
				name := args[0]
				if entry, denied := s.deniedCommand(name, args[1:]); denied {
					if err := s.report(ctx, layerRuntime, ruleCommandDenylist, commandDeniedError(name, entry)); err != nil {
						return nil, err
					}
				}
				askApproved, askErr := s.checkAsk(ctx, name, args[1:])
				if err := s.report(ctx, layerRuntime, ruleCommandAsk, askErr); err != nil {
					return nil, err
				}
				osOnly := osSandboxOnlyCommands[name] && useOSSandbox
				if !s.commandWhitelisted(name) && !s.extraAllowsArgs(name, args[1:]) && !osOnly && !askApproved {
					if err := s.report(ctx, layerRuntime, ruleCommandWhitelist, commandNotAllowed(name)); err != nil {
						return nil, err
					}
				}
				if err := s.runtimeArgValidator(ctx, name, args); err != nil {
					return nil, err
				}
			}
			return args, nil
		}),
		interp.OpenHandler(func(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
			if f, ok := openStdStream(ctx, path, flag); ok {
				return f, nil
			}
			hc := interp.HandlerCtx(ctx)
			if err := s.report(ctx, layerRuntime, rulePathBoundary, validateOpenPath(path, flag, hc.Dir, sets)); err != nil {
				return nil, err
			}
			return interp.DefaultOpenHandler()(ctx, path, flag, perm)
		}),
		interp.ExecHandler(func(ctx context.Context, args []string) error {
			return s.execArgv(ctx, args, useOSSandbox, readAllowedPaths, writeAllowedPaths, sets, 0)
		}),
	}
}
