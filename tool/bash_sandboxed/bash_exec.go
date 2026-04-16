package bash_sandboxed

import (
	"context"
	"fmt"
	"io"
	"os"
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

// isScriptPath returns true if the command name looks like a direct script
// invocation path: starts with "./", "../", or "/". Plain names like
// "script.sh" are NOT treated as script paths (use "bash script.sh" for those).
func isScriptPath(name string) bool {
	return strings.HasPrefix(name, "./") || strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/")
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
func validateSourceArgs(s *Sandbox, args []*syntax.Word) error {
	cmdName := wordText(args[0])
	if len(args) < 2 {
		return fmt.Errorf("bare %q (no file argument) is not allowed", cmdName)
	}
	return nil
}

// blockedBashFlags lists bash/sh flags that are not allowed.
var blockedBashFlags = map[string]string{
	"-i":            "interactive mode is not allowed",
	"--interactive": "interactive mode is not allowed",
	"-s":            "reading commands from stdin is not allowed",
	"--init-file":   "sourcing init files is not allowed",
	"--rcfile":      "sourcing rc files is not allowed",
	"-l":            "login shell is not allowed",
	"--login":       "login shell is not allowed",
}

// allowedBashFlags lists bash/sh flags that are safe to use.
var allowedBashFlags = map[string]bool{
	"-e":           true,
	"-x":           true,
	"-u":           true,
	"-n":           true,
	"-v":           true,
	"-c":           true,
	"--norc":       true,
	"--noprofile":  true,
}

// validateBashArgs validates bash/sh command arguments at the AST level.
func validateBashArgs(s *Sandbox, args []*syntax.Word) error {
	cmdName := wordText(args[0])
	i := 1
	foundC := false
	for i < len(args) {
		text := wordText(args[i])
		if text == "" {
			i++
			continue
		}

		// Check for blocked flags
		if reason, blocked := blockedBashFlags[text]; blocked {
			return fmt.Errorf("%s: flag %q is not allowed: %s", cmdName, text, reason)
		}

		// -o takes a value argument (e.g., -o pipefail)
		if text == "-o" {
			i += 2
			continue
		}

		// -c flag: next arg is the command string
		if text == "-c" {
			foundC = true
			i++
			if i >= len(args) {
				return fmt.Errorf("%s -c requires a command string argument", cmdName)
			}
			// Static validation only checks flags here. The command string
			// content is fully validated at runtime by executeBash (parse →
			// validate → path checks) to avoid an initialization cycle.
			i++
			continue
		}

		// Known safe flags
		if allowedBashFlags[text] {
			i++
			continue
		}

		// Combined short flags like -ex, -eu, -exu
		if len(text) > 1 && text[0] == '-' && text[1] != '-' {
			allValid := true
			for _, ch := range text[1:] {
				flag := "-" + string(ch)
				if _, blocked := blockedBashFlags[flag]; blocked {
					return fmt.Errorf("%s: flag %q (in %q) is not allowed", cmdName, flag, text)
				}
				if flag == "-c" {
					foundC = true
				}
				if !allowedBashFlags[flag] && flag != "-o" {
					allValid = false
				}
			}
			if allValid || foundC {
				if foundC {
					// -c was in the combined flags; next arg is the command string
					i++
					if i >= len(args) {
						return fmt.Errorf("%s -c requires a command string argument", cmdName)
					}
					// Content validated at runtime by executeBash
				}
				i++
				continue
			}
			// If not all valid and no -c, it might be a script file path
			// Fall through to script file handling below
		}

		// If we haven't found -c, this could be a script file path
		if !foundC && !strings.HasPrefix(text, "-") {
			// Script file — can't validate content statically, runtime will handle it
			i++
			// Remaining args are script arguments, skip them
			break
		}

		// Allow unknown flags that start with + (set options)
		if strings.HasPrefix(text, "+") {
			i++
			continue
		}

		// After -c command_string, remaining args are $0, $1, etc.
		if foundC {
			i++
			continue
		}

		i++
	}

	// Bare bash/sh with no -c and no script file reads from stdin
	if !foundC && i == 1 {
		return fmt.Errorf("bare %q (no -c or script file) is not allowed: reads from stdin", cmdName)
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

	// Parse arguments
	var cmdString string
	var scriptFile string
	var shellFlags []string
	foundC := false

	i := 1
	for i < len(args) {
		arg := args[i]

		if arg == "-o" {
			if i+1 < len(args) {
				shellFlags = append(shellFlags, "-o", args[i+1])
				i += 2
				continue
			}
			i++
			continue
		}

		if arg == "-c" {
			foundC = true
			i++
			if i < len(args) {
				cmdString = args[i]
			}
			i++
			continue
		}

		// Known safe flags
		if allowedBashFlags[arg] || arg == "--norc" || arg == "--noprofile" {
			if arg != "-c" && arg != "--norc" && arg != "--noprofile" {
				shellFlags = append(shellFlags, arg)
			}
			i++
			continue
		}

		// Combined short flags
		if len(arg) > 1 && arg[0] == '-' && arg[1] != '-' {
			for _, ch := range arg[1:] {
				flag := "-" + string(ch)
				if flag == "-c" {
					foundC = true
					continue
				}
				if allowedBashFlags[flag] {
					shellFlags = append(shellFlags, flag)
				}
			}
			if foundC {
				i++
				if i < len(args) {
					cmdString = args[i]
				}
				i++
				continue
			}
			i++
			continue
		}

		// Script file (first non-flag argument when not -c mode)
		if !foundC && !strings.HasPrefix(arg, "-") {
			scriptFile = arg
			i++
			break
		}

		// Args after -c command_string
		i++
	}

	// Determine the script content
	var script string
	if foundC {
		if cmdString == "" {
			return fmt.Errorf("%s -c: empty command string", cmdName)
		}
		script = cmdString
	} else if scriptFile != "" {
		hc := interp.HandlerCtx(ctx)
		path := absPath(scriptFile, hc.Dir)
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s: cannot read script %s: %w", cmdName, path, err)
		}
		script = string(data)
	} else {
		return fmt.Errorf("%s: no command or script file specified", cmdName)
	}

	// Prepend shell flags as set commands
	if len(shellFlags) > 0 {
		script = "set " + strings.Join(shellFlags, " ") + "\n" + script
	}

	// Parse the script
	f, err := ParseBash(script)
	if err != nil {
		return fmt.Errorf("%s: %w", cmdName, err)
	}

	// Validate through the sandbox
	if err := s.validate(f); err != nil {
		return fmt.Errorf("%s: validation failed: %w", cmdName, err)
	}

	hc := interp.HandlerCtx(ctx)
	if err := validatePaths(f, hc.Dir, paths.readAllowedPaths, paths.writeAllowedPaths); err != nil {
		return fmt.Errorf("%s: validation failed: %w", cmdName, err)
	}
	if err := validateRedirectPaths(f, hc.Dir, paths.readAllowedPaths, paths.writeAllowedPaths); err != nil {
		return fmt.Errorf("%s: validation failed: %w", cmdName, err)
	}

	// Create nested context with incremented depth
	nestedCtx := context.WithValue(ctx, bashDepthKey, depth+1)
	nestedCtx = context.WithValue(nestedCtx, sandboxPathsKey, paths)

	// Build and run nested interpreter
	return s.runNestedInterp(nestedCtx, f, hc, paths)
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

	// Read the script file
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("cannot read script %s: %w", scriptPath, err)
	}
	script := string(data)

	// Strip shebang line if present
	if strings.HasPrefix(script, "#!") {
		if idx := strings.IndexByte(script, '\n'); idx >= 0 {
			script = script[idx+1:]
		} else {
			script = ""
		}
	}

	// Parse and validate
	f, err := ParseBash(script)
	if err != nil {
		return fmt.Errorf("script %s: %w", args[0], err)
	}
	if err := s.validate(f); err != nil {
		return fmt.Errorf("script %s: validation failed: %w", args[0], err)
	}
	if err := validatePaths(f, hc.Dir, paths.readAllowedPaths, paths.writeAllowedPaths); err != nil {
		return fmt.Errorf("script %s: validation failed: %w", args[0], err)
	}
	if err := validateRedirectPaths(f, hc.Dir, paths.readAllowedPaths, paths.writeAllowedPaths); err != nil {
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

	return s.runNestedInterp(nestedCtx, f, hc, paths)
}

// runNestedInterp creates and runs a nested interpreter with the same
// security handlers as the parent.
func (s *Sandbox) runNestedInterp(ctx context.Context, f *syntax.File, hc interp.HandlerContext, paths *sandboxPaths) error {
	s.mu.RLock()
	useOSSandbox := s.osSandbox
	s.mu.RUnlock()

	// Build environment from parent context
	var env []string
	hc.Env.Each(func(name string, vr expand.Variable) bool {
		if !vr.IsSet() {
			return true
		}
		env = append(env, name+"="+vr.String())
		return true
	})

	opts := []interp.RunnerOption{
		interp.Dir(hc.Dir),
		interp.StdIO(hc.Stdin, hc.Stdout, hc.Stderr),
		interp.Env(expand.ListEnviron(env...)),
	}

	opts = append(opts, s.buildSecurityHandlers(paths.readAllowedPaths, paths.writeAllowedPaths, useOSSandbox)...)

	runner, err := interp.New(opts...)
	if err != nil {
		return fmt.Errorf("failed to create nested interpreter: %w", err)
	}

	return runner.Run(ctx, f)
}

// buildSecurityHandlers returns the common CallHandler, OpenHandler, and
// ExecHandler options used by both the top-level and nested interpreters.
func (s *Sandbox) buildSecurityHandlers(readAllowedPaths, writeAllowedPaths []string, useOSSandbox bool) []interp.RunnerOption {
	return []interp.RunnerOption{
		interp.CallHandler(func(ctx context.Context, args []string) ([]string, error) {
			hc := interp.HandlerCtx(ctx)
			if err := validateExpandedPaths(args, hc.Dir, readAllowedPaths, writeAllowedPaths); err != nil {
				return nil, err
			}
			return args, nil
		}),
		interp.OpenHandler(func(ctx context.Context, path string, flag int, perm os.FileMode) (io.ReadWriteCloser, error) {
			hc := interp.HandlerCtx(ctx)
			if err := validateOpenPath(path, flag, hc.Dir, readAllowedPaths, writeAllowedPaths); err != nil {
				return nil, err
			}
			return interp.DefaultOpenHandler()(ctx, path, flag, perm)
		}),
		interp.ExecHandler(func(ctx context.Context, args []string) error {
			extra := s.getExtraCommands()
			if len(args) > 0 {
				cmdName := args[0]
				// Runtime command whitelist check — catches blocked commands
				// introduced via source/. or other dynamic execution paths.
				if !allowedCommands[cmdName] && !extra[cmdName] {
					if !s.getConfig().LocalBinaryExecution.IsEnabled() || !isScriptPath(cmdName) {
						return fmt.Errorf("command %q is not allowed", cmdName)
					}
				}
				switch cmdName {
				case "awk":
					return executeAwk(ctx, args)
				case "bash", "sh":
					return s.executeBash(ctx, args)
				}
				if isScriptPath(cmdName) {
					// Bare extra_commands entries are explicitly opted in by the
					// user — run them directly without reading/validating script
					// contents. This mirrors the top-level executeRaw fast path
					// so that `cd X && ./my-script.sh` behaves the same as
					// `./my-script.sh` when ./my-script.sh is in extra_commands.
					if s.getBareExtraCommands()[cmdName] {
						if useOSSandbox {
							return s.execInWorker(ctx, args)
						}
						return interp.DefaultExecHandler(-1)(ctx, args)
					}
					if !s.getConfig().LocalBinaryExecution.IsEnabled() {
						return fmt.Errorf("direct execution of %q is not allowed", cmdName)
					}
					// Check if file is a compiled binary (ELF/Mach-O)
					hc := interp.HandlerCtx(ctx)
					path := absPath(cmdName, hc.Dir)
					if isBinaryExecutable(path) {
						if useOSSandbox {
							return s.execInWorker(ctx, args)
						}
						return interp.DefaultExecHandler(-1)(ctx, args)
					}
					return s.executeScript(ctx, args)
				}
			}
			if useOSSandbox {
				return s.execInWorker(ctx, args)
			}
			return interp.DefaultExecHandler(-1)(ctx, args)
		}),
	}
}
