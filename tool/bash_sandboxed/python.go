package bash_sandboxed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	montygo "github.com/fugue-labs/monty-go"
	"mvdan.cc/sh/v3/interp"
)

// python is not a real interpreter here. `python` / `python3` are dispatched to
// monty (https://github.com/pydantic/monty), a Python interpreter compiled to
// WebAssembly and embedded in this process, so an agent's Python runs in a real
// sandbox instead of being rejected outright. monty performs no I/O of its own:
// every filesystem touch comes back to the host as an OS call, authorized in
// python_oscall.go against the same read/write path sets that bound bash.
//
// The tradeoff is that monty implements a subset of Python. Third-party imports
// are impossible (there is no package directory to import from) and parts of the
// language are missing. Because the alias is transparent, an agent that hits one
// of those walls gets an error it did not expect, so failures are rewritten
// below to name monty and point at `uv run` for real CPython.

const (
	// montyMaxMemoryBytes caps the interpreter's heap. monty reports a
	// MemoryError to the script rather than growing without bound.
	montyMaxMemoryBytes = 256 << 20

	// montyMaxRecursionDepth mirrors CPython's default recursion limit.
	montyMaxRecursionDepth = 1000

	// montyMaxSuspensions bounds how many OS calls one run may make. Every
	// filesystem operation is a suspension, so the budget has to be large
	// enough for real work (walking a tree, rewriting a few hundred files)
	// while still stopping a script that loops on host calls. Host-call time
	// does not advance monty's own duration accounting, which is why this
	// backstop exists separately from the command timeout.
	montyMaxSuspensions = 50_000
)

// montyRunner returns the process-wide compiled monty runtime, building it on
// first use. Compiling the wasm module costs ~2s, so it is deliberately lazy:
// a sandbox that never runs Python never pays for it. Runner.Execute builds a
// fresh isolated instance per call, so one Runner is safe to share across
// concurrent invocations.
//
// It takes its own mutex rather than the sandbox's config lock, so the one-off
// compile does not block every getConfig in the process while it runs.
func (s *Sandbox) montyRunner() (*montygo.Runner, error) {
	s.montyMu.Lock()
	defer s.montyMu.Unlock()
	if s.monty != nil {
		return s.monty, nil
	}
	r, err := montygo.New()
	if err != nil {
		return nil, fmt.Errorf("python: cannot start the monty interpreter: %w", err)
	}
	s.monty = r
	return r, nil
}

// pythonInvocation is the result of parsing a python argv.
type pythonInvocation struct {
	code string
	// name is what the traceback should call the program, matching CPython:
	// the script path, or "-c" / "<stdin>" when there is no file.
	name string
	// argv is what the program sees as sys.argv, following CPython: element 0
	// is the script path (or "-c" / "-"), the rest are its arguments. monty has
	// no sys.argv of its own; see python_argv.go for how it is supplied.
	argv []string
	// syntaxCheck holds the files to syntax-check instead of running anything,
	// set by `-m py_compile`. See checkPythonSyntax.
	syntaxCheck []string
}

// parsePythonArgs turns a python/python3 argv into the program to run. It
// resolves -c inline, marks a script path for reading, and rejects the argv
// shapes monty cannot serve. readScript is called for a script-file argument so
// the caller can read it through the path boundary; it is not called for -c or
// stdin.
func parsePythonArgs(args []string, stdin io.Reader, readScript func(path string) (string, error)) (*pythonInvocation, error) {
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		arg := rest[i]
		switch {
		case arg == "-c":
			if i+1 >= len(rest) {
				return nil, fmt.Errorf("python: argument to -c is missing")
			}
			return &pythonInvocation{
				code: rest[i+1],
				name: "-c",
				argv: append([]string{"-c"}, rest[i+2:]...),
			}, nil

		case arg == "-m":
			if i+1 >= len(rest) {
				return nil, fmt.Errorf("python: argument to -m is missing")
			}
			// py_compile is the one module worth serving: agents reach for it
			// to check a file's syntax, and monty can answer that question
			// exactly (see checkPythonSyntax). Nothing else is importable.
			if rest[i+1] == "py_compile" {
				files := rest[i+2:]
				if len(files) == 0 {
					return nil, fmt.Errorf("python: -m py_compile needs at least one file to check")
				}
				return &pythonInvocation{name: "py_compile", syntaxCheck: files}, nil
			}
			return nil, fmt.Errorf("python: -m %s is not available: %s It has no importable "+
				"module path, and only `-m py_compile` is served (as a syntax check). Run code "+
				"directly with -c or a script file, or:\n%s", rest[i+1], pythonIsMontyNote, pythonEscapeHatches)

		case arg == "-":
			// The interpreter leaves Stdin nil when nothing is piped or
			// redirected in, so a bare `python3 -` must not reach io.ReadAll.
			if stdin == nil {
				return nil, fmt.Errorf("python: -  reads the program from stdin, but nothing is piped in. " +
					"Pipe a program (echo '...' | python3 -), pass a script file, or use -c")
			}
			data, err := io.ReadAll(stdin)
			if err != nil {
				return nil, fmt.Errorf("python: cannot read program from stdin: %w", err)
			}
			return &pythonInvocation{
				code: string(data),
				name: "<stdin>",
				argv: append([]string{"-"}, rest[i+1:]...),
			}, nil

		// Flags that only affect a real CPython process (buffering, isolation,
		// bytecode) have nothing to configure here. Accept and ignore them so
		// habitual invocations like `python3 -u script.py` still run.
		case arg == "-u", arg == "-B", arg == "-E", arg == "-I", arg == "-s", arg == "-S", arg == "-q":

		case arg == "-V", arg == "--version":
			return &pythonInvocation{code: montyVersionProgram, name: "-c", argv: []string{"-c"}}, nil

		case strings.HasPrefix(arg, "-"):
			return nil, fmt.Errorf("python: flag %q is not supported in the sandbox", arg)

		default:
			code, err := readScript(arg)
			if err != nil {
				return nil, err
			}
			return &pythonInvocation{
				code: code,
				name: arg,
				argv: append([]string{arg}, rest[i+1:]...),
			}, nil
		}
	}
	// Bare `python3`, or only ignorable flags: CPython would start a REPL.
	return nil, fmt.Errorf("python: no program given, and the interactive interpreter is not available " +
		"in the sandbox. Pass a script file or use -c")
}

// montyVersionProgram backs `python3 -V`. monty reports its own version through
// the sys module, and saying which interpreter this is up front is worth more
// than a bare version number.
const montyVersionProgram = `import sys
print("Python " + sys.version + " [lite-sandbox]")`

// executePython runs a python/python3 invocation on the embedded monty
// interpreter. It is dispatched from the ExecHandler, so it never reaches the
// OS sandbox worker: monty is in-process wasm and cannot touch the filesystem
// on its own, and the host-side operations its OS calls trigger are confined by
// os.Root instead (see python_oscall.go).
func (s *Sandbox) executePython(ctx context.Context, args []string, sets resolvedPathSets) error {
	hc := interp.HandlerCtx(ctx)

	fs := newMontyFS(hc.Dir, sets)
	defer fs.close()

	inv, err := parsePythonArgs(args, hc.Stdin, func(path string) (string, error) {
		// A script file is a file access like any other: it answers to the
		// read boundary before a line of it is interpreted.
		root, rel, err := fs.authorize(path, false)
		if err != nil {
			return "", fmt.Errorf("python: %w", err)
		}
		data, err := root.ReadFile(rel)
		if err != nil {
			return "", fmt.Errorf("python: can't open file %s: %v", path, cleanFSError(err, path))
		}
		return string(data), nil
	})
	if err != nil {
		fmt.Fprintln(hc.Stderr, err.Error())
		return interp.ExitStatus(2)
	}

	runner, err := s.montyRunner()
	if err != nil {
		return err
	}

	if len(inv.syntaxCheck) > 0 {
		return s.checkPythonSyntax(ctx, runner, fs, inv.syntaxCheck)
	}

	// The command timeout arrives as a deadline on ctx and is what actually
	// stops a runaway script: wazero closes the module when it fires, which
	// works whether the interpreter is computing or parked in a host call.
	// MaxDuration is set from the same deadline purely for the error message —
	// monty reports its own TimeoutError, which says far more than the wasm
	// runtime's "module closed with context deadline exceeded". It is a
	// slightly shorter fuse so monty usually gets to raise it first.
	limits := montygo.Limits{
		MaxMemoryBytes:    montyMaxMemoryBytes,
		MaxRecursionDepth: montyMaxRecursionDepth,
		MaxSuspensions:    montyMaxSuspensions,
	}
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining > 0 {
			limits.MaxDuration = remaining - remaining/20
		}
	}
	// monty has no sys.argv, so it is supplied by a prologue when the program
	// asks for it; lineOffset is how far that shifts the program's own line
	// numbering. See python_argv.go.
	code, lineOffset := applyArgvShim(inv.code, inv.argv)

	_, err = runner.Execute(ctx, code, nil,
		montygo.WithPrintFunc(func(out string) { io.WriteString(hc.Stdout, out) }),
		montygo.WithOsCallFunc(s.montyOsCall(fs)),
		montygo.WithLimits(limits),
	)
	if err != nil {
		return pythonRunError(err, inv.name, lineOffset, hc.Stderr)
	}
	// monty returns the value of the last expression. CPython does not print it
	// when running a script, so neither do we.
	return nil
}

// pythonRunError reports a failed run the way an interpreter would: the
// traceback on stderr and a non-zero exit status, so `python3 x.py || echo
// failed` behaves as an agent expects.
func pythonRunError(err error, progName string, lineOffset int, stderr io.Writer) error {
	var montyErr *montygo.MontyError
	if !errors.As(err, &montyErr) {
		// Not a Python-level failure: a cancelled context, a denied OS call, or
		// a wasm-level fault. Surface it as a command error rather than a
		// traceback, since there is no Python frame to blame. A denial reads
		// like the equivalent bash denial once the bridge's own framing is off.
		return fmt.Errorf("python: %s", stripOsCallWrapper(err.Error()))
	}
	msg := shiftTracebackLines(strings.TrimRight(montyErr.Message, "\n"), lineOffset)
	// monty always labels frames "script.py"; use the name the program was
	// actually invoked under so the traceback points somewhere real. CPython
	// spells the two nameless cases "<string>" and "<stdin>".
	frameName := progName
	switch progName {
	case "":
		frameName = "script.py"
	case "-c":
		frameName = "<string>"
	}
	msg = strings.ReplaceAll(msg, `File "script.py"`, fmt.Sprintf("File %q", frameName))
	fmt.Fprintln(stderr, msg)
	if note := pythonLimitationNote(msg); note != "" {
		fmt.Fprintln(stderr, note)
	}
	return interp.ExitStatus(1)
}

// stripOsCallWrapper removes the bridge's framing from an error raised by the
// OS-call handler. montygo reports these as
// `montygo: OS call "Path.read_text" failed: <our message>`; the agent needs
// our message, not the plumbing that carried it.
func stripOsCallWrapper(msg string) string {
	const prefix = "montygo: OS call "
	rest, ok := strings.CutPrefix(msg, prefix)
	if !ok {
		return msg
	}
	// Skip the quoted function name and the fixed " failed: " that follows it.
	if _, after, found := strings.Cut(rest, "\" failed: "); found {
		return after
	}
	return msg
}

// pythonEscapeHatches is appended to every message that reports a monty
// limitation. An agent that hits one of these needs to know two things it
// cannot guess: that `python3` here is not CPython, and exactly how to get the
// real one. Without the second half the next move is `pip install`, which
// cannot work either.
const pythonEscapeHatches = "To run the real python on this machine instead:\n" +
	"  lite-sandbox config extra-commands add python3\n" +
	"  (python then bypasses sandbox command validation, like any extra_commands entry)\n" +
	"Or run real CPython under uv, which stays sandboxed:\n" +
	"  lite-sandbox config runtimes uv enable   # then: uv run script.py\n" +
	"To turn the built-in interpreter off entirely:\n" +
	"  lite-sandbox config runtimes montypython disable"

// pythonIsMontyNote names the interpreter. Kept separate from the escape
// hatches so a message can lead with whichever half fits its failure.
const pythonIsMontyNote = "note: `python` here is monty, a sandboxed Python interpreter built into " +
	"lite-sandbox, not CPython."

// pythonLimitationNote returns the explanation to append when a traceback is
// really monty telling the agent it is not CPython. Without it the failure
// reads as a broken environment and the next move is `pip install`, which
// cannot work here either.
func pythonLimitationNote(traceback string) string {
	switch {
	case strings.Contains(traceback, "ModuleNotFoundError"), strings.Contains(traceback, "ImportError"):
		return "\n" + pythonIsMontyNote + " Third-party packages cannot be installed or " +
			"imported — pip and venv do not exist here. The standard library is partial: os, " +
			"pathlib, json, re, math, datetime, sys, typing, asyncio, dataclasses, collections, " +
			"functools, itertools and base64 work.\n" + pythonEscapeHatches
	case strings.Contains(traceback, "TimeoutError"):
		return "\nnote: the sandbox stopped the program at the bash tool's command timeout. " +
			"Long-running work belongs in a background command."
	case strings.Contains(traceback, "exceeded max suspensions"):
		return fmt.Sprintf("\nnote: the program made more than %d filesystem operations, "+
			"the sandbox's limit for one python run. Batch the work or split it across runs.",
			montyMaxSuspensions)
	case strings.Contains(traceback, "MemoryError"):
		return "\nnote: the sandbox caps the built-in interpreter's heap. Process the data in " +
			"chunks, or:\n" + pythonEscapeHatches
	case strings.Contains(traceback, "Internal error in monty"):
		return "\n" + pythonIsMontyNote + " It hit a limit of its own implementation rather " +
			"than a bug in this program. Try a simpler formulation, or:\n" + pythonEscapeHatches
	case isMontySyntaxLimitation(traceback):
		return "\n" + pythonIsMontyNote + " It implements a subset of the language: class " +
			"inheritance, super(), @property/@classmethod/@staticmethod, generators, match " +
			"statements and del are among the things it does not support. Rewrite without them, " +
			"or:\n" + pythonEscapeHatches
	}
	return ""
}

// isMontySyntaxLimitation recognises the failures that come from monty's subset
// of the language rather than from a genuine mistake in the script.
func isMontySyntaxLimitation(traceback string) bool {
	for _, marker := range []string{
		"not supported", "unsupported", "not implemented", "NotImplementedError",
	} {
		if strings.Contains(traceback, marker) {
			return true
		}
	}
	return false
}

// pythonExplicitlyRequested reports whether this python invocation matches an
// explicit extra_commands or unsandboxed_commands entry, in which case the user
// has asked for the real interpreter on PATH rather than the embedded monty
// one. monty implements a subset of Python and cannot import third-party
// packages, so naming python in those lists is the supported way to opt back
// into full CPython — with the loss of validation those lists always imply.
//
// A bare entry ("python3") covers every invocation. A subcommand-restricted
// entry ("python3 manage.py") covers only invocations whose leading non-flag
// arguments match, so the rest still run on monty. unsandboxed_commands entries
// are merged into the same maps by UpdateConfig, so both are handled here.
func (s *Sandbox) pythonExplicitlyRequested(args []string) bool {
	if len(args) == 0 {
		return false
	}
	cmdName := args[0]
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.bareExtraCommands[cmdName] {
		return true
	}
	if restrictions, ok := s.extraSubCommands[cmdName]; ok {
		return argsMatchSubCommand(restrictions, args[1:])
	}
	return false
}

// syntaxProbe is prepended to a file being syntax-checked. monty compiles a
// whole module before executing any of it, so a syntax error anywhere is
// reported without a line running — and when the syntax is good, this first
// statement raises before the file can do anything at all. That is what makes
// `-m py_compile` a real check rather than a run.
//
// Prepending rather than indenting the source into a dummy function matters:
// re-indenting would corrupt tab-indented files and invent TabErrors that
// CPython would never report.
const syntaxProbe = `raise ValueError("` + syntaxOKMarker + `")` + "\n"

// syntaxOKMarker is the sentinel the probe raises. Nothing else in the file
// runs, so seeing it back means the file compiled.
const syntaxOKMarker = "__lite_sandbox_syntax_ok__"

// checkPythonSyntax implements `python -m py_compile FILE...`. It matches
// CPython's observable behaviour for the way agents use it: silence and a zero
// status when every file compiles, the compiler's own error and a non-zero
// status when one does not. It writes no .pyc files — monty has no bytecode
// cache, and the agent is asking "does this parse?", not for build output.
func (s *Sandbox) checkPythonSyntax(ctx context.Context, runner *montygo.Runner, fs *montyFS, files []string) error {
	hc := interp.HandlerCtx(ctx)
	for _, file := range files {
		root, rel, err := fs.authorize(file, false)
		if err != nil {
			fmt.Fprintf(hc.Stderr, "python: %s\n", stripOsCallWrapper(err.Error()))
			return interp.ExitStatus(1)
		}
		src, err := root.ReadFile(rel)
		if err != nil {
			fmt.Fprintf(hc.Stderr, "python: can't open file %s: %v\n", file, cleanFSError(err, file))
			return interp.ExitStatus(1)
		}

		_, err = runner.Execute(ctx, syntaxProbe+string(src), nil,
			// A compiling file never reaches its own code, so there is nothing
			// to print and no OS call to service. Denying them keeps a checked
			// file from having any effect at all.
			montygo.WithPrintFunc(func(string) {}),
			montygo.WithOsCallFunc(func(context.Context, *montygo.OsCall) (any, error) {
				return nil, fmt.Errorf("py_compile does not run the file")
			}),
			montygo.WithLimits(montygo.Limits{
				MaxMemoryBytes:    montyMaxMemoryBytes,
				MaxRecursionDepth: montyMaxRecursionDepth,
				MaxSuspensions:    1,
			}),
		)
		var montyErr *montygo.MontyError
		switch {
		case err == nil:
			// The probe must always raise; reaching here means monty did not
			// run it, so the answer is not trustworthy either way.
			return fmt.Errorf("python: could not check %s", file)
		case !errors.As(err, &montyErr):
			return fmt.Errorf("python: %s", stripOsCallWrapper(err.Error()))
		case strings.Contains(montyErr.Message, syntaxOKMarker):
			continue // compiled
		}
		// A real compile failure. Report it in the file's own numbering, under
		// its own name, the way the interpreter would.
		msg := shiftTracebackLines(strings.TrimRight(montyErr.Message, "\n"), 1)
		msg = strings.ReplaceAll(msg, `File "script.py"`, fmt.Sprintf("File %q", file))
		// The probe's own frame is noise for a compile error.
		msg = strings.TrimPrefix(msg, "Traceback (most recent call last):\n")
		fmt.Fprintln(hc.Stderr, msg)
		if note := pythonLimitationNote(msg); note != "" {
			fmt.Fprintln(hc.Stderr, note)
		}
		return interp.ExitStatus(1)
	}
	return nil
}

// pythonOptedOutToHost reports whether python is on the subCommandDenylist only
// by default — i.e. the user has a bare extra_commands / unsandboxed_commands
// entry for it, which is an explicit request for the host interpreter with no
// validation.
//
// The denylist exists because a wrapper spawns its child as a native process,
// so `xargs python3` would run the real CPython outside every sandbox layer.
// That reasoning does not apply once the user has asked for exactly that: a
// bare entry already lets `python3 anything` run unwrapped, so refusing the
// wrapped form protects nothing. A subcommand-restricted entry is deliberately
// not enough — its whole point is that only some invocations are trusted, and a
// wrapper's argv is not checked against that restriction.
func pythonOptedOutToHost(s *Sandbox, cmdName string) bool {
	if cmdName != "python" && cmdName != "python3" {
		return false
	}
	return s.getBareExtraCommands()[cmdName]
}
