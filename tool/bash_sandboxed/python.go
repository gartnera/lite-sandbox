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
			// Everything after the code is sys.argv, which monty does not
			// provide (see the sys.argv check below).
			if extra := rest[i+2:]; len(extra) > 0 {
				return nil, errNoScriptArgs()
			}
			return &pythonInvocation{code: rest[i+1], name: "-c"}, nil

		case arg == "-m":
			return nil, fmt.Errorf("python: -m is not supported by this Python interpreter (monty): " +
				"it has no importable module path. Run the code directly with -c or a script file, " +
				"or use `uv run` for real CPython")

		case arg == "-":
			if extra := rest[i+1:]; len(extra) > 0 {
				return nil, errNoScriptArgs()
			}
			data, err := io.ReadAll(stdin)
			if err != nil {
				return nil, fmt.Errorf("python: cannot read program from stdin: %w", err)
			}
			return &pythonInvocation{code: string(data), name: "<stdin>"}, nil

		// Flags that only affect a real CPython process (buffering, isolation,
		// bytecode) have nothing to configure here. Accept and ignore them so
		// habitual invocations like `python3 -u script.py` still run.
		case arg == "-u", arg == "-B", arg == "-E", arg == "-I", arg == "-s", arg == "-S", arg == "-q":

		case arg == "-V", arg == "--version":
			return &pythonInvocation{code: montyVersionProgram, name: "-c"}, nil

		case strings.HasPrefix(arg, "-"):
			return nil, fmt.Errorf("python: flag %q is not supported in the sandbox", arg)

		default:
			if extra := rest[i+1:]; len(extra) > 0 {
				return nil, errNoScriptArgs()
			}
			code, err := readScript(arg)
			if err != nil {
				return nil, err
			}
			return &pythonInvocation{code: code, name: arg}, nil
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

// errNoScriptArgs explains the one argv shape that looks ordinary but cannot
// work: monty exposes no sys.argv, so arguments after the program would be
// silently invisible to it. Failing loudly beats a script that reads an empty
// argv and does the wrong thing.
func errNoScriptArgs() error {
	return fmt.Errorf("python: passing arguments to the program is not supported by this Python " +
		"interpreter (monty): it provides no sys.argv, so the arguments would be silently ignored. " +
		"Inline the values with -c, or use `uv run` for real CPython")
}

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
	_, err = runner.Execute(ctx, inv.code, nil,
		montygo.WithPrintFunc(func(out string) { io.WriteString(hc.Stdout, out) }),
		montygo.WithOsCallFunc(s.montyOsCall(fs)),
		montygo.WithLimits(limits),
	)
	if err != nil {
		return pythonRunError(err, inv.name, hc.Stderr)
	}
	// monty returns the value of the last expression. CPython does not print it
	// when running a script, so neither do we.
	return nil
}

// pythonRunError reports a failed run the way an interpreter would: the
// traceback on stderr and a non-zero exit status, so `python3 x.py || echo
// failed` behaves as an agent expects.
func pythonRunError(err error, progName string, stderr io.Writer) error {
	var montyErr *montygo.MontyError
	if !errors.As(err, &montyErr) {
		// Not a Python-level failure: a cancelled context, a denied OS call, or
		// a wasm-level fault. Surface it as a command error rather than a
		// traceback, since there is no Python frame to blame. A denial reads
		// like the equivalent bash denial once the bridge's own framing is off.
		return fmt.Errorf("python: %s", stripOsCallWrapper(err.Error()))
	}
	msg := strings.TrimRight(montyErr.Message, "\n")
	// monty always labels frames "script.py"; use the name the program was
	// actually invoked under so the traceback points somewhere real.
	if progName != "" && progName != "-c" {
		msg = strings.ReplaceAll(msg, `File "script.py"`, fmt.Sprintf("File %q", progName))
	}
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

// pythonLimitationNote returns the explanation to append when a traceback is
// really monty telling the agent it is not CPython. Without it the failure
// reads as a broken environment and the next move is `pip install`, which
// cannot work here either.
func pythonLimitationNote(traceback string) string {
	switch {
	case strings.Contains(traceback, "ModuleNotFoundError"), strings.Contains(traceback, "ImportError"):
		return "\nnote: this is monty, a sandboxed Python interpreter embedded in lite-sandbox, " +
			"not CPython. Third-party packages cannot be installed or imported — pip and venv are " +
			"not available. The standard library is partial: os, pathlib, json, re, math, datetime, " +
			"sys, typing, asyncio, dataclasses, collections, functools, itertools and base64 work.\n" +
			"If you need a real interpreter or a third-party package, use `uv run` " +
			"(enable it with `lite-sandbox config runtimes uv enable`)."
	case strings.Contains(traceback, "TimeoutError"):
		return "\nnote: the sandbox stopped the program at the bash tool's command timeout. " +
			"Long-running work belongs in a background command."
	case strings.Contains(traceback, "exceeded max suspensions"):
		return fmt.Sprintf("\nnote: the program made more than %d filesystem operations, "+
			"the sandbox's limit for one python run. Batch the work or split it across runs.",
			montyMaxSuspensions)
	case strings.Contains(traceback, "MemoryError"):
		return "\nnote: the sandbox caps monty's heap. Process the data in chunks, " +
			"or use `uv run` for real CPython."
	case isMontySyntaxLimitation(traceback):
		return "\nnote: this is monty, a sandboxed Python interpreter embedded in lite-sandbox, " +
			"not CPython, and it implements a subset of the language. Class inheritance, super(), " +
			"@property/@classmethod/@staticmethod, generators, match statements and del are among " +
			"the things it does not support. Rewrite without them, or use `uv run` for real CPython."
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
