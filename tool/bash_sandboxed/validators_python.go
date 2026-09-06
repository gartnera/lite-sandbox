package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// validatePythonArgs gates `python`/`python3` on the Python runtime switch and
// rejects the argv shapes monty cannot serve, early and with a message that
// names the real reason.
//
// Unlike the other runtimes this one defaults to ON: there is nothing to detect
// or install (the interpreter is a wasm blob embedded in the binary), and monty
// is more contained than the commands already on the whitelist — it has no
// network, no environment, no ambient filesystem, and every file it touches
// goes through the sandbox's own path boundary. The switch exists so it can be
// turned off, not because it needs to be turned on.
//
// This is a static pass. executePython re-derives everything it needs from the
// expanded argv, and the runtime layer re-runs this validator (python is not in
// runtimeValidatorSkip), so nothing here is load-bearing for security; it is
// here to fail fast with a good message.
func validatePythonArgs(s *Sandbox, args []*syntax.Word) error {
	cfg := s.getConfig()
	if cfg.Runtimes != nil && !cfg.Runtimes.Python.PythonEnabled() {
		return fmt.Errorf("command %q is not allowed (runtimes.python.enabled is disabled)", wordOrDefault(args, 0, "python"))
	}

	lits := wordLits(args)
	for i := 1; i < len(lits); i++ {
		arg := lits[i]
		switch {
		case arg == "":
			// A non-literal word (a variable, a command substitution): its
			// value is only known after expansion, so leave it to the runtime
			// pass, which sees the real argv.
			return nil
		case arg == "-c":
			// The code itself is not inspected here — it is not shell, and
			// monty is what confines it. Anything past it is sys.argv.
			return nil
		case arg == "-m":
			// py_compile is served as a syntax check (see checkPythonSyntax);
			// no other module is importable. The file arguments after it are
			// path-checked by the usual passes.
			if i+1 < len(lits) && lits[i+1] == "py_compile" {
				return nil
			}
			if i+1 < len(lits) && lits[i+1] == "" {
				return nil // a non-literal module name; the runtime pass sees it
			}
			return fmt.Errorf("python -m is not supported by this Python interpreter (monty): " +
				"it has no importable module path. Only `-m py_compile` is served (as a syntax " +
				"check). Run the code directly with -c or a script file, or use `uv run` for real CPython")
		case arg == "-", !strings.HasPrefix(arg, "-"):
			// The program (stdin or a script file); everything after it is
			// sys.argv, not something python itself interprets.
			return nil
		case pythonIgnoredFlags[arg]:
		case arg == "-V", arg == "--version":
			return nil
		default:
			return fmt.Errorf("python flag %q is not supported in the sandbox", arg)
		}
	}
	return nil
}

// pythonIgnoredFlags are CPython process flags with nothing to configure in an
// embedded interpreter (buffering, bytecode writing, site/env isolation). They
// are accepted and ignored so habitual invocations still run. Kept in sync with
// the same list in parsePythonArgs.
var pythonIgnoredFlags = map[string]bool{
	"-u": true, "-B": true, "-E": true, "-I": true,
	"-s": true, "-S": true, "-q": true,
}

// wordOrDefault returns the literal text of the word at index i, or def when it
// is absent or not a plain literal.
func wordOrDefault(args []*syntax.Word, i int, def string) string {
	if i >= len(args) {
		return def
	}
	if lit := args[i].Lit(); lit != "" {
		return lit
	}
	return def
}

// pythonNonPathArgIndices returns the argument indices that are Python source
// rather than file paths, so the generic path checker skips them.
//
// The code after -c routinely contains "/" — in a string literal, a regex, a
// comment — which is enough for looksLikePath to treat the whole program as a
// path and reject it for resolving outside the allowed directories. The code is
// not a path and monty is what confines it, so the only path argument python
// ever has is the script file, which stays checked.
//
// This mirrors the same exemption sed and grep have for their script and
// pattern arguments.
func pythonNonPathArgIndices(args []string) map[int]bool {
	skip := map[int]bool{}
	for i := 1; i < len(args); i++ {
		if args[i] == "-c" && i+1 < len(args) {
			skip[i+1] = true
			// Everything after the code belongs to the program, not to python.
			for j := i + 2; j < len(args); j++ {
				skip[j] = true
			}
			return skip
		}
	}
	return skip
}
