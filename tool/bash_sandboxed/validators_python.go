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
			// monty is what confines it. Anything past it would be sys.argv.
			if i+2 < len(lits) {
				return errNoScriptArgs()
			}
			return nil
		case arg == "-m":
			return fmt.Errorf("python -m is not supported by this Python interpreter (monty): " +
				"it has no importable module path. Run the code directly with -c or a script file, " +
				"or use `uv run` for real CPython")
		case arg == "-", !strings.HasPrefix(arg, "-"):
			// The program (stdin or a script file). Anything after it would be
			// sys.argv, which monty does not provide.
			if i+1 < len(lits) {
				return errNoScriptArgs()
			}
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
