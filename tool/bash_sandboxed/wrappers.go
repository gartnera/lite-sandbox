package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Command wrappers (xargs, env, timeout, nice, nohup, setsid, stdbuf) exec
// the command they are given as a native child that never re-enters the
// sandbox interpreter, so the sandbox has to find that command in the
// wrapper's own argv and validate it as if it had been typed. Finding it is
// one walker, wrapperSpec.commandIndex, driven by a description of each
// wrapper's options (wrapperSpecs). The AST argument validators and the
// []string unwrapper used for path checks and unsandboxed routing
// (unwrapWrapperArgs) both go through it, which is what guarantees
// validation, path checks, and routing agree on what a wrapper runs.
//
// The walker has to land where the wrapper itself does: an index past the
// real command lets that command run unchecked (an `xargs --max-args 1 CMD`
// read as running "1" took CMD past the deny list). Every wrapper here parses
// its options with getopt in "+" mode — options end at the first operand —
// so the walker follows getopt: short options cluster (-0n1), a value-taking
// one takes the rest of its word or the next word, a long one may be
// abbreviated to any unambiguous prefix, and "--" ends the options. Where
// GNU and BSD spellings of a wrapper differ, its spec lists the union of the
// options that take a value: an option the platform's wrapper does not have
// makes it fail before it runs anything.

const (
	// wrapperNoCommand means the invocation wraps no command at all (e.g.
	// `env FOO=bar`, `xargs` with its default echo, `timeout 5`).
	wrapperNoCommand = -1
	// wrapperRejected means the invocation uses an option that makes the
	// wrapped command unknowable and is therefore refused outright
	// (env -S/--split-string).
	wrapperRejected = -2
)

// wrapperSpec describes how a wrapper parses its own arguments.
type wrapperSpec struct {
	// opts is the wrapper's option table; it is read in "+" mode,
	// stopping at the first operand.
	opts optSpec
	// rejected lists options (by name) that build the command from a
	// string, so it cannot be known: commandIndex returns wrapperRejected.
	rejected []string
	// dashIsOption makes a lone "-" an option (env's spelling of -i)
	// rather than the command.
	dashIsOption bool
	// assignments makes the operands that follow the options and contain
	// "=" variable assignments rather than the command (env NAME=VALUE).
	// Both env(1)s take any operand with a "=" in it, not just a valid
	// identifier (env a-b=1 cmd runs cmd).
	assignments bool
	// operands is the number of operands before the command (timeout's
	// DURATION).
	operands int
}

// commandIndex returns the index of the command a wrapper invocation runs
// (lits[0] is the wrapper), wrapperNoCommand when it runs none, or
// wrapperRejected for a rejected option. assignLits is consulted only for the
// assignment test, which needs the maximal literal prefix of a word (so
// FOO=$BAR still reads as one) where every option test keeps to the strict
// literal; callers with already-expanded strings pass lits for both.
func (sp wrapperSpec) commandIndex(lits, assignLits []string) int {
	opts := sp.opts
	opts.stopAtOperand = true
	p := parsedArgs{args: lits}
	for start := 1; ; {
		n := len(p.operands)
		opts.scanFrom(&p, start)
		if !sp.dashIsOption || p.dashdash || len(p.operands) == n || lits[p.operands[n]] != "-" {
			break
		}
		start = p.operands[n] + 1
		p.operands = p.operands[:n]
	}
	if p.has(sp.rejected...) {
		return wrapperRejected
	}
	i := len(lits)
	if len(p.operands) > 0 {
		i = p.operands[0]
	}
	if sp.assignments {
		for i < len(lits) && strings.Contains(assignLits[i], "=") {
			i++
		}
	}
	i += sp.operands
	if i >= len(lits) {
		return wrapperNoCommand
	}
	return i
}

// wrapperSpecs describes each wrapper's options (see wrapperSpec).
var wrapperSpecs = map[string]wrapperSpec{
	// GNU xargs "+0a:E:e::I:i::L:l::n:oprP:s:txd:", BSD xargs
	// "+0E:I:J:L:n:oP:pR:S:s:rtx". -e, -i, and -l take an optional value,
	// which getopt only reads attached.
	"xargs": {opts: optSpec{
		short:    "adEIJLnPRSs",
		long:     []string{"arg-file", "delimiter", "max-lines", "max-args", "max-procs", "max-chars", "process-slot-var"},
		optional: "eil",
		flags: []string{
			"null", "eof", "replace", "open-tty", "interactive", "no-run-if-empty",
			"show-limits", "verbose", "exit", "help", "version",
		},
		alias: map[string]string{"replace": "i"},
	}},
	// GNU env "+C:iS:u:v0" (newer releases add -a/--argv0), BSD env
	// "-0C:iL:P:S:U:u:v": -P names the directories the command is looked
	// up in, -L and -U a user.
	"env": {
		opts: optSpec{
			short: "aCLPSUu",
			long:  []string{"argv0", "chdir", "split-string", "unset"},
			flags: []string{
				"ignore-environment", "null", "block-signal", "default-signal", "ignore-signal",
				"list-signal-handling", "debug", "help", "version",
			},
			alias: map[string]string{"split-string": "S"},
		},
		rejected:     []string{"S"},
		dashIsOption: true,
		assignments:  true,
	},
	// GNU timeout "+fk:ps:v", then DURATION.
	"timeout": {
		opts: optSpec{
			short: "ks",
			long:  []string{"kill-after", "signal"},
			flags: []string{"foreground", "preserve-status", "verbose", "help", "version"},
		},
		operands: 1,
	},
	// GNU nice "+n:", BSD nice "n:". A legacy `nice -10` is an option
	// cluster with no value-taking letter, so it is skipped too.
	"nice":  {opts: optSpec{short: "n", long: []string{"adjustment"}, flags: []string{"help", "version"}}},
	"nohup": {opts: optSpec{flags: []string{"help", "version"}}},
	// util-linux setsid "+Vhcfw".
	"setsid": {opts: optSpec{flags: []string{"ctty", "fork", "wait", "help", "version"}}},
	// GNU stdbuf "+i:o:e:".
	"stdbuf": {opts: optSpec{short: "ioe", long: []string{"input", "output", "error"}, flags: []string{"help", "version"}}},
}

// wrapperCommandIndex is wrapperSpecs[lits[0]].commandIndex over
// already-expanded (or strictly literal) words.
func wrapperCommandIndex(lits []string) int {
	return wrapperSpecs[lits[0]].commandIndex(lits, lits)
}

// errEnvSplitString is returned when env is invoked with -S/--split-string.
// That option builds a whole argv from a single string (intended for shebang
// lines), which would smuggle an otherwise-blocked command past validation, so
// it is rejected outright.
func errEnvSplitString() error {
	return fmt.Errorf("env -S/--split-string is not allowed (it builds a command from a string, bypassing validation)")
}

// validateWrapperArgs validates a wrapper by recursively validating the
// command it runs against the whitelist. With no command there is nothing to
// run: xargs defaults to echo, env prints the environment, and the rest fail
// or print.
func validateWrapperArgs(s *Sandbox, args []*syntax.Word) error {
	lits := wordLits(args)
	// wordLeadingLits handles env assignment values that are non-literal
	// expansions (e.g. FOO=$BAR), whose Lit() would otherwise be empty.
	assignLits := wordLeadingLits(args)
	idx := wrapperSpecs[lits[0]].commandIndex(lits, assignLits)
	if idx == wrapperRejected {
		return errEnvSplitString()
	}
	if idx < 0 {
		return nil
	}
	switch lits[0] {
	case "env":
		if err := validateEnvAssignments(s, args, assignLits, idx); err != nil {
			return err
		}
	case "xargs":
		if err := validateSubCommand(s, args[idx:]); err != nil {
			return err
		}
		return validateSSHUnderXargs(s, args[:idx], args[idx:])
	}
	return validateSubCommand(s, args[idx:])
}

// validateEnvAssignments holds env's NAME=VALUE operands (those before the
// command at idx) to the same blocked variables as a shell assignment (FOO=bar
// cmd), which they are equivalent to.
func validateEnvAssignments(s *Sandbox, args []*syntax.Word, assignLits []string, idx int) error {
	for i := idx - 1; i > 0 && strings.Contains(assignLits[i], "="); i-- {
		name, val, _ := strings.Cut(assignLits[i], "=")
		if err := s.checkEnvAssign(name, val); err != nil {
			return err
		}
		// The sandbox drops $HOME from rsync's environment (stripRsyncHome),
		// and env would set it again: popt reads aliases from $HOME/.popt.
		if name == "HOME" && rsyncInvocation(wordLits(args[idx:])) != nil {
			return fmt.Errorf("env HOME=... rsync is not allowed: rsync reads option aliases from $HOME/.popt, which can add any option")
		}
	}
	return nil
}

// wordLeadingLit returns the maximal literal prefix of a word: the text of its
// leading *syntax.Lit parts up to the first non-literal part. For "FOO=$BAR"
// this is "FOO="; for "$CMD" it is "". Used to recognize env NAME=VALUE
// operands even when the VALUE is a non-literal expansion.
func wordLeadingLit(w *syntax.Word) string {
	var b strings.Builder
	for _, part := range w.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			break
		}
		b.WriteString(lit.Value)
	}
	return b.String()
}

// wordLeadingLits maps wordLeadingLit over words.
func wordLeadingLits(words []*syntax.Word) []string {
	lits := make([]string, len(words))
	for i, w := range words {
		lits[i] = wordLeadingLit(w)
	}
	return lits
}

// unwrapWrapperArgs repeatedly strips leading wrapper commands (timeout, env,
// xcrun, xargs, ...) to expose the real command being run, so path checks and
// unsandboxed routing evaluate the wrapped command rather than the wrapper.
// Returns the innermost args (command name first); returns args unchanged
// when there is no wrapper, or nil when a wrapper has no wrapped command. Each
// step drops at least the wrapper token, so this terminates; the depth guard
// is belt-and-suspenders.
func unwrapWrapperArgs(args []string) []string {
	for guard := 0; guard <= maxBashDepth && len(args) > 0; guard++ {
		unwrap := lookupCommand(args[0]).unwrap
		if unwrap == nil {
			return args
		}
		inner := unwrap(args)
		if len(inner) == 0 {
			return nil
		}
		args = inner
	}
	return args
}

// unwrapWrapper returns the command a wrapperSpecs wrapper runs, using the
// same walker as validateWrapperArgs.
func unwrapWrapper(args []string) []string {
	return sliceWrappedCommand(args, wrapperCommandIndex(args))
}

// sliceWrappedCommand turns a walker result into the wrapped command's args,
// or nil when there is no command (or the invocation is rejected).
func sliceWrappedCommand(args []string, idx int) []string {
	if idx < 0 {
		return nil
	}
	return args[idx:]
}
