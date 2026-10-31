package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// findSubcommand locates the subcommand of a multi-command tool: the first
// argument after the command name that does not start with "-", skipping any
// global flag listed in valueFlags together with the token that follows it
// (the space form `--flag value`; the `--flag=value` form carries its own value
// and is skipped by the plain flag test, never consuming the next token).
// valueFlags is matched by exact equality and may be nil for tools whose global
// flags never take a separate value (deno).
//
// It returns the subcommand and its index in args, or ("", 0, nil) when the
// invocation has no subcommand at all (bare command, or only flags — typically
// prints help, which every caller allows). A word that is not a plain literal
// cannot be resolved statically, so it is rejected with a per-tool message;
// tool names the tool as it appears in that message.
//
// Note the skipNext test runs before the literal test, so a non-literal word in
// a value position (e.g. `go -C $DIR build`) is consumed as the flag's value
// rather than rejected — the behavior every copy of this loop had.
func findSubcommand(tool string, args []*syntax.Word, valueFlags map[string]bool) (string, int, error) {
	if len(args) < 2 {
		// bare command with no subcommand
		return "", 0, nil
	}
	skipNext := false
	for i, arg := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		lit := arg.Lit()
		if lit == "" {
			return "", 0, fmt.Errorf("%s arguments must be literal strings", tool)
		}
		// Skip global flags that take a separate value argument.
		if valueFlags[lit] {
			skipNext = true
			continue
		}
		// Skip flags (start with -)
		if strings.HasPrefix(lit, "-") {
			continue
		}
		return lit, i + 1, nil
	}
	return "", 0, nil
}

// argsAfterToken returns the arguments that follow the first argument (after
// the command name) whose literal text equals token, or nil when the token does
// not appear. Words that are not plain literals are skipped while searching.
//
// This is deliberately a plain scan for the token rather than a slice at the
// index findSubcommand reported: the two can differ when the token also appears
// earlier as a global flag's value (e.g. `go -C run run main.go`), and the scan
// is what every per-subcommand validator here has always done — it inspects a
// superset of the arguments the tool itself would treat as subcommand flags, so
// it can only be stricter.
func argsAfterToken(args []*syntax.Word, token string) []*syntax.Word {
	for i, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if lit == token {
			return args[i+2:]
		}
	}
	return nil
}

// validateRgArgs checks that rg --pre (preprocessor) references only
// whitelisted commands. --pre executes COMMAND for each file searched,
// so the command is validated recursively against the allowlist.
func validateRgArgs(s *Sandbox, args []*syntax.Word) error {
	for i := 1; i < len(args); i++ {
		text := wordText(args[i])
		if text == "" {
			continue
		}
		// --pre COMMAND (separate arg)
		if text == "--pre" {
			i++
			if i >= len(args) {
				return fmt.Errorf("rg --pre requires a command argument")
			}
			if err := validateSubCommand(s, args[i:i+1]); err != nil {
				return fmt.Errorf("rg --pre: %w", err)
			}
			continue
		}
		// --pre=COMMAND (inline)
		if strings.HasPrefix(text, "--pre=") {
			cmdName := text[len("--pre="):]
			if cmdName == "" {
				continue // empty --pre= disables preprocessing
			}
			cmdWord := &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: cmdName}}}
			if err := validateSubCommand(s, []*syntax.Word{cmdWord}); err != nil {
				return fmt.Errorf("rg --pre: %w", err)
			}
			continue
		}
	}
	return nil
}

// blockedFindFlags lists find flags that modify the filesystem or write to files.
var blockedFindFlags = map[string]string{
	"-delete":  "deletes files",
	"-fls":     "writes to a file",
	"-fprint":  "writes to a file",
	"-fprint0": "writes to a file",
	"-fprintf": "writes to a file",
}

// findExecFlags is the set of find flags that execute a subcommand.
// These are allowed but the embedded subcommand is validated recursively.
var findExecFlags = map[string]bool{
	"-exec":    true,
	"-execdir": true,
	"-ok":      true,
	"-okdir":   true,
}

// isFindExecTerminator reports whether a word's value (see wordValues) ends
// a find -exec command: find takes ";" or "+", which the shell hands it from
// \; or ';'.
func isFindExecTerminator(v string) bool {
	return v == ";" || v == "+"
}

// findAction is one action of a find expression that the validators look
// at: a -exec, -execdir, -ok, or -okdir, with the command it runs at
// [start, end) of find's argv, or a blockedFindFlags entry.
type findAction struct {
	flag       string
	start, end int
}

// findActions walks a find invocation by its words' values (vals[0] is
// "find"; see wordValues) and returns its actions in order, skipping the
// words of the commands -exec and friends run. A command with no terminator
// runs to the end.
func findActions(vals []string) []findAction {
	var out []findAction
	for i := 1; i < len(vals); i++ {
		lit := vals[i]
		if findExecFlags[lit] {
			j := i + 1
			for j < len(vals) && !isFindExecTerminator(vals[j]) {
				j++
			}
			out = append(out, findAction{flag: lit, start: i + 1, end: j})
			i = j
			continue
		}
		if _, blocked := blockedFindFlags[lit]; blocked {
			out = append(out, findAction{flag: lit})
		}
	}
	return out
}

// validateFindArgs checks that find is not called with dangerous flags.
// For -exec/-execdir/-ok/-okdir, the embedded subcommand is extracted and
// validated recursively against the command whitelist.
func validateFindArgs(s *Sandbox, args []*syntax.Word) error {
	for _, a := range findActions(wordValues(args)) {
		if reason, blocked := blockedFindFlags[a.flag]; blocked {
			return fmt.Errorf("find flag %q is not allowed: %s", a.flag, reason)
		}
		subArgs := args[a.start:a.end]
		if len(subArgs) == 0 {
			return fmt.Errorf("find %s has no command to execute", a.flag)
		}
		if err := validateSubCommand(s, subArgs); err != nil {
			return fmt.Errorf("find %s: %w", a.flag, err)
		}
		// find puts the file names where {} is (with +, several of
		// them).
		if err := validateSSHWrappedInput(s, "find "+a.flag, []string{"{}"}, subArgs); err != nil {
			return err
		}
	}
	return nil
}

// validateSubCommand validates a command name and its arguments against the
// whitelist, including any per-command argument validators. args[0] must be
// the command name. Used for recursive validation of commands embedded in
// find -exec, xargs, env, and timeout.
func validateSubCommand(s *Sandbox, args []*syntax.Word) error {
	if len(args) == 0 {
		return fmt.Errorf("empty command")
	}
	if s.remote != nil {
		return s.remote.command(s, args)
	}
	cmdName := args[0].Lit()
	if cmdName == "" {
		return tagRule(ruleStructural, "", fmt.Errorf("dynamic command names are not allowed"))
	}
	// The command deny list applies to a wrapped command exactly as it does to
	// a top-level one — a wrapper spawns its child itself, so this is the only
	// layer that sees it.
	if entry, denied := s.deniedCommandWords(cmdName, args[1:]); denied {
		return commandDeniedError(cmdName, entry)
	}
	// Nor can a wrapped command be approved: the validators here do not see
	// the call's approval, so a prompted command must run on its own.
	if entry, ok := matchCommandEntries(s.getAskCommands(), cmdName, wordLits(args[1:])); ok {
		return askWrappedError(cmdName, entry)
	}
	// A command whose safety relies on the sandbox interpreter being its
	// direct caller (commandSpec.notWrappable: bash, sh, awk, time, python)
	// would run here as a native child, with the -c script, awk program, or
	// wrapped command unvalidated. A user's bare allow of python is the
	// exception (pythonOptedOutToHost).
	if lookupCommand(cmdName).notWrappable && !pythonOptedOutToHost(s, cmdName) {
		return tagRule(ruleStructural, cmdName, fmt.Errorf("command %q is not allowed as a wrapped subcommand (find -exec, xargs, env, timeout, nice, nohup, setsid, stdbuf, xcrun)", cmdName))
	}
	extra := s.getExtraCommands()
	// The whitelist is an allowlist-only rule. A wrapped
	// command that fails them is returned tagged so the reporting site can
	// treat it as advisory in denylist/open mode; its own validator is then
	// skipped, but the wrapper's path arguments are still boundary-checked by
	// the generic path pass.
	if !s.commandWhitelisted(cmdName) && !extra[cmdName] {
		if s.enforcesAllowlist() {
			return commandNotAllowed(cmdName)
		}
		return nil
	}
	if validator, ok := s.validator(cmdName); ok {
		if err := validator(s, args); err != nil {
			return err
		}
	}
	return nil
}

// blockedArOps lists ar operation flags that are not read-only.
var blockedArOps = map[byte]string{
	'r': "replaces/inserts members",
	'd': "deletes members",
	'q': "quick appends to archive",
	'x': "extracts members",
	'm': "moves members",
	's': "creates archive index",
}

// validateArArgs ensures ar is invoked in read-only mode only.
// Only permits t (list) and p (print to stdout) operations.
func validateArArgs(_ *Sandbox, args []*syntax.Word) error {
	if len(args) < 2 {
		return fmt.Errorf("ar requires an operation argument")
	}
	// ar operation is typically the first argument (e.g., "ar t archive.a")
	// It can be with or without a leading dash.
	opArg := args[1].Lit()
	if opArg == "" {
		return fmt.Errorf("ar operation must be a literal argument")
	}
	// Strip leading dash if present
	ops := opArg
	if ops[0] == '-' {
		ops = ops[1:]
	}
	hasAllowedOp := false
	for i := 0; i < len(ops); i++ {
		if reason, blocked := blockedArOps[ops[i]]; blocked {
			return fmt.Errorf("ar operation '%c' is not allowed: %s", ops[i], reason)
		}
		if ops[i] == 't' || ops[i] == 'p' {
			hasAllowedOp = true
		}
	}
	if !hasAllowedOp {
		return fmt.Errorf("ar is only allowed with t (list) or p (print) operations")
	}
	return nil
}
