package bash_sandboxed

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gartnera/lite-sandbox/config"
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
	// wrapped command unknowable, or makes it a different file than the one
	// validated, and is therefore refused outright (env -S/--split-string,
	// -C/--chdir, -P).
	wrapperRejected = -2
)

// wrapperSpec describes how a wrapper parses its own arguments.
type wrapperSpec struct {
	// opts is the wrapper's option table; it is read in "+" mode,
	// stopping at the first operand.
	opts optSpec
	// rejected maps options (by name) that the sandbox refuses to the error
	// it reports: commandIndex returns wrapperRejected for them. They are
	// the options that build the command from a string, so it cannot be
	// known, and those that change where the command is looked up, so the
	// file the wrapper runs is not the one validation, path checks, and
	// routing resolved.
	rejected map[string]string
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
	idx, _, _ := sp.layout(lits, assignLits)
	return idx
}

// layout is commandIndex, also returning the index of the first operand
// (env's first NAME=VALUE assignment) and, for wrapperRejected, the error
// for the first rejected option.
func (sp wrapperSpec) layout(lits, assignLits []string) (idx, operands int, rejected error) {
	_, idx, operands, rejected = sp.parse(lits, assignLits)
	return idx, operands, rejected
}

// parse is layout, also returning the wrapper's options as its getopt reads
// them (env's lone "-" reported as -i).
func (sp wrapperSpec) parse(lits, assignLits []string) (p parsedArgs, idx, operands int, rejected error) {
	opts := sp.opts
	opts.stopAtOperand = true
	p = parsedArgs{args: lits}
	for start := 1; ; {
		n := len(p.operands)
		opts.scanFrom(&p, start)
		if !sp.dashIsOption || p.dashdash || len(p.operands) == n || lits[p.operands[n]] != "-" {
			break
		}
		p.opts = append(p.opts, parsedOpt{name: "i", index: p.operands[n], valueIndex: -1})
		start = p.operands[n] + 1
		p.operands = p.operands[:n]
	}
	for _, o := range p.opts {
		if msg, ok := sp.rejected[o.name]; ok {
			return p, wrapperRejected, 0, errors.New(msg)
		}
	}
	i := len(lits)
	if len(p.operands) > 0 {
		i = p.operands[0]
	}
	operands = i
	if sp.assignments {
		for i < len(lits) && strings.Contains(assignLits[i], "=") {
			i++
		}
	}
	i += sp.operands
	if i >= len(lits) {
		return p, wrapperNoCommand, operands, nil
	}
	return p, i, operands, nil
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
	//
	// -S builds the argv from a string, which would smuggle an otherwise
	// blocked command past validation. -C runs the command from another
	// directory and -P looks it up in other directories, while validation,
	// path checks, and no_sandbox routing resolve it against the shell's
	// own directory and PATH: `env -C evil ./host.sh` would run
	// evil/host.sh where ./host.sh was checked.
	"env": {
		opts: optSpec{
			short: "aCLPSUu",
			long:  []string{"argv0", "chdir", "split-string", "unset"},
			flags: []string{
				"ignore-environment", "null", "block-signal", "default-signal", "ignore-signal",
				"list-signal-handling", "debug", "help", "version",
			},
			alias: map[string]string{"split-string": "S", "chdir": "C"},
		},
		rejected: map[string]string{
			"S": "env -S/--split-string is not allowed (it builds a command from a string, bypassing validation)",
			"C": "env -C/--chdir is not allowed (the command would run from another directory than the one it was validated against; cd first instead)",
			"P": "env -P is not allowed (the command would be looked up in other directories than the one it was validated against)",
		},
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

// validateWrapperArgs validates a wrapper by recursively validating the
// command it runs against the whitelist. With no command there is nothing to
// run: xargs defaults to echo, env prints the environment, and the rest fail
// or print.
func validateWrapperArgs(s *Sandbox, args []*syntax.Word) error {
	lits := wordLits(args)
	// wordLeadingLits handles env assignment values that are non-literal
	// expansions (e.g. FOO=$BAR), whose Lit() would otherwise be empty.
	assignLits := wordLeadingLits(args)
	idx, operands, rejected := wrapperSpecs[lits[0]].layout(lits, assignLits)
	if idx == wrapperRejected {
		return rejected
	}
	if idx < 0 {
		return nil
	}
	switch lits[0] {
	case "env":
		if err := validateEnvAssignments(s, args, assignLits[operands:idx], idx); err != nil {
			return err
		}
	case "xargs":
		if err := validateSubCommand(s, args[idx:]); err != nil {
			return err
		}
		if err := validateWrapperUnderXargs(s, args[:idx], args[idx:]); err != nil {
			return err
		}
		if err := validateCommandlessWrapperUnderXargs(lits[:idx], lits[idx:]); err != nil {
			return err
		}
		return validateSSHUnderXargs(s, args[:idx], args[idx:])
	}
	return validateSubCommand(s, args[idx:])
}

// validateCommandlessWrapperUnderXargs refuses a wrapper left without a
// command under an xargs that appends its input (no replace string): the
// input would become the wrapper's command and options, which nothing
// validated (`echo curl | xargs env`). xargsOpts are xargs's own words, xargs
// included; args is the command it runs. Non-literal xargs options are
// already refused around a wrapper (validateWrapperUnderXargs).
func validateCommandlessWrapperUnderXargs(xargsOpts, args []string) error {
	if len(xargsReplaceStrings(xargsOpts)) > 0 {
		return nil
	}
	for len(args) > 0 {
		spec, ok := wrapperSpecs[args[0]]
		if !ok || args[0] == "xargs" {
			return nil
		}
		idx := spec.commandIndex(args, args)
		if idx == wrapperNoCommand {
			return fmt.Errorf("xargs: %s has no command of its own, so it would run xargs's input as one, which cannot be checked", args[0])
		}
		if idx < 0 {
			return nil
		}
		args = args[idx:]
	}
	return nil
}

// validateWrapperUnderXargs checks the replace strings of a command xargs
// runs; xargsOpts are xargs's own words before the command (xargs itself
// included), which set them. xargs puts its input where they are after
// validation, so the command is walked with validateWrappedReplaceStrings
// (none in a wrapper's own words) and checkReplacedOptions (none where the
// command, nested under wrappers and find -exec, could read it as an
// option). A replace string that is not literal could be any text, so a
// command either check looks into is refused under it.
func validateWrapperUnderXargs(s *Sandbox, xargsOpts, args []*syntax.Word) error {
	if len(args) == 0 {
		return nil
	}
	opts := make([]string, len(xargsOpts))
	for i, w := range xargsOpts {
		v, ok := wordLiteral(w)
		if !ok {
			if name := args[0].Lit(); replaceWalked(name) || replaceOptionsChecked(s, name) {
				return fmt.Errorf("xargs: %s under xargs options that are not literal is not allowed: a replace string set by them could put the input in the options of the command it runs", name)
			}
			return nil
		}
		opts[i] = v
	}
	replace := xargsReplaceStrings(opts)
	return walkReplaceStrings(s, "xargs", replace, replace, args, 0)
}

// replaceWalked reports whether validateWrappedReplaceStrings looks into a
// command: a wrapper (wrapperSpecs), xcrun, or find, whose -exec commands it
// walks.
func replaceWalked(name string) bool {
	_, ok := wrapperSpecs[name]
	return ok || name == "xcrun" || name == "find"
}

// replaceOptionsChecked reports whether checkReplacedOptions looks at a
// command's words: one with an argument validator, which an option the input
// becomes would get past. A command without one accepts any option already.
// ssh, sshpass, scp, and rsync have a finer check of their own
// (validateSSHWrappedInput), which lets the input into ssh's remote command.
func replaceOptionsChecked(s *Sandbox, name string) bool {
	if name == "ssh" || name == "sshpass" || slices.Contains(config.SSHCopyCommands, name) {
		return false
	}
	_, ok := s.validator(name)
	return ok
}

// validateWrappedReplaceStrings refuses a wrapper (wrapperSpecs, or xcrun)
// that xargs with replace strings (-I, -i, --replace, BSD -J) or find -exec
// ({}) runs with a replace string in one of the wrapper's own words before
// its command. The input is put there after validation, so it can become one
// of the wrapper's options or its command: with input "Cevil",
// `xargs -I{} env -{} ./host.sh` runs `env -Cevil ./host.sh`, which runs
// evil/host.sh where ./host.sh was validated and routed. Nested wrappers are
// walked, and so are the -exec commands of a find (with {} added to the
// replace strings). An env assignment's value may hold one (env FOO={} cmd):
// the input there stays the value. wrapper names the outer command for
// messages.
func validateWrappedReplaceStrings(s *Sandbox, wrapper string, replace []string, args []*syntax.Word) error {
	return walkReplaceStrings(s, wrapper, replace, nil, args, 0)
}

// walkReplaceStrings is validateWrappedReplaceStrings, which also runs
// checkReplacedOptions with optReplace (xargs's replace strings; find's {}
// is not among them) on every command it reaches that is not a wrapper.
func walkReplaceStrings(s *Sandbox, wrapper string, replace, optReplace []string, args []*syntax.Word, depth int) error {
	if len(args) == 0 || len(replace) == 0 || depth > maxBashDepth {
		return nil
	}
	lits := wordLits(args)
	vals := wordValues(args)
	var idx, operands int
	assignments := false
	switch name := lits[0]; name {
	case "find":
		actions := findActions(vals)
		if len(optReplace) > 0 {
			if err := checkReplacedFindOptions(wrapper, optReplace, args, actions); err != nil {
				return err
			}
		}
		withBraces := append(slices.Clone(replace), "{}")
		for _, a := range actions {
			if a.end > a.start {
				if err := walkReplaceStrings(s, wrapper, withBraces, optReplace, args[a.start:a.end], depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	case "xcrun":
		idx = xcrunCommandIndex(lits)
	default:
		spec, ok := wrapperSpecs[name]
		if !ok {
			if len(optReplace) > 0 && replaceOptionsChecked(s, name) {
				return checkReplacedOptions(wrapper, optReplace, args)
			}
			return nil
		}
		idx, operands, _ = spec.layout(lits, wordLeadingLits(args))
		assignments = spec.assignments
	}
	end := idx
	if idx < 0 {
		end = len(args)
	}
	for i := 1; i < end; i++ {
		v := vals[i]
		at := replaceIndex(v, replace)
		if at < 0 {
			continue
		}
		if assignments && i >= operands && strings.Contains(v[:at], "=") {
			continue
		}
		return fmt.Errorf("%s: %s word %q holds a replace string before the command %s runs, so the input put there could become one of its options or its command", wrapper, lits[0], v, lits[0])
	}
	if idx < 0 {
		return nil
	}
	return walkReplaceStrings(s, wrapper, replace, optReplace, args[idx:], depth+1)
}

// replaceIndex returns where the first of the replace strings starts in v,
// or -1 when none is in it.
func replaceIndex(v string, replace []string) int {
	at := -1
	for _, r := range replace {
		if j := strings.Index(v, r); r != "" && j >= 0 && (at < 0 || j < at) {
			at = j
		}
	}
	return at
}

// replacedOptionError is the refusal of a word that checkReplacedOptions or
// checkReplacedFindOptions finds the input could change.
func replacedOptionError(wrapper string, args []*syntax.Word, v string) error {
	name := args[0].Lit()
	return fmt.Errorf("%s: %s word %q holds a replace string, but %s's argument checks saw the word as written, and the input put there could become an option or change what they check (a sed script, a tar option cluster); run %s without a replace string in its words", wrapper, name, v, name, name)
}

// checkReplacedOptions refuses a replace string (xargs -I, -i, --replace,
// BSD -J) in any word of a command with an argument validator (args, its
// name first). The validator saw the word as written, and xargs puts its
// input there after: with input "-delete" `xargs -I% find . %` would run
// `find . -delete`, and with "I" `xargs -I% tar c%f prog out.tar src` would
// run tar's compress program. Neither literal text before it (tar's first
// word is options, sed's /%/ an address) nor a -- (sed -- 's/%//') makes
// the word safe for every command, so none is accepted; find, whose words
// are read the same way everywhere, is checkReplacedFindOptions.
func checkReplacedOptions(wrapper string, replace []string, args []*syntax.Word) error {
	vals := wordValues(args)
	for i := 1; i < len(args); i++ {
		if replaceIndex(vals[i], replace) >= 0 {
			return replacedOptionError(wrapper, args, vals[i])
		}
	}
	return nil
}

// findValueTests are GNU find's tests and options (find --help) that take
// the next word as their value, which find does not read as a primary:
// `find . -name %` matches the input as a name whatever it is.
var findValueTests = map[string]bool{
	"-amin": true, "-anewer": true, "-atime": true, "-cmin": true, "-cnewer": true,
	"-context": true, "-ctime": true, "-fstype": true, "-gid": true, "-group": true,
	"-ilname": true, "-iname": true, "-inum": true, "-ipath": true, "-iwholename": true,
	"-iregex": true, "-links": true, "-lname": true, "-mmin": true, "-mtime": true,
	"-name": true, "-newer": true, "-path": true, "-perm": true, "-regex": true,
	"-wholename": true, "-size": true, "-type": true, "-uid": true, "-used": true,
	"-user": true, "-xtype": true, "-maxdepth": true, "-mindepth": true,
	"-regextype": true, "-samefile": true, "-printf": true,
}

// findNoValue are find's primaries, options, and operators that take no
// value. checkReplacedFindOptions treats any other word starting with - that
// is not in findValueTests as one that may take the next word as its value
// (BSD's -Bnewer, GNU's -files0-from, ...), so that word is never read as a
// test whose value it could skip.
var findNoValue = map[string]bool{
	"-print": true, "-print0": true, "-ls": true, "-prune": true, "-quit": true,
	"-delete": true, "-depth": true, "-mount": true, "-xdev": true, "-noleaf": true,
	"-follow": true, "-daystart": true, "-nowarn": true, "-warn": true,
	"-empty": true, "-false": true, "-true": true, "-nouser": true, "-nogroup": true,
	"-readable": true, "-writable": true, "-executable": true,
	"-ignore_readdir_race": true, "-noignore_readdir_race": true,
	"-not": true, "-and": true, "-or": true, "-a": true, "-o": true,
	"-H": true, "-L": true, "-P": true, "--": true,
}

// findTakesValue reports whether find reads the word after v as v's value:
// v is in findValueTests or is a -newerXY test (-newermt).
func findTakesValue(v string) bool {
	return findValueTests[v] || (len(v) == len("-newerXY") && strings.HasPrefix(v, "-newer"))
}

// checkReplacedFindOptions is checkReplacedOptions for find (args, with its
// -exec commands at actions, which walkReplaceStrings walks on their own).
// find reads a word as a primary or an operator by its first character (-,
// or the words (, ), !, and ,), wherever it sits, -- or not, so a replace
// string is safe only as the value of a test in findValueTests (or -newerXY),
// which find
// matches as a name, pattern, or number, or after literal text that does
// not start with one of those characters (./%), which keeps it a start
// path.
func checkReplacedFindOptions(wrapper string, replace []string, args []*syntax.Word, actions []findAction) error {
	vals := wordValues(args)
	inAction := make(map[int]bool)
	for _, a := range actions {
		for i := a.start - 1; i <= a.end && i < len(args); i++ {
			inAction[i] = true
		}
	}
	for i := 1; i < len(args); i++ {
		if inAction[i] {
			continue
		}
		v := vals[i]
		if findTakesValue(v) {
			i++ // its value
			continue
		}
		if strings.HasPrefix(v, "-") && !findNoValue[v] && i+1 < len(args) && !inAction[i+1] {
			// It may take the next word as its value: that word is
			// checked, never read as a test.
			if replaceIndex(v, replace) >= 0 {
				return replacedOptionError(wrapper, args, v)
			}
			i++
			v = vals[i]
		}
		at := replaceIndex(v, replace)
		if at < 0 || (at > 0 && !strings.ContainsRune("-()!,", rune(v[0]))) {
			continue
		}
		return replacedOptionError(wrapper, args, v)
	}
	return nil
}

// validateEnvAssignments holds env's NAME=VALUE operands (assigns, the words
// between its options and the command at idx) to the same blocked variables
// as a shell assignment (FOO=bar cmd), which they are equivalent to.
func validateEnvAssignments(s *Sandbox, args []*syntax.Word, assigns []string, idx int) error {
	for _, a := range assigns {
		name, val, _ := strings.Cut(a, "=")
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
