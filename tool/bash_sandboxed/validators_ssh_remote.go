package bash_sandboxed

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/gartnera/lite-sandbox/config"
)

// The remote command ssh runs is held to read-only commands, unless the
// destination's hosts entry widens that (config.SSHHost): write: true lifts
// the check, and its commands entries allow those commands with any
// arguments.
//
// ssh joins the words after the destination with spaces and the remote user's
// shell runs the result, so the check parses that string as a shell script
// (sh/bash syntax) and validates it the way a local script is validated
// (validateWithFunctionsCtx), by a Sandbox whose remotePolicy swaps in what
// a remote command may do. No runtime layer sees a remote command, so each
// one is checked the way a wrapped command is (validateSubCommand), on its
// words' values, and everything in it must be known before it runs: no
// variables, command substitution, arithmetic, loops, or function
// definitions. Each command is a bare name from the read-only commands below
// (or a host commands entry), held by its validator in remoteArgValidators.
// The wrappers are the local validators (env, timeout, nice, stdbuf, find
// -exec), plus sudo, command, and sh/bash -c, whose script is validated the
// same way. Output redirections may only go to /dev/null.
//
// Without a command, ssh opens a login shell that runs whatever reaches its
// stdin, so that is refused unless stdin is closed (-n) or no session runs
// (-N, -G). A terminal (-t) is refused for the same reason: a pager (less,
// under systemctl or git) would take commands from it. A subsystem (-s, such
// as sftp), RemoteCommand, and SetEnv are refused too.

// remoteScriptDepth bounds sh -c nesting in a remote command.
const remoteScriptDepth = 4

// checkSSHRemote checks what an ssh invocation runs on its destination, whose
// hosts entry is host (nil when it is not listed, which the caller refuses
// first).
func checkSSHRemote(p sshArgs, argv []string, host *config.SSHHost) error {
	if p.noSession || host == nil || host.Writes() {
		return nil
	}
	name := host.Host
	fix := fmt.Sprintf("the user can allow a command there with `lite-sandbox config ssh hosts add %s --command '<command>'`, or any remote command with --write", name)
	refuse := func(format string, a ...any) error {
		return fmt.Errorf("ssh to %s runs read-only commands only: %s; %s", name, fmt.Sprintf(format, a...), fix)
	}
	switch {
	case p.subsystem:
		return refuse("a subsystem (-s, SessionType=subsystem) such as sftp can write files")
	case p.remoteCommand:
		return refuse("give the command after the destination instead of -o RemoteCommand")
	case len(p.setEnv) > 0:
		return refuse("-o SetEnv sets the remote environment")
	case p.tty && !p.stdinNull:
		return refuse("a terminal (-t, RequestTTY) lets stdin drive the remote programs (a pager runs what it is sent); drop -t")
	}
	if p.cmdIdx >= len(argv) {
		if p.stdinNull {
			return nil
		}
		return refuse("without a command the remote shell runs whatever reaches its stdin; give the command (ssh %s uptime)", name)
	}
	if err := newRemoteSandbox(host).validateRemoteScript(strings.Join(argv[p.cmdIdx:], " ")); err != nil {
		return refuse("%v", err)
	}
	return nil
}

// remotePolicy is what a remote command may do on one host (see
// Sandbox.remote).
type remotePolicy struct {
	// commands are the host's commands entries, parsed like the deny list's.
	commands map[string][]deniedEntry
	// depth is the sh -c nesting of the script being validated.
	depth int
}

// newRemoteSandbox returns the Sandbox that validates host's remote command.
func newRemoteSandbox(host *config.SSHHost) *Sandbox {
	return &Sandbox{
		cfg:           &config.Config{Mode: string(config.ModeAllowlist)},
		argValidators: remoteArgValidators,
		remote:        &remotePolicy{commands: parseDeniedCommands(host.Commands)},
	}
}

// validateRemoteScript parses and validates a remote shell script.
func (s *Sandbox) validateRemoteScript(src string) error {
	if s.remote.depth > remoteScriptDepth {
		return fmt.Errorf("sh -c is nested too deeply")
	}
	f, err := ParseBash(src)
	if err != nil {
		return fmt.Errorf("the remote command does not parse: %v", err)
	}
	return s.validateWithFunctionsCtx(context.Background(), f, nil, "")
}

// remoteNodeError is the refusal for the script nodes a remote command may
// not hold, or nil.
func remoteNodeError(node syntax.Node) error {
	if err := expansionError(node); err != nil {
		return err
	}
	switch n := node.(type) {
	case *syntax.ArithmCmd, *syntax.LetClause:
		return fmt.Errorf("shell arithmetic is not allowed")
	case *syntax.ForClause:
		return fmt.Errorf("for loops are not allowed: their variable is only known on the remote host")
	case *syntax.FuncDecl:
		return fmt.Errorf("function definitions are not allowed")
	case *syntax.CoprocClause:
		return fmt.Errorf("coprocesses are not allowed")
	case *syntax.DeclClause:
		return fmt.Errorf("%s is not allowed: it sets shell variables", n.Variant.Value)
	case *syntax.TestDecl:
		return fmt.Errorf("@test is not allowed")
	}
	return nil
}

// expansionError is the refusal for a word part whose value is only known
// when the shell runs, or nil for any other node.
func expansionError(node syntax.Node) error {
	switch n := node.(type) {
	case *syntax.ParamExp:
		return fmt.Errorf("variables ($%s) are only known on the remote host; write the value out (~ for the home directory)", paramName(n))
	case *syntax.CmdSubst:
		return fmt.Errorf("command substitution is not allowed; run the inner command on its own first")
	case *syntax.ArithmExp:
		return fmt.Errorf("shell arithmetic is not allowed")
	case *syntax.ProcSubst:
		return fmt.Errorf("process substitution is not allowed")
	case *syntax.ExtGlob:
		return fmt.Errorf("extended globs are not allowed")
	}
	return nil
}

func paramName(p *syntax.ParamExp) string {
	if p.Param != nil {
		return p.Param.Value
	}
	return ""
}

// partError is the refusal for a word part literalWord stopped at.
func partError(part syntax.WordPart) error {
	if err := expansionError(part); err != nil {
		return err
	}
	switch p := part.(type) {
	case *syntax.SglQuoted:
		return fmt.Errorf("$'...' quoting is not allowed: use '...'")
	case *syntax.DblQuoted:
		if p.Dollar {
			return fmt.Errorf(`$"..." quoting is not allowed: use "..."`)
		}
	}
	return fmt.Errorf("this word is not allowed in the remote command")
}

// remoteRedirect holds a remote command's output redirections, which
// validateRedirect leaves to the path checks locally, to /dev/null.
func remoteRedirect(rd *syntax.Redirect) error {
	switch rd.Op {
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		w, bad := literalWord(rd.Word)
		if bad != nil {
			return partError(bad)
		}
		if w.glob || w.val != "/dev/null" {
			return fmt.Errorf("output redirection to %q is not allowed: only to /dev/null", w.val)
		}
	}
	return nil
}

// remoteEnvName matches the variables a remote command may set for the
// command it prefixes (LC_ALL=C sort): locale, time zone, and output width.
var remoteEnvName = regexp.MustCompile(`^(LANG|LANGUAGE|LC_[A-Z]+|TZ|COLUMNS|NO_COLOR|TERM)$`)

// remoteEnvValue is the characters such a value may hold.
var remoteEnvValue = regexp.MustCompile(`^[A-Za-z0-9_.:/@,+-]*$`)

func checkRemoteAssign(name, val string) error {
	if !remoteEnvName.MatchString(name) {
		return fmt.Errorf("setting %s is not allowed: only locale, time zone, and width variables (LC_ALL, LANG, TZ, COLUMNS, ...)", name)
	}
	if !remoteEnvValue.MatchString(val) {
		return fmt.Errorf("%s=%s is not allowed: the value may only hold letters, digits, and _.:/@,+-", name, val)
	}
	return nil
}

// call checks one command of the remote script: its assignments, and the
// command on its words' values (command).
func (r *remotePolicy) call(s *Sandbox, c *syntax.CallExpr) error {
	if len(c.Args) == 0 {
		return fmt.Errorf("assigning shell variables is not allowed")
	}
	for _, a := range c.Assigns {
		if a.Name == nil || a.Index != nil || a.Array != nil || a.Append || a.Naked {
			return fmt.Errorf("this assignment is not allowed")
		}
		val := ""
		if a.Value != nil {
			w, bad := literalWord(a.Value)
			if bad != nil {
				return partError(bad)
			}
			if w.glob {
				return fmt.Errorf("%s=%s is not allowed: the value may only hold letters, digits, and _.:/@,+-", a.Name.Value, w.val)
			}
			val = w.val
		}
		if err := checkRemoteAssign(a.Name.Value, val); err != nil {
			return err
		}
	}
	words := make([]shellWord, len(c.Args))
	for i, w := range c.Args {
		v, bad := literalWord(w)
		if bad != nil {
			return partError(bad)
		}
		words[i] = v
	}
	if err := r.checkGlobs(words); err != nil {
		return err
	}
	return r.command(s, literalWords(shellWordVals(words)))
}

// remoteCommandName is a bare command name: no path, glob, or placeholder.
var remoteCommandName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+-]*$`)

// command checks a remote command (args, literal: see literalWords), the
// remote form of validateSubCommand: a host commands entry allows it as
// written, and otherwise it must be one of the read-only commands, held by
// its validator.
func (r *remotePolicy) command(s *Sandbox, args []*syntax.Word) error {
	vals := wordLits(args)
	name := vals[0]
	if !remoteCommandName.MatchString(name) {
		return fmt.Errorf("%q is not allowed: run commands by a bare name", name)
	}
	if r.allows(vals) || remotePlainReaders[name] {
		return nil
	}
	validator, ok := s.validator(name)
	if !ok {
		return fmt.Errorf("%s is not one of the read-only commands", name)
	}
	return validator(s, args)
}

// allows reports whether one of the host's commands entries allows argv: a
// bare entry, or one whose arguments are a prefix of argv's leading non-flag
// arguments. Unlike a commands allow, an invocation with no non-flag
// arguments (systemctl --version) is not taken to match: it is left to the
// read-only check.
func (r *remotePolicy) allows(argv []string) bool {
	nonFlag := nonFlagArgs(argv[1:])
	return slices.ContainsFunc(r.commands[argv[0]], func(e deniedEntry) bool {
		return e.prefix == nil || hasTokenPrefix(nonFlag, e.prefix)
	})
}

// errNoGlob is the refusal for a glob in a command that is not a plain reader.
func errNoGlob(name, word string) error {
	return fmt.Errorf("%s %s: unquoted globs and braces are only allowed in the arguments of plain readers (cat, ls, grep, ...); quote it or list the files", name, word)
}

// checkGlobs refuses a word the remote shell expands (a glob or brace), whose
// value is only known there, except in the arguments of a plain reader or of
// a host commands entry, looked for through the wrappers.
func (r *remotePolicy) checkGlobs(words []shellWord) error {
	vals := shellWordVals(words)
	start := 0
	for {
		if words[start].glob {
			return fmt.Errorf("%q is not allowed: run commands by a bare name", vals[start])
		}
		index, ok := remoteWrapperIndex[vals[start]]
		if !ok {
			break
		}
		idx := index(vals[start:])
		if idx <= 0 {
			break
		}
		for _, w := range words[start+1 : start+idx] {
			if w.glob {
				return errNoGlob(vals[start], w.val)
			}
		}
		start += idx
	}
	if remotePlainReaders[vals[start]] || r.allows(vals[start:]) {
		return nil
	}
	for _, w := range words[start+1:] {
		if w.glob {
			return errNoGlob(vals[start], w.val)
		}
	}
	return nil
}

// remoteWrapperIndex finds the command each remote wrapper runs: its index
// in the wrapper's argv, or a negative number when it runs none. The
// validators of the wrappers use the same walkers.
var remoteWrapperIndex = map[string]func(argv []string) int{
	"sudo": func(argv []string) int {
		idx, _ := remoteSudoIndex(argv)
		return idx
	},
	"env":     wrapperCommandIndex,
	"timeout": wrapperCommandIndex,
	"nice":    wrapperCommandIndex,
	"stdbuf":  wrapperCommandIndex,
	"command": remoteCommandBuiltinIndex,
}

// remoteBlockedShellFlags are the shell flags a remote sh -c may not take:
// blockedBashFlags, but a login shell (-l), whose profile a read-only
// command cannot have written, is allowed.
var remoteBlockedShellFlags = func() map[string]string {
	m := maps.Clone(blockedBashFlags)
	delete(m, "-l")
	delete(m, "--login")
	return m
}()

// remoteShells are the shells a remote command may run a -c script with.
var remoteShells = map[string]bool{"sh": true, "bash": true, "dash": true}

// validateRemoteShell allows sh/bash/dash -c SCRIPT, and validates SCRIPT as
// a remote command; any other invocation reads commands from stdin or a
// file.
func validateRemoteShell(s *Sandbox, args []*syntax.Word) error {
	vals := wordLits(args)
	idx, err := bashCommandStringIndex(vals, remoteBlockedShellFlags)
	if err != nil {
		return err
	}
	if idx < 0 {
		return fmt.Errorf("%s is only allowed as %s -c 'commands'", vals[0], vals[0])
	}
	s.remote.depth++
	defer func() { s.remote.depth-- }()
	return s.validateRemoteScript(vals[idx])
}

// validateRemoteFind is validateFindArgs, refusing a shell under -exec and
// friends: find puts the file names it finds into the script, where the
// shell would run them.
func validateRemoteFind(s *Sandbox, args []*syntax.Word) error {
	vals := wordLits(args)
	for _, a := range findActions(vals) {
		if a.end > a.start && remoteShells[vals[a.start]] {
			return fmt.Errorf("find %s %s is not allowed: find puts the file names into the script, where the shell would run them", a.flag, vals[a.start])
		}
	}
	return validateFindArgs(s, args)
}

// validateRemoteSudo checks sudo's options and the command it runs.
func validateRemoteSudo(s *Sandbox, args []*syntax.Word) error {
	idx, err := remoteSudoIndex(wordLits(args))
	if err != nil || idx < 0 {
		return err
	}
	return validateSubCommand(s, args[idx:])
}

// sudo's options: those that take a value (sudoSpec), and the flags.
var (
	sudoSpec = optSpec{
		short: "CDgprRtTUu",
		long:  []string{"close-from", "chdir", "group", "host", "prompt", "chroot", "role", "type", "other-user", "command-timeout", "user"},
	}
	sudoFlags     = "ABbEHhKklNnPSVv"
	sudoLongFlags = []string{"askpass", "bell", "background", "preserve-env", "set-home", "help", "remove-timestamp", "reset-timestamp", "list", "no-update", "non-interactive", "preserve-groups", "stdin", "version", "validate"}
)

// remoteSudoIndex returns the command sudo runs, or -1. Its options stop at
// the first operand ("+" getopt, as wrapperSpec.commandIndex walks); only
// the ones above are allowed, so -e (sudoedit), -i, and -s (a shell) are
// refused, as are VAR=value operands.
func remoteSudoIndex(argv []string) (int, error) {
	idx := wrapperSpec{opts: optSpec{short: sudoSpec.short, long: sudoSpec.long, flags: sudoLongFlags}}.commandIndex(argv, argv)
	end := idx
	if idx < 0 {
		end = len(argv)
	}
	allLong := append(slices.Clone(sudoSpec.long), sudoLongFlags...)
	for _, opt := range scanOptions(argv[:end], sudoSpec, allLong) {
		name, long := strings.CutPrefix(opt, "--")
		if long && !slices.Contains(allLong, name) || !long && !strings.Contains(sudoFlags+sudoSpec.short, opt[1:]) {
			return 0, fmt.Errorf("sudo %s is not allowed: it edits files or starts a shell", opt)
		}
	}
	if idx < 0 {
		return -1, nil
	}
	if strings.Contains(argv[idx], "=") {
		return 0, fmt.Errorf("sudo %s is not allowed: it sets the command's environment", argv[idx])
	}
	return idx, nil
}

// validateRemoteCommandBuiltin checks the command the command builtin runs.
func validateRemoteCommandBuiltin(s *Sandbox, args []*syntax.Word) error {
	idx := remoteCommandBuiltinIndex(wordLits(args))
	if idx < 0 {
		return nil
	}
	return validateSubCommand(s, args[idx:])
}

// remoteCommandBuiltinIndex returns the command the command builtin runs, or
// -1: command -v/-V only looks the name up.
func remoteCommandBuiltinIndex(argv []string) int {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--":
			if i+1 < len(argv) {
				return i + 1
			}
			return -1
		case len(a) < 2 || a[0] != '-':
			return i
		case strings.ContainsAny(a, "vV"):
			return -1
		}
	}
	return -1
}

// remoteOpts checks a command whose options can write or run something:
// refuse lists those ("-x", "--name"), matched the way refusedOption matches
// them (an abbreviated long name included), and operands checks the
// operands. spec lists the options that take a value.
type remoteOpts struct {
	spec     optSpec
	refuse   []string
	why      string
	operands func(pos []string) error
}

func (o remoteOpts) check(argv []string) error {
	long := slices.Clone(o.spec.long)
	for _, r := range o.refuse {
		if name, ok := strings.CutPrefix(r, "--"); ok && !slices.Contains(long, name) {
			long = append(long, name)
		}
	}
	if opt := refusedOption(argv, o.spec, long, o.refuse...); opt != "" {
		return fmt.Errorf("%s %s is not allowed: it %s", argv[0], opt, o.why)
	}
	if o.operands != nil {
		pos, _, _ := o.spec.parse(argv, nil)
		return o.operands(pos)
	}
	return nil
}

func noOperands(what string) func([]string) error {
	return func(pos []string) error {
		if len(pos) > 0 {
			return fmt.Errorf("an operand (%s) %s", pos[0], what)
		}
		return nil
	}
}

// remotePlainReaders are the read-only commands whose arguments are not
// checked (and may hold globs).
var remotePlainReaders = map[string]bool{}

// remoteArgValidators are the validators of the other commands a remote
// command may run: the wrappers, and the commands with options or verbs
// that write. Their keys and remotePlainReaders are the read-only commands.
var remoteArgValidators map[string]argValidator

func init() {
	for _, c := range []string{
		"cat", "head", "tail", "wc", "cut", "tr", "column", "fold", "paste", "rev", "tac", "nl",
		"expand", "unexpand", "comm", "join", "strings", "od", "hexdump", "base32", "base64",
		"md5sum", "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "b2sum", "cksum", "sum",
		"grep", "egrep", "fgrep", "zcat", "bzcat", "xzcat", "zgrep", "diff", "cmp", "jq",
		"ls", "stat", "du", "df", "readlink", "realpath", "basename", "dirname", "pwd", "cd",
		"which", "type", "echo", "printf", "true", "false", "test", "[", ":", "sleep",
		"uptime", "whoami", "id", "groups", "who", "w", "users", "last", "ps", "pgrep", "pidof",
		"free", "vmstat", "nproc", "lscpu", "lsblk", "lsmem", "findmnt", "mountpoint", "lsof",
		"printenv", "getconf", "uname", "arch",
	} {
		remotePlainReaders[c] = true
	}
	// argv adapts a check of the argv's values: the words are literal.
	argv := func(check func([]string) error) func(*Sandbox, []*syntax.Word) error {
		return func(_ *Sandbox, args []*syntax.Word) error { return check(wordLits(args)) }
	}
	remoteArgValidators = map[string]argValidator{
		"env":     validateWrapperArgs,
		"timeout": validateWrapperArgs,
		"nice":    validateWrapperArgs,
		"stdbuf":  validateWrapperArgs,
		"sudo":    validateRemoteSudo,
		"command": validateRemoteCommandBuiltin,
		"sh":      validateRemoteShell,
		"bash":    validateRemoteShell,
		"dash":    validateRemoteShell,
		"find":    validateRemoteFind,
		"journalctl": argv(remoteOpts{
			refuse: []string{"--cursor-file", "--vacuum-size", "--vacuum-time", "--vacuum-files", "--sync", "--relinquish-var", "--smart-relinquish-var", "--flush", "--rotate", "--update-catalog", "--setup-keys", "--synchronize-on-exit"},
			why:    "writes or removes journal files",
		}.check),
		"systemctl": argv(checkRemoteSystemctl),
		"git":       argv(checkRemoteGit),
		"docker":    argv(checkRemoteDocker),
		"sed":       argv(checkRemoteSed),
		"ip":        argv(checkRemoteIP),
		"sort": argv(remoteOpts{
			spec:   optSpec{short: "kSTot", long: []string{"random-source", "sort", "batch-size", "files0-from", "key", "buffer-size", "field-separator", "temporary-directory", "parallel", "output", "compress-program"}},
			refuse: []string{"-o", "--output", "--compress-program"},
			why:    "writes a file or runs a program",
		}.check),
		"uniq": argv(remoteOpts{
			spec: optSpec{short: "fsw", long: []string{"skip-fields", "skip-chars", "check-chars"}},
			operands: func(pos []string) error {
				if len(pos) > 1 {
					return fmt.Errorf("uniq with a second operand (%s) writes it", pos[1])
				}
				return nil
			},
		}.check),
		"date": argv(checkRemoteDate),
		"hostname": argv(remoteOpts{
			spec:     optSpec{short: "F", long: []string{"file"}},
			refuse:   []string{"-b", "-F", "--boot", "--file"},
			why:      "sets the host name",
			operands: noOperands("sets the host name"),
		}.check),
		"dmesg": argv(remoteOpts{
			spec:   optSpec{short: "Fflns", long: []string{"file", "facility", "level", "console-level", "buffer-size", "since", "until", "time-format"}},
			refuse: []string{"-c", "-C", "-D", "-E", "-n", "--clear", "--read-clear", "--console-off", "--console-on", "--console-level"},
			why:    "clears the kernel log or changes the console",
		}.check),
		"ss": argv(remoteOpts{
			spec:   optSpec{short: "DFN", long: []string{"diag", "filter", "net"}},
			refuse: []string{"-K", "-D", "--kill", "--diag"},
			why:    "closes sockets or writes a file",
		}.check),
		"file": argv(remoteOpts{
			spec:   optSpec{short: "efFmP", long: []string{"exclude", "exclude-quiet", "files-from", "separator", "magic-file", "parameter"}},
			refuse: []string{"-C", "--compile"},
			why:    "writes a compiled magic file",
		}.check),
		"rg": argv(remoteOpts{
			spec:   optSpec{short: "ABCEefgjMmrTt", long: []string{"pre", "hostname-bin"}},
			refuse: []string{"--pre", "--hostname-bin"},
			why:    "runs a program",
		}.check),
	}
}

func checkRemoteDate(argv []string) error {
	// -I takes its optional FMT attached (-Iseconds), which parse would read
	// as -s's value.
	argv = slices.DeleteFunc(slices.Clone(argv), func(a string) bool { return strings.HasPrefix(a, "-I") })
	return remoteOpts{
		spec:   optSpec{short: "dfrs", long: []string{"date", "file", "reference", "rfc-3339", "set"}},
		refuse: []string{"-s", "--set"},
		why:    "sets the clock",
		operands: func(pos []string) error {
			for _, p := range pos {
				if !strings.HasPrefix(p, "+") {
					return fmt.Errorf("date %s is not allowed: an operand other than +FORMAT sets the clock", p)
				}
			}
			return nil
		},
	}.check(argv)
}

// systemctl's read-only verbs (no verb is list-units).
var systemctlReadOnly = []string{
	"list-units", "list-automounts", "list-paths", "list-sockets", "list-timers",
	"is-active", "is-failed", "status", "show", "cat", "help", "list-dependencies",
	"whoami", "list-unit-files", "is-enabled", "get-default", "list-machines",
	"list-jobs", "show-environment", "is-system-running",
}

func checkRemoteSystemctl(argv []string) error {
	return remoteOpts{
		spec: optSpec{short: "tpPsnoHMC", long: []string{
			"type", "state", "property", "job-mode", "check-inhibitors", "kill-whom", "kill-value",
			"kill-subgroup", "signal", "what", "message", "root", "image", "image-policy", "preset-mode",
			"lines", "output", "boot-loader-menu", "boot-loader-entry", "reboot-argument",
			"kernel-cmdline", "timestamp", "drop-in", "when", "host", "machine", "capsule", "legend",
		}},
		refuse: []string{"-H", "--host"},
		why:    "reaches another host",
		operands: func(pos []string) error {
			if len(pos) > 0 && !slices.Contains(systemctlReadOnly, pos[0]) {
				return fmt.Errorf("systemctl %s is not a read-only verb (%s)", pos[0], strings.Join(systemctlReadOnly, ", "))
			}
			return nil
		},
	}.check(argv)
}

// git's read-only subcommands on a remote repository.
var gitRemoteReadOnly = []string{
	"status", "log", "show", "diff", "rev-parse", "rev-list", "ls-files", "ls-tree", "blame",
	"describe", "shortlog", "cat-file", "grep",
}

// The git global options a remote git may take: with a value, and flags.
var (
	gitRemoteGlobalValues = []string{"-C", "--git-dir", "--work-tree", "--namespace"}
	gitRemoteGlobalFlags  = []string{"-P", "--no-pager", "--bare", "--no-replace-objects", "--literal-pathspecs", "--glob-pathspecs", "--noglob-pathspecs", "--icase-pathspecs", "--no-optional-locks"}
)

// checkRemoteGit allows git's read-only subcommands, with only the global
// options above (no -c, which can make git run a program) and without the
// options that write a file or run a pager.
func checkRemoteGit(argv []string) error {
	sub, idx, err := findSubcommand("git", literalWords(argv), gitGlobalValueFlags)
	if err != nil {
		return err
	}
	end := len(argv)
	if sub != "" {
		end = idx
	}
	for i := 1; i < end; i++ {
		name, _, hasVal := strings.Cut(argv[i], "=")
		switch {
		case slices.Contains(gitRemoteGlobalValues, argv[i]):
			i++
		case slices.Contains(gitRemoteGlobalFlags, argv[i]):
		case hasVal && name != "-C" && slices.Contains(gitRemoteGlobalValues, name):
		default:
			return fmt.Errorf("git %s is not allowed before a read-only subcommand (only -C, -P, --git-dir, --work-tree)", argv[i])
		}
	}
	if sub == "" {
		return nil
	}
	if !slices.Contains(gitRemoteReadOnly, sub) {
		return fmt.Errorf("git %s is not a read-only subcommand (%s)", sub, strings.Join(gitRemoteReadOnly, ", "))
	}
	return remoteOpts{refuse: []string{"-O", "--output", "--open-files-in-pager"}, why: "writes a file or runs a pager"}.check(argv[idx:])
}

// docker's read-only commands: top-level, and under each management command.
var dockerRemoteReadOnly = map[string][]string{
	"":          {"ps", "logs", "inspect", "images", "version", "info", "stats", "top", "port", "diff", "history", "events"},
	"container": {"ls", "list", "ps", "logs", "inspect", "top", "port", "diff", "stats"},
	"image":     {"ls", "list", "inspect", "history"},
	"network":   {"ls", "list", "inspect"},
	"volume":    {"ls", "list", "inspect"},
	"system":    {"df", "info", "events"},
	"compose":   {"ps", "logs", "ls", "images", "top", "version", "port"},
}

func checkRemoteDocker(argv []string) error {
	if len(argv) < 2 {
		return nil
	}
	sub := argv[1]
	if verbs, ok := dockerRemoteReadOnly[sub]; ok && sub != "" {
		i := 2
		if sub == "compose" {
			// Compose's own options come before its subcommand.
			values := []string{"-f", "--file", "-p", "--project-name", "--project-directory", "--env-file", "--profile", "--progress", "--ansi", "--parallel"}
			for i < len(argv) && strings.HasPrefix(argv[i], "-") {
				if slices.Contains(values, argv[i]) {
					i++
				}
				i++
			}
		}
		if i < len(argv) && !slices.Contains(verbs, argv[i]) {
			return fmt.Errorf("docker %s %s is not read-only (%s)", sub, argv[i], strings.Join(verbs, ", "))
		}
		return nil
	}
	if !slices.Contains(dockerRemoteReadOnly[""], sub) {
		return fmt.Errorf("docker %s is not read-only (ps, logs, inspect, images, stats, ..., or container/image/network/volume/system/compose ls, inspect, logs, ...)", sub)
	}
	return nil
}

// checkRemoteIP allows ip OBJECT [show|list|ls|lst|get|help ...], with the
// options that do not read commands from a file (-batch, -force).
func checkRemoteIP(argv []string) error {
	flags := []string{"-s", "-stats", "-statistics", "-d", "-details", "-h", "-human", "-human-readable", "-iec",
		"-4", "-6", "-0", "-B", "-o", "-oneline", "-r", "-resolve", "-a", "-all", "-c", "-color",
		"-br", "-brief", "-j", "-json", "-p", "-pretty", "-N", "-Numeric", "-t", "-timestamp", "-ts", "-tshort", "-V", "-Version"}
	i := 1
	for ; i < len(argv) && strings.HasPrefix(argv[i], "-"); i++ {
		a := argv[i]
		if strings.HasPrefix(a, "--") {
			a = a[1:]
		}
		name, _, _ := strings.Cut(a, "=")
		switch {
		case name == "-n" || name == "-netns":
			i++
		case slices.Contains(flags, name) && (name == a || name == "-c" || name == "-color"):
		default:
			return fmt.Errorf("ip %s is not allowed (only display options, and -n NETNS)", argv[i])
		}
	}
	if i+1 < len(argv) && !slices.Contains([]string{"show", "list", "ls", "lst", "get", "help"}, argv[i+1]) {
		return fmt.Errorf("ip %s %s is not allowed: only show, list, and get (written out in full)", argv[i], argv[i+1])
	}
	return nil
}

// checkRemoteSed refuses in-place editing, script files, and the script
// commands that write a file or run one (w, W, e, and s///w and s///e).
func checkRemoteSed(argv []string) error {
	if opt := refusedOption(argv, sedSpec, sedLongOpts, "-i", "-I", "-f", "--in-place", "--file"); opt != "" {
		return fmt.Errorf("sed %s is not allowed: it edits files in place or reads the script from a file", opt)
	}
	scripts, _ := sedScripts(argv)
	for _, s := range scripts {
		if err := sedScriptCheck(s, "ewW"); errors.Is(err, errSedRefused) {
			return fmt.Errorf("sed: the w, W, and e commands and the s///w and s///e flags are not allowed: they write a file or run a command")
		} else if err != nil {
			return fmt.Errorf("sed: %w", err)
		}
	}
	return nil
}
