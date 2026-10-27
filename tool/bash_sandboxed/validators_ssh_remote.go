package bash_sandboxed

import (
	"errors"
	"fmt"
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
// (sh/bash syntax) and walks it. Everything in it must be known before it
// runs: no variables, command substitution, arithmetic, loops, or function
// definitions, and each command is a bare name from the read-only list below
// (or a host commands entry), with literal arguments. Wrappers (sudo, env,
// timeout, nice, stdbuf, command, and sh/bash -c) are looked through. Output
// redirections may only go to /dev/null.
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
	r := remoteChecker{commands: parseHostCommands(host.Commands)}
	if err := r.script(strings.Join(argv[p.cmdIdx:], " "), 0); err != nil {
		return refuse("%v", err)
	}
	return nil
}

// parseHostCommands turns a hosts entry's commands into the leading
// arguments each allows, by command name; a bare name maps to nil (any
// arguments). Unlike a commands allow, an invocation with no leading
// arguments (systemctl --version) is not taken to match: it is left to the
// read-only check.
func parseHostCommands(cmds []string) map[string][][]string {
	out := map[string][][]string{}
	for _, c := range cmds {
		f := strings.Fields(c)
		if len(f) == 0 {
			continue
		}
		if len(f) == 1 {
			out[f[0]] = nil
			continue
		}
		if prev, ok := out[f[0]]; ok && prev == nil {
			continue // a bare entry already allows everything
		}
		out[f[0]] = append(out[f[0]], f[1:])
	}
	return out
}

type remoteChecker struct {
	commands map[string][][]string
}

// remoteWord is one word of the remote command: its value after the remote
// shell's quote removal, and whether the shell expands it further (an
// unquoted glob or brace expansion), so its value is only known there.
type remoteWord struct {
	val  string
	glob bool
}

func remoteVals(ws []remoteWord) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.val
	}
	return out
}

// script parses and checks a remote shell script.
func (r remoteChecker) script(src string, depth int) error {
	if depth > remoteScriptDepth {
		return fmt.Errorf("sh -c is nested too deeply")
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		return fmt.Errorf("the remote command does not parse: %v", err)
	}
	var walkErr error
	syntax.Walk(f, func(node syntax.Node) bool {
		if walkErr != nil {
			return false
		}
		walkErr = r.node(node, depth)
		return walkErr == nil
	})
	return walkErr
}

func (r remoteChecker) node(node syntax.Node, depth int) error {
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
	case *syntax.Stmt:
		for _, rd := range n.Redirs {
			if err := remoteRedirect(rd); err != nil {
				return err
			}
		}
	case *syntax.CallExpr:
		return r.call(n, depth)
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

// remoteRedirect allows input redirections, fd duplication, and output to
// /dev/null.
func remoteRedirect(rd *syntax.Redirect) error {
	switch rd.Op {
	case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc, syntax.DplIn, syntax.RdrIn:
		return nil
	case syntax.DplOut:
		w, err := remoteWordValue(rd.Word)
		if err != nil {
			return err
		}
		if w.val == "" || strings.Trim(w.val, "0123456789-") != "" {
			return fmt.Errorf("output redirection to %q is not allowed: only to a file descriptor (2>&1) or /dev/null", w.val)
		}
		return nil
	case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll:
		w, err := remoteWordValue(rd.Word)
		if err != nil {
			return err
		}
		if w.glob || w.val != "/dev/null" {
			return fmt.Errorf("output redirection to %q is not allowed: only to /dev/null", w.val)
		}
		return nil
	}
	return fmt.Errorf("redirection %s is not allowed", rd.Op)
}

// remoteWordValue returns w's value as the remote shell sees it once quotes
// are removed. Expansions are refused (the walk reports them first); $'...'
// and $"..." are refused because shells disagree on them.
func remoteWordValue(w *syntax.Word) (remoteWord, error) {
	var out remoteWord
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			v, glob := unescapeUnquoted(p.Value)
			sb.WriteString(v)
			out.glob = out.glob || glob
		case *syntax.SglQuoted:
			if p.Dollar {
				return out, fmt.Errorf("$'...' quoting is not allowed: use '...'")
			}
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return out, fmt.Errorf(`$"..." quoting is not allowed: use "..."`)
			}
			for _, dp := range p.Parts {
				lit, ok := dp.(*syntax.Lit)
				if !ok {
					return out, partError(dp)
				}
				sb.WriteString(unescapeDoubleQuoted(lit.Value))
			}
		default:
			return out, partError(part)
		}
	}
	out.val = sb.String()
	return out, nil
}

func partError(part syntax.WordPart) error {
	if err := expansionError(part); err != nil {
		return err
	}
	return fmt.Errorf("this word is not allowed in the remote command")
}

// unescapeUnquoted removes the backslashes of an unquoted word part and
// reports whether it has an unescaped glob character or brace expansion
// (a { other than find's {} placeholder).
func unescapeUnquoted(s string) (string, bool) {
	var sb strings.Builder
	glob := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			if s[i] != '\n' {
				sb.WriteByte(s[i])
			}
			continue
		}
		switch c {
		case '*', '?', '[':
			glob = true
		case '{':
			if !strings.HasPrefix(s[i:], "{}") {
				glob = true
			}
		}
		sb.WriteByte(c)
	}
	return sb.String(), glob
}

// unescapeDoubleQuoted removes the backslashes that escape a character
// inside double quotes ($, `, ", \, and a newline).
func unescapeDoubleQuoted(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
			i++
			if s[i] != '\n' {
				sb.WriteByte(s[i])
			}
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
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

func (r remoteChecker) call(c *syntax.CallExpr, depth int) error {
	if len(c.Args) == 0 {
		return fmt.Errorf("assigning shell variables is not allowed")
	}
	for _, a := range c.Assigns {
		if a.Name == nil || a.Index != nil || a.Array != nil || a.Append || a.Naked {
			return fmt.Errorf("this assignment is not allowed")
		}
		val := ""
		if a.Value != nil {
			w, err := remoteWordValue(a.Value)
			if err != nil {
				return err
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
	words := make([]remoteWord, len(c.Args))
	for i, w := range c.Args {
		v, err := remoteWordValue(w)
		if err != nil {
			return err
		}
		words[i] = v
	}
	return r.argv(words, depth)
}

// remoteCommandName is a bare command name: no path, glob, or placeholder.
var remoteCommandName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.+-]*$`)

// errNoGlob is the refusal for a glob in a command that is not a plain reader.
func errNoGlob(name, word string) error {
	return fmt.Errorf("%s %s: unquoted globs and braces are only allowed in the arguments of plain readers (cat, ls, grep, ...); quote it or list the files", name, word)
}

// argv checks one command and its arguments.
func (r remoteChecker) argv(words []remoteWord, depth int) error {
	name := words[0].val
	if words[0].glob || !remoteCommandName.MatchString(name) {
		return fmt.Errorf("%q is not allowed: run commands by a bare name", name)
	}
	vals := remoteVals(words)
	if restrictions, ok := r.commands[name]; ok {
		if restrictions == nil || slices.ContainsFunc(restrictions, func(seq []string) bool {
			return hasTokenPrefix(nonFlagArgs(vals[1:]), seq)
		}) {
			return nil
		}
	}
	if wrap, ok := remoteWrappers[name]; ok {
		idx, err := wrap(vals)
		if err != nil {
			return err
		}
		end := idx
		if idx < 0 || idx > len(words) {
			end = len(words)
		}
		for _, w := range words[1:end] {
			if w.glob {
				return errNoGlob(name, w.val)
			}
		}
		if end == len(words) {
			return nil
		}
		return r.argv(words[idx:], depth)
	}
	if shells[name] {
		return r.shell(words, depth)
	}
	check, ok := remoteReadOnly[name]
	if !ok {
		return fmt.Errorf("%s is not one of the read-only commands", name)
	}
	if check == nil {
		return nil
	}
	for _, w := range words[1:] {
		if w.glob {
			return errNoGlob(name, w.val)
		}
	}
	return check(vals)
}

var shells = map[string]bool{"sh": true, "bash": true, "dash": true}

// shell checks sh/bash/dash -c SCRIPT, which runs SCRIPT; any other
// invocation reads commands from stdin or a file.
func (r remoteChecker) shell(words []remoteWord, depth int) error {
	name := words[0].val
	hasC := false
	for i := 1; i < len(words); i++ {
		w := words[i]
		switch {
		case w.glob:
			return errNoGlob(name, w.val)
		case w.val == "--login" || w.val == "--noprofile" || w.val == "--norc" || w.val == "--posix":
		case (w.val == "-o" || w.val == "+o") && i+1 < len(words):
			i++
		case len(w.val) > 1 && (w.val[0] == '-' || w.val[0] == '+') && strings.Trim(w.val[1:], "elnuvxc") == "":
			hasC = hasC || (w.val[0] == '-' && strings.Contains(w.val, "c"))
		case hasC:
			return r.script(w.val, depth+1)
		default:
			return fmt.Errorf("%s is only allowed as %s -c 'commands'", name, name)
		}
	}
	return fmt.Errorf("%s is only allowed as %s -c 'commands'", name, name)
}

// remoteWrappers find the command a wrapper runs: its index in the argv, or
// -1 when it runs none.
var remoteWrappers = map[string]func(argv []string) (int, error){
	"sudo": remoteSudoIndex,
	"env": func(argv []string) (int, error) {
		idx := envCommandIndex(argv, argv)
		if idx == wrapperRejected {
			return 0, errEnvSplitString()
		}
		end := idx
		if idx < 0 {
			end = len(argv)
		}
		for _, a := range argv[1:end] {
			if isEnvAssignment(a) {
				name, val, _ := strings.Cut(a, "=")
				if err := checkRemoteAssign(name, val); err != nil {
					return 0, err
				}
			}
		}
		return idx, nil
	},
	"timeout": func(argv []string) (int, error) {
		idx := optionWrapperCommandIndex(argv, optSpec{short: "ks", long: []string{"kill-after", "signal"}})
		if idx < 0 {
			return -1, nil
		}
		return idx + 1, nil // past DURATION
	},
	"nice": func(argv []string) (int, error) {
		return optionWrapperCommandIndex(argv, optionWrapperSpecs["nice"]), nil
	},
	"stdbuf": func(argv []string) (int, error) {
		return optionWrapperCommandIndex(argv, optionWrapperSpecs["stdbuf"]), nil
	},
	"command": func(argv []string) (int, error) {
		for i := 1; i < len(argv); i++ {
			a := argv[i]
			switch {
			case a == "--":
				return i + 1, nil
			case len(a) < 2 || a[0] != '-':
				return i, nil
			case strings.ContainsAny(a, "vV"):
				return -1, nil // command -v/-V only looks the name up
			}
		}
		return -1, nil
	},
}

// remoteSudoIndex returns the command sudo runs. Its options stop at the
// first operand ("+" getopt); -e (sudoedit), -i, and -s (a shell) are
// refused, as are VAR=value operands.
func remoteSudoIndex(argv []string) (int, error) {
	const (
		flags  = "ABbEHhKklNnPSVv"
		values = "CDgprRtTUu"
	)
	longFlags := []string{"askpass", "bell", "background", "preserve-env", "set-home", "help", "remove-timestamp", "reset-timestamp", "list", "no-update", "non-interactive", "preserve-groups", "stdin", "version", "validate"}
	longValues := []string{"close-from", "chdir", "group", "host", "prompt", "chroot", "role", "type", "other-user", "command-timeout", "user"}
	refused := func(o string) error {
		return fmt.Errorf("sudo %s is not allowed: it edits files or starts a shell", o)
	}
	all := optSpec{long: append(slices.Clone(longFlags), longValues...)}
	i := 1
	for ; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			i++
			break
		}
		if name, ok := strings.CutPrefix(a, "--"); ok {
			name, _, hasVal := strings.Cut(name, "=")
			full := all.longName(name)
			switch {
			case slices.Contains(longValues, full):
				if !hasVal {
					i++
				}
			case slices.Contains(longFlags, full):
			default:
				return 0, refused(a)
			}
			continue
		}
		if len(a) < 2 || a[0] != '-' {
			break
		}
		for j := 1; j < len(a); j++ {
			c := a[j]
			if strings.IndexByte(values, c) >= 0 {
				if j == len(a)-1 {
					i++
				}
				break
			}
			if strings.IndexByte(flags, c) < 0 {
				return 0, refused("-" + string(c))
			}
		}
	}
	if i >= len(argv) {
		return -1, nil
	}
	if strings.Contains(argv[i], "=") {
		return 0, fmt.Errorf("sudo %s is not allowed: it sets the command's environment", argv[i])
	}
	return i, nil
}

// remoteOpts checks a command whose options can write or run something:
// refuse lists those (short letters, and long names matched the way
// getopt_long matches abbreviations), operands checks the operands.
type remoteOpts struct {
	spec       optSpec
	refuse     string
	refuseLong []string
	why        string
	operands   func(pos []string) error
}

func (o remoteOpts) check(argv []string) error {
	pos, _, flags := o.spec.parse(argv, nil)
	for f := range flags {
		if len(f) == 1 && strings.Contains(o.refuse, f) {
			return fmt.Errorf("%s -%s is not allowed: it %s", argv[0], f, o.why)
		}
	}
	if err := o.refusedLong(argv); err != nil {
		return err
	}
	if o.operands != nil {
		return o.operands(pos)
	}
	return nil
}

// refusedLong refuses a word naming one of the refused long options, or an
// abbreviation of one (--rot for --rotate), up to "--". A value that only
// looks like one (-g --flush) is refused too.
func (o remoteOpts) refusedLong(argv []string) error {
	for _, a := range argv[1:] {
		if a == "--" {
			return nil
		}
		name, ok := strings.CutPrefix(a, "--")
		if !ok {
			continue
		}
		name, _, _ = strings.Cut(name, "=")
		for _, l := range o.refuseLong {
			if strings.HasPrefix(l, name) {
				return fmt.Errorf("%s --%s is not allowed: it %s", argv[0], name, o.why)
			}
		}
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

// remoteReadOnly lists the commands a read-only remote command may run, with
// the check for their arguments (nil: any arguments, and globs allowed).
var remoteReadOnly map[string]func(argv []string) error

func init() {
	remoteReadOnly = map[string]func([]string) error{
		"journalctl": remoteOpts{
			refuseLong: []string{"cursor-file", "vacuum-size", "vacuum-time", "vacuum-files", "sync", "relinquish-var", "smart-relinquish-var", "flush", "rotate", "update-catalog", "setup-keys", "synchronize-on-exit"},
			why:        "writes or removes journal files",
		}.check,
		"systemctl": checkRemoteSystemctl,
		"git":       checkRemoteGit,
		"docker":    checkRemoteDocker,
		"sed":       checkRemoteSed,
		"find":      checkRemoteFind,
		"ip":        checkRemoteIP,
		"sort": remoteOpts{
			spec:       optSpec{short: "kSTot", long: []string{"random-source", "sort", "batch-size", "files0-from", "key", "buffer-size", "field-separator", "temporary-directory", "parallel", "output", "compress-program"}},
			refuse:     "o",
			refuseLong: []string{"output", "compress-program"},
			why:        "writes a file or runs a program",
		}.check,
		"uniq": remoteOpts{
			spec: optSpec{short: "fsw", long: []string{"skip-fields", "skip-chars", "check-chars"}},
			operands: func(pos []string) error {
				if len(pos) > 1 {
					return fmt.Errorf("uniq with a second operand (%s) writes it", pos[1])
				}
				return nil
			},
		}.check,
		"date": checkRemoteDate,
		"hostname": remoteOpts{
			spec:       optSpec{short: "F", long: []string{"file"}},
			refuse:     "bF",
			refuseLong: []string{"boot", "file"},
			why:        "sets the host name",
			operands:   noOperands("sets the host name"),
		}.check,
		"dmesg": remoteOpts{
			spec:       optSpec{short: "Fflns", long: []string{"file", "facility", "level", "console-level", "buffer-size", "since", "until", "time-format"}},
			refuse:     "cCDEn",
			refuseLong: []string{"clear", "read-clear", "console-off", "console-on", "console-level"},
			why:        "clears the kernel log or changes the console",
		}.check,
		"ss": remoteOpts{
			spec:       optSpec{short: "DFN", long: []string{"diag", "filter", "net"}},
			refuse:     "KD",
			refuseLong: []string{"kill", "diag"},
			why:        "closes sockets or writes a file",
		}.check,
		"file": remoteOpts{
			spec:       optSpec{short: "efFmP", long: []string{"exclude", "exclude-quiet", "files-from", "separator", "magic-file", "parameter"}},
			refuse:     "C",
			refuseLong: []string{"compile"},
			why:        "writes a compiled magic file",
		}.check,
		"rg": remoteOpts{
			spec:       optSpec{short: "ABCEefgjMmrTt", long: []string{"pre", "hostname-bin"}},
			refuseLong: []string{"pre", "hostname-bin"},
			why:        "runs a program",
		}.check,
	}
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
		remoteReadOnly[c] = nil
	}
}

func checkRemoteDate(argv []string) error {
	// -I takes its optional FMT attached (-Iseconds), which parse would read
	// as -s's value.
	argv = slices.DeleteFunc(slices.Clone(argv), func(a string) bool { return strings.HasPrefix(a, "-I") })
	return remoteOpts{
		spec:       optSpec{short: "dfrs", long: []string{"date", "file", "reference", "rfc-3339", "set"}},
		refuse:     "s",
		refuseLong: []string{"set"},
		why:        "sets the clock",
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
		refuse:     "H",
		refuseLong: []string{"host"},
		why:        "reaches another host",
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

func checkRemoteGit(argv []string) error {
	i := 1
	for ; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "-C" || a == "--git-dir" || a == "--work-tree" || a == "--namespace":
			i++
		case a == "-P" || a == "--no-pager" || a == "--bare" || a == "--no-replace-objects" ||
			a == "--literal-pathspecs" || a == "--glob-pathspecs" || a == "--noglob-pathspecs" ||
			a == "--icase-pathspecs" || a == "--no-optional-locks" ||
			strings.HasPrefix(a, "--git-dir=") || strings.HasPrefix(a, "--work-tree=") || strings.HasPrefix(a, "--namespace="):
		case strings.HasPrefix(a, "-"):
			return fmt.Errorf("git %s is not allowed before a read-only subcommand (only -C, -P, --git-dir, --work-tree)", a)
		default:
			goto sub
		}
	}
	return nil
sub:
	if !slices.Contains(gitRemoteReadOnly, argv[i]) {
		return fmt.Errorf("git %s is not a read-only subcommand (%s)", argv[i], strings.Join(gitRemoteReadOnly, ", "))
	}
	return remoteOpts{refuse: "O", refuseLong: []string{"output", "open-files-in-pager"}, why: "writes a file or runs a pager"}.check(argv[i:])
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

// checkRemoteFind refuses find's actions that delete or write, and checks the
// command -exec and friends run.
func checkRemoteFind(argv []string) error {
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if reason, ok := blockedFindFlags[a]; ok {
			return fmt.Errorf("find %s is not allowed: it %s", a, reason)
		}
		if !findExecFlags[a] {
			continue
		}
		j := i + 1
		for j < len(argv) && argv[j] != ";" && argv[j] != "+" {
			j++
		}
		if j == i+1 {
			return fmt.Errorf("find %s has no command", a)
		}
		words := make([]remoteWord, j-i-1)
		for k := range words {
			words[k] = remoteWord{val: argv[i+1+k]}
		}
		if err := (remoteChecker{}).argv(words, 0); err != nil {
			return fmt.Errorf("find %s: %w", a, err)
		}
		i = j
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
	pos, vals, flags := optSpec{short: "efl", long: []string{"expression", "file", "line-length"}}.parse(argv, nil)
	o := remoteOpts{refuse: "if", refuseLong: []string{"in-place", "file"}, why: "edits files in place or reads the script from a file"}
	for f := range flags {
		if len(f) == 1 && strings.Contains(o.refuse, f) {
			return fmt.Errorf("sed -%s is not allowed: it %s", f, o.why)
		}
	}
	if err := o.refusedLong(argv); err != nil {
		return err
	}
	scripts := append(slices.Clone(vals["e"]), vals["expression"]...)
	if len(scripts) == 0 && len(pos) > 0 {
		scripts = pos[:1]
	}
	for _, s := range scripts {
		if err := sedScriptReadOnly(s); err != nil {
			return fmt.Errorf("sed: %w", err)
		}
	}
	return nil
}

var errSedWrites = errors.New("the w, W, and e commands and the s///w and s///e flags are not allowed: they write a file or run a command")

// sedScriptReadOnly parses a sed script (GNU syntax, which covers POSIX and
// BSD sed) and refuses the commands that write or run something. What it does
// not understand it refuses.
func sedScriptReadOnly(s string) error {
	i := 0
	skipBlank := func() {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
	}
	// toEnd skips to the end of the line; toCmdEnd (a label) to the end of
	// the line, a ";", or a blank, whichever comes first.
	toEnd := func() {
		for i < len(s) && s[i] != '\n' {
			i++
		}
	}
	toCmdEnd := func() {
		for i < len(s) && s[i] != '\n' && s[i] != ';' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
	}
	// delimited skips a delimited part (after the delimiter) and the closing
	// delimiter.
	delimited := func(d byte) error {
		for i < len(s) {
			switch s[i] {
			case '\\':
				i += 2
				continue
			case d:
				i++
				return nil
			}
			i++
		}
		return fmt.Errorf("unterminated sed command")
	}
	address := func() error {
		switch {
		case i < len(s) && s[i] == '/':
			i++
			if err := delimited('/'); err != nil {
				return err
			}
		case i+1 < len(s) && s[i] == '\\':
			d := s[i+1]
			i += 2
			if err := delimited(d); err != nil {
				return err
			}
		case i < len(s) && s[i] == '$':
			i++
			return nil
		default:
			for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '~' || s[i] == '+') {
				i++
			}
			return nil
		}
		for i < len(s) && (s[i] == 'I' || s[i] == 'M') {
			i++
		}
		return nil
	}
	for i < len(s) {
		skipBlank()
		if i >= len(s) {
			break
		}
		switch s[i] {
		case '\n', ';', '}':
			i++
			continue
		case '#':
			toEnd()
			continue
		}
		if err := address(); err != nil {
			return err
		}
		skipBlank()
		if i < len(s) && s[i] == ',' {
			i++
			skipBlank()
			if err := address(); err != nil {
				return err
			}
		}
		for skipBlank(); i < len(s) && s[i] == '!'; skipBlank() {
			i++
		}
		if i >= len(s) {
			return fmt.Errorf("missing sed command")
		}
		c := s[i]
		i++
		switch c {
		case '{', '=', 'd', 'D', 'g', 'G', 'h', 'H', 'n', 'N', 'p', 'P', 'x', 'z', 'F':
		case 'l', 'L', 'q', 'Q':
			skipBlank()
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
			}
		case 'a', 'i', 'c':
			// Text up to an unescaped newline.
			for i < len(s) && s[i] != '\n' {
				if s[i] == '\\' {
					i++
				}
				i++
			}
		case ':', 'b', 't', 'T', 'v':
			toCmdEnd()
		case 'r', 'R':
			toEnd()
		case 's', 'y':
			if i >= len(s) || s[i] == '\n' || s[i] == '\\' {
				return fmt.Errorf("unterminated sed command")
			}
			d := s[i]
			i++
			if err := delimited(d); err != nil {
				return err
			}
			if err := delimited(d); err != nil {
				return err
			}
			if c == 'y' {
				break
			}
			for i < len(s) && s[i] != ';' && s[i] != '\n' && s[i] != '}' && s[i] != '#' && s[i] != ' ' && s[i] != '\t' {
				switch f := s[i]; {
				case f == 'w' || f == 'e':
					return errSedWrites
				case f == 'g' || f == 'p' || f == 'i' || f == 'I' || f == 'm' || f == 'M' || f >= '0' && f <= '9':
				default:
					return fmt.Errorf("unknown s flag %q", f)
				}
				i++
			}
		case 'w', 'W', 'e':
			return errSedWrites
		default:
			return fmt.Errorf("unknown sed command %q", c)
		}
	}
	return nil
}
