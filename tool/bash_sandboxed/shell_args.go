package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// shellInvocation is a bash/sh command line as the shell reads it: which
// word is the -c command string or the script file, and the options to
// apply before the script runs. parseShellArgs builds it; the static
// validator, the static script scan, executeBash, and the remote shell check
// all read a shell's argv through it, so they agree on which word runs.
type shellInvocation struct {
	// vals is each word's value, "" for one only known after expansion.
	vals []string
	// set is the options executeBash applies with set before the script
	// (-e, +x, -o pipefail); see shellSetFlags.
	set []string
	// command is the index of the -c command string, script that of the
	// script file; both are -1 when there is neither. The words after
	// either are the script's $0 (-c only), $1, ...
	command, script int
	// complete is false when a word whose value is only known after
	// expansion sits among the options: it may be an option (taking the next
	// word as its value, or ending the options) or the first operand, so
	// command and script are -1. The words after it are still checked
	// against blocked. The runtime layer parses the expanded argv again.
	complete bool
}

// readsStdin reports whether the shell reads its commands from stdin: it has
// neither a -c command string nor a script file.
func (inv shellInvocation) readsStdin() bool {
	return inv.complete && inv.command < 0 && inv.script < 0
}

// bashLongOptions are bash's long options (bash --help), with whether each
// takes the next word as its value. bash takes no --name=value form and no
// abbreviations, and reads long options only before its single-letter ones.
var bashLongOptions = map[string]bool{
	"debug": false, "debugger": false, "dump-po-strings": false, "dump-strings": false,
	"help": false, "init-file": true, "login": false, "noediting": false,
	"noprofile": false, "norc": false, "posix": false, "pretty-print": false,
	"rcfile": true, "restricted": false, "verbose": false, "version": false,
}

// shellSetFlags are the single-letter options executeBash applies with set,
// in either sign; the others the sandbox interpreter has no use for (-B, -h,
// -O's shopt names, ...) are parsed and dropped.
const shellSetFlags = "exunv"

// blockedBashFlags lists bash/sh flags that are not allowed. A letter is
// refused under either sign: bash reads +c, +l, and +s as -c, -l, and -s.
var blockedBashFlags = map[string]string{
	"-i":          "interactive mode is not allowed",
	"-s":          "reading commands from stdin is not allowed",
	"--init-file": "sourcing init files is not allowed",
	"--rcfile":    "sourcing rc files is not allowed",
	"-l":          "login shell is not allowed",
	"--login":     "login shell is not allowed",
}

// parseShellArgs reads a bash/sh invocation (words[0] is the shell) the way
// bash's own option parser does (shell.c's parse_long_options and
// parse_shell_options), refusing the flags in blocked:
//
//   - Long options (--norc) come first and are matched exactly; one that is
//     not bash's, or that follows a single-letter option, makes bash exit
//     with an error, so it is refused.
//   - Then each word starting with - or + is a cluster of single-letter
//     options, in either sign. c makes the first operand the command string;
//     o and O take the next word as their value. "-" and "--" end the
//     options; "+" alone is skipped.
//   - The first operand is the -c command string, or else the script file.
//     -c takes the first operand, not the next word: `bash -c -e 'cmd'` runs
//     cmd with -e.
//
// bash also reads a long option spelled with one dash (-norc) as the long
// one, where sh (dash) reads it as letters, which consume a different number
// of words (-norc's o takes the next one); such a word is refused, so every
// shell agrees on which word runs.
//
// A word that is not literal text leaves the parse incomplete: its value
// decides whether it is an option or an operand. It is skipped, and the
// words after it are still read as options, so a blocked flag among them is
// refused whatever it turns out to be.
func parseShellArgs(words []*syntax.Word, blocked map[string]string) (shellInvocation, error) {
	n := len(words)
	inv := shellInvocation{vals: make([]string, n), command: -1, script: -1}
	literal := make([]bool, n)
	for i, w := range words {
		inv.vals[i], literal[i] = wordLiteral(w)
	}
	name := inv.vals[0]
	refuse := func(flag, word string) error {
		reason, ok := blocked[flag]
		switch {
		case !ok:
			return nil
		case flag == word:
			return fmt.Errorf("%s: flag %q is not allowed: %s", name, flag, reason)
		default:
			return fmt.Errorf("%s: flag %q (in %q) is not allowed: %s", name, flag, word, reason)
		}
	}

	i := 1
	for ; i < n && literal[i] && strings.HasPrefix(inv.vals[i], "--") && inv.vals[i] != "--"; i++ {
		w := inv.vals[i]
		takesValue, ok := bashLongOptions[w[2:]]
		if !ok {
			return inv, fmt.Errorf("%s: unknown option %q", name, w)
		}
		if err := refuse(w, w); err != nil {
			return inv, err
		}
		if takesValue {
			i++
		}
	}

	cmdMode, unknown := false, false
options:
	for ; i < n; i++ {
		if !literal[i] {
			unknown = true
			continue
		}
		w := inv.vals[i]
		switch {
		case w == "-" || w == "--":
			i++
			break options
		case w == "" || (w[0] != '-' && w[0] != '+'):
			break options
		case strings.HasPrefix(w, "--"):
			return inv, fmt.Errorf("%s: long option %q must come before the single-letter options", name, w)
		case w[0] == '-' && isBashLongOption(w[1:]):
			return inv, fmt.Errorf("%s: option %q is read as --%s by bash and as single letters by sh; write --%s", name, w, w[1:], w[1:])
		}
		sign := w[:1]
		for _, ch := range w[1:] {
			if err := refuse("-"+string(ch), w); err != nil {
				return inv, err
			}
			switch {
			case ch == 'c':
				cmdMode = true
			case ch == 'o' || ch == 'O':
				i++
				if ch == 'o' && i < n {
					inv.set = append(inv.set, sign+"o", inv.vals[i])
				}
			case strings.ContainsRune(shellSetFlags, ch):
				inv.set = append(inv.set, sign+string(ch))
			}
		}
	}

	if unknown {
		return inv, nil
	}
	inv.complete = true
	switch {
	case i < n && cmdMode:
		inv.command = i
	case i < n:
		inv.script = i
	case cmdMode:
		return inv, fmt.Errorf("%s -c requires a command string argument", name)
	}
	return inv, nil
}

func isBashLongOption(name string) bool {
	_, ok := bashLongOptions[name]
	return ok
}

// shellScript is the commandSpec.script of bash and sh: the -c command
// string, or the script file.
func shellScript(args []*syntax.Word) (int, bool) {
	inv, err := parseShellArgs(args, blockedBashFlags)
	switch {
	case err != nil:
		return -1, false
	case inv.command >= 0:
		return inv.command, true
	default:
		return inv.script, false
	}
}

// sourcedFile is the commandSpec.script of source and .: the file they read.
func sourcedFile(args []*syntax.Word) (int, bool) {
	if len(args) < 2 {
		return -1, false
	}
	return 1, false
}
