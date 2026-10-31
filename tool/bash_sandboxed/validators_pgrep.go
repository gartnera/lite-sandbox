package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// pgrepShortValueOpts are the pgrep short options that take a value
// (procps-ng; macOS's BSD pgrep takes a subset of them).
const pgrepShortValueOpts = "dgGPstuUFrO"

// pgrepLongValueOpts are the procps-ng pgrep long options that take a value.
var pgrepLongValueOpts = []string{
	"delimiter", "pgroup", "group", "parent", "session", "signal", "terminal",
	"euid", "uid", "pidfile", "runstates", "older", "cgroup", "ns", "nslist",
}

// isPgrepPidfileLong reports whether name (a long option without its "--")
// selects --pidfile, which getopt_long also accepts abbreviated.
func isPgrepPidfileLong(name string) bool {
	return len(name) >= 2 && strings.HasPrefix("pidfile", name)
}

// pgrepLongTakesValue reports whether name, possibly abbreviated, is a long
// option that takes a value.
func pgrepLongTakesValue(name string) bool {
	for _, opt := range pgrepLongValueOpts {
		if name != "" && strings.HasPrefix(opt, name) {
			return true
		}
	}
	return false
}

// scanPgrepArgs walks pgrep's arguments the way getopt does (options may
// follow the pattern) and returns the indices of the arguments that name a
// pid file (-F FILE, --pidfile FILE) and of the ones carrying a pid file
// embedded in the option itself (-FFILE, -lFFILE, --pidfile=FILE). The pid
// file is the only file pgrep reads; every other argument is a pattern or an
// option value.
func scanPgrepArgs(args []string) (pidfiles, embedded map[int]bool) {
	pidfiles = make(map[int]bool)
	embedded = make(map[int]bool)
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			continue // pattern
		}
		if strings.HasPrefix(arg, "--") {
			name, _, hasValue := strings.Cut(arg[2:], "=")
			if hasValue {
				if isPgrepPidfileLong(name) {
					embedded[i] = true
				}
				continue
			}
			if pgrepLongTakesValue(name) && i+1 < len(args) {
				i++
				if isPgrepPidfileLong(name) {
					pidfiles[i] = true
				}
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			c := arg[j]
			if !strings.ContainsRune(pgrepShortValueOpts, rune(c)) {
				continue
			}
			// The rest of the cluster is the value; without one, the next
			// argument is, whatever it starts with.
			if j+1 < len(arg) {
				if c == 'F' {
					embedded[i] = true
				}
			} else if i+1 < len(args) {
				i++
				if c == 'F' {
					pidfiles[i] = true
				}
			}
			break
		}
	}
	return pidfiles, embedded
}

// pgrepNonPathArgIndices returns every argument index except the pid files
// scanPgrepArgs finds: pgrep's patterns (`pgrep -f /usr/bin/node`) and option
// values are not paths, so only the pid file is held to the path boundary.
// Embedded pid files are left to the generic flag check as well, though
// validatePgrepArgs refuses them outright.
func pgrepNonPathArgIndices(args []string) map[int]bool {
	pidfiles, embedded := scanPgrepArgs(args)
	skip := make(map[int]bool)
	for i := 1; i < len(args); i++ {
		if !pidfiles[i] && !embedded[i] {
			skip[i] = true
		}
	}
	return skip
}

// validatePgrepArgs refuses a pid file passed inside its option (-Ffile,
// -lFfile, --pidfile=file). The path check finds a pid file only as an
// argument of its own, and the generic flag extraction misreads a cluster
// like -lF/etc/secret (it would check "F/etc/secret", a relative path).
func validatePgrepArgs(_ *Sandbox, args []*syntax.Word) error {
	texts := make([]string, len(args))
	for i, w := range args {
		texts[i] = wordText(w)
	}
	_, embedded := scanPgrepArgs(texts)
	for i := range texts {
		if embedded[i] {
			return fmt.Errorf("pgrep %s: pass the pid file as its own argument (-F FILE)", texts[i])
		}
	}
	return nil
}

func init() {
	registerCommands(commandSpec{validate: validatePgrepArgs, nonPathArgs: pgrepNonPathArgIndices}, "pgrep")
}
