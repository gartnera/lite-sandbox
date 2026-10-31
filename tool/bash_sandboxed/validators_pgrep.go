package bash_sandboxed

import (
	"fmt"

	"mvdan.cc/sh/v3/syntax"
)

// pgrepOpts is procps-ng pgrep's option table; macOS's BSD pgrep takes a
// subset of its value options with getopt, which stops at the first
// operand (bsdPgrepOpts).
var (
	pgrepOpts = optSpec{
		short: "dgGPstuUFrO",
		long: []string{
			"delimiter", "pgroup", "group", "parent", "session", "signal", "terminal",
			"euid", "uid", "pidfile", "runstates", "older", "cgroup", "ns", "nslist",
		},
		flags: []string{
			"count", "full", "ignore-case", "list-name", "list-full", "newest", "oldest",
			"inverse", "lightweight", "exact", "logpidfile", "require-handler", "env", "help", "version",
		},
		alias: map[string]string{"pidfile": "F"},
	}
	bsdPgrepOpts = optSpec{short: "FGMNPUdgstu", stopAtOperand: true}
)

// pgrepPidfiles returns, over every reading of a pgrep command line, the
// indices of the words that name a pid file (-F FILE, --pidfile FILE) and of
// the options carrying one attached (-FFILE, -lFFILE, --pidfile=FILE). The
// pid file is the only file pgrep reads; every other argument is a pattern or
// an option value.
func pgrepPidfiles(args []string) (pidfiles, attached map[int]bool) {
	pidfiles, attached = map[int]bool{}, map[int]bool{}
	for _, sp := range []optSpec{pgrepOpts, bsdPgrepOpts, {short: pgrepOpts.short, long: pgrepOpts.long, flags: pgrepOpts.flags, alias: pgrepOpts.alias, stopAtOperand: true}} {
		for _, o := range sp.scan(args).opts {
			switch {
			case o.name != "F" || !o.hasValue:
			case o.valueIndex >= 0:
				pidfiles[o.valueIndex] = true
			default:
				attached[o.index] = true
			}
		}
	}
	return pidfiles, attached
}

// pgrepNonPathArgIndices returns every argument index except the pid files
// pgrepPidfiles finds: pgrep's patterns (`pgrep -f /usr/bin/node`) and option
// values are not paths, so only the pid file is held to the path boundary.
// Attached pid files are left to the generic flag check as well, though
// validatePgrepArgs refuses them outright.
func pgrepNonPathArgIndices(args []string) map[int]bool {
	pidfiles, attached := pgrepPidfiles(args)
	skip := make(map[int]bool)
	for i := 1; i < len(args); i++ {
		if !pidfiles[i] && !attached[i] {
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
	_, attached := pgrepPidfiles(texts)
	for i := range texts {
		if attached[i] {
			return fmt.Errorf("pgrep %s: pass the pid file as its own argument (-F FILE)", texts[i])
		}
	}
	return nil
}
