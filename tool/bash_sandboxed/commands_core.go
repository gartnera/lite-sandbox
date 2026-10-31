package bash_sandboxed

import (
	"context"
	"path/filepath"
	"strings"
)

// The registrations of the coreutils-style commands: the readers and
// writers on the whitelist whose argument handling is small enough to state
// here. Commands with a module of their own (git, tar, ssh, gh, the
// wrappers, the profiles' toolchains) register in that module's file. See
// commandSpec for what each field means.

func init() {
	// Shell interpreters the sandbox runs itself: bash and sh -c scripts
	// and sourced files go back through the sandbox interpreter, awk runs
	// as goawk with system() and file writes disabled. A wrapper would
	// spawn the host's instead, with none of that (notWrappable).
	registerCommands(commandSpec{
		validate: validateBashArgs, notWrappable: true, revalidatesItself: true, inProcess: true,
		run: func(ctx context.Context, s *Sandbox, args []string, _ execEnv) (bool, error) {
			return true, s.executeBash(ctx, args)
		},
	}, "bash", "sh")
	registerCommands(commandSpec{
		validate: validateAwkArgs, notWrappable: true, revalidatesItself: true, inProcess: true,
		run: func(ctx context.Context, _ *Sandbox, args []string, _ execEnv) (bool, error) {
			return true, executeAwk(ctx, args)
		},
	}, "awk")
	registerCommands(commandSpec{validate: validateSourceArgs}, "source", ".")
	// At the top level `time` is a shell keyword (a TimeClause whose inner
	// command is walked and validated); as a real /usr/bin/time exec it is
	// a command wrapper of its own (and -o can write files), so a wrapper
	// reaching it would run its child command unvalidated.
	registerCommands(commandSpec{notWrappable: true}, "time")

	// Readers with a validator.
	registerCommands(commandSpec{validate: validateRgArgs}, "rg")
	registerCommands(commandSpec{validate: validateFindArgs}, "find")
	registerCommands(commandSpec{validate: validateDiff3Args}, "diff3")
	registerCommands(commandSpec{validate: validateSdiffArgs}, "sdiff")
	registerCommands(commandSpec{validate: validateLessArgs}, "less", "zless", "bzless", "xzless")
	registerCommands(commandSpec{validate: validateArchArgs}, "arch")
	registerCommands(commandSpec{validate: validateXzArgs}, "xzcat")

	// Readers whose patterns, delimiters, or program names are not paths.
	registerCommands(commandSpec{nonPathArgs: grepNonPathArgIndices},
		"grep", "egrep", "fgrep", "rgrep", "zgrep", "zegrep", "zfgrep",
		"bzgrep", "bzegrep", "bzfgrep", "xzgrep", "xzegrep", "xzfgrep")
	registerCommands(commandSpec{nonPathArgs: allArgsNonPaths}, "pidof")
	registerCommands(commandSpec{noFlagPaths: true}, "cut", "tr") // cut -d/, -f; tr's char classes

	// Writers: every path argument is checked against the write set, and
	// the ones they write against .claude.
	registerCommands(commandSpec{writes: true, validate: validateRmArgs, writeTargets: operandTargets(optSpec{})}, "rm")
	registerCommands(commandSpec{writes: true, writeTargets: operandTargets(optSpec{})}, "tee", "unlink", "rmdir")
	registerCommands(commandSpec{writes: true, writeTargets: operandTargets(optSpec{short: "dtr", long: []string{"date", "reference"}})}, "touch")
	registerCommands(commandSpec{writes: true, writeTargets: operandTargets(optSpec{short: "m", long: []string{"mode", "context"}})}, "mkdir")
	registerCommands(commandSpec{writes: true, writeTargets: operandTargets(optSpec{short: "ns", long: []string{"iterations", "size", "random-source"}})}, "shred")
	registerCommands(commandSpec{writes: true, writeTargets: operandTargets(optSpec{short: "sr", long: []string{"size", "reference"}})}, "truncate")
	registerCommands(commandSpec{writes: true, writeTargets: operandTargets(optSpec{short: "lo", long: []string{"length", "offset"}})}, "fallocate")
	registerCommands(commandSpec{writes: true, writeTargets: operandTargets(optSpec{short: "m", long: []string{"mode"}})}, "mkfifo")
	registerCommands(commandSpec{writes: true, writeTargets: mvTargets}, "mv")
	registerCommands(commandSpec{writes: true, writeTargets: cpTargets}, "cp")
	registerCommands(commandSpec{writes: true, writeTargets: lnTargets}, "ln")
	registerCommands(commandSpec{writes: true, writeTargets: linkTargets}, "link")
	registerCommands(commandSpec{writes: true, writeTargets: func(args []string, _ map[int]bool) []string { return chmodTargets(args) }}, "chmod")
	registerCommands(commandSpec{writes: true, writeTargets: chownTargets}, "chown", "chgrp")
	registerCommands(commandSpec{writes: true, validate: validateInstallArgs, writeTargets: installTargets}, "install")
	registerCommands(commandSpec{writes: true, validate: validateSedArgs, nonPathArgs: sedNonPathArgIndices, writeTargets: sedTargets}, "sed")

	// Readers that write only some of their arguments: those are checked
	// against the write set and .claude.
	registerCommands(commandSpec{validate: validateGzipArgs, writeTargets: compressTargets(gzipSpec)}, "gzip", "gunzip")
	registerCommands(commandSpec{validate: validateXzArgs, writeTargets: compressTargets(xzSpec)}, "xz", "unxz")
	registerCommands(commandSpec{writeTargets: compressTargets(optSpec{})}, "bzip2", "bunzip2")
	registerCommands(commandSpec{validate: validateSplitArgs, writeTargets: splitTargets}, "split")
	registerCommands(commandSpec{writeTargets: csplitTargets}, "csplit")
	registerCommands(commandSpec{writeTargets: outputOptionTargets(optSpec{short: "ino", long: []string{"input-range", "head-count", "output", "random-source"}})}, "shuf")
	registerCommands(commandSpec{noFlagPaths: true, writeTargets: outputOptionTargets(optSpec{ // sort -t<sep>
		short: "ktSTo",
		long:  []string{"key", "field-separator", "buffer-size", "temporary-directory", "output", "batch-size", "compress-program", "files0-from", "parallel", "random-source", "sort"},
	})}, "sort")
	registerCommands(commandSpec{writeTargets: outputOptionTargets(optSpec{short: "fto", long: []string{"from-code", "to-code", "output"}})}, "iconv")
	registerCommands(commandSpec{writeTargets: secondOperandTargets(optSpec{short: "fsw", long: []string{"skip-fields", "skip-chars", "check-chars"}})}, "uniq")
	registerCommands(commandSpec{writeTargets: secondOperandTargets(optSpec{short: "cglosnR"})}, "xxd")
	registerCommands(commandSpec{writeTargets: yqTargets}, "yq")
	// dd's operands are KEY=VALUE: if= is read-checked, of= write-checked.
	registerCommands(commandSpec{
		nonPathArgs:  allArgsNonPaths,
		writeTargets: func(args []string, _ map[int]bool) []string { return ddOperands(args, "of") },
		checkPaths: func(args []string, workDir string, sets resolvedPathSets) error {
			return validateDdReads(args, workDir, sets.read)
		},
	}, "dd")
	// mktemp writes under $TMPDIR, contained by the OS sandbox's private
	// /tmp (see allowedCommands); only its .claude check applies.
	registerCommands(commandSpec{writeTargets: mktempTargets, targetsConfinedElsewhere: true}, "mktemp")
}

func mvTargets(args []string, _ map[int]bool) []string {
	pos, vals, _ := optSpec{short: "tS", long: []string{"target-directory", "suffix"}}.parse(args, nil)
	return append(pos, targetDirs(vals)...)
}

// cpTargets returns the destination of cp: its -t directory, or its last
// operand.
func cpTargets(args []string, _ map[int]bool) []string {
	pos, vals, _ := optSpec{short: "tS", long: []string{"target-directory", "suffix"}}.parse(args, nil)
	if dirs := targetDirs(vals); len(dirs) > 0 {
		return dirs
	}
	if len(pos) >= 2 {
		return pos[len(pos)-1:]
	}
	return nil
}

// lnTargets is cpTargets, but ln TARGET creates the link in the current
// directory.
func lnTargets(args []string, skip map[int]bool) []string {
	pos, vals, _ := optSpec{short: "tS", long: []string{"target-directory", "suffix"}}.parse(args, nil)
	if len(targetDirs(vals)) == 0 && len(pos) == 1 {
		return []string{"."}
	}
	return cpTargets(args, skip)
}

func linkTargets(args []string, _ map[int]bool) []string {
	pos, _, _ := optSpec{}.parse(args, nil)
	if len(pos) >= 2 {
		return pos[1:]
	}
	return nil
}

func chownTargets(args []string, _ map[int]bool) []string {
	pos, _, flags := optSpec{long: []string{"from", "reference"}}.parse(args, nil)
	if flags["reference"] || len(pos) == 0 {
		return pos
	}
	return pos[1:] // the first operand is the owner or group
}

func installTargets(args []string, _ map[int]bool) []string {
	pos, vals, flags := installSpec.parse(args, nil)
	if flags["d"] || flags["directory"] {
		return pos
	}
	if dirs := targetDirs(vals); len(dirs) > 0 {
		return dirs
	}
	if len(pos) >= 2 {
		return pos[len(pos)-1:]
	}
	return nil
}

func sedTargets(args []string, skip map[int]bool) []string {
	pos, _, flags := optSpec{short: "efl", long: []string{"expression", "file", "line-length"}}.parse(args, skip)
	if flags["i"] || flags["in-place"] {
		return pos
	}
	return nil
}

// compressTargets is the writeTargets of gzip, bzip2, xz, and their
// decompressors: each operand is replaced by its (de)compressed file beside
// it, unless the output goes to stdout or nothing is written.
func compressTargets(spec optSpec) func(args []string, skip map[int]bool) []string {
	return func(args []string, _ map[int]bool) []string {
		pos, _, flags := spec.parse(args, nil)
		for _, f := range []string{"c", "stdout", "to-stdout", "t", "test", "l", "list"} {
			if flags[f] {
				return nil
			}
		}
		return pos
	}
}

// splitTargets: split [FILE [PREFIX]] writes PREFIXaa, PREFIXab, ...
// (default x).
func splitTargets(args []string, _ map[int]bool) []string {
	pos, _, _ := splitSpec.parse(args, nil)
	if len(pos) >= 2 {
		return pos[1:]
	}
	return []string{"x"}
}

// csplitTargets: csplit writes PREFIX followed by the suffix format
// (default xx%02d); the format may hold a "/", so the two are checked
// joined.
func csplitTargets(args []string, _ map[int]bool) []string {
	_, vals, _ := optSpec{short: "bfn", long: []string{"suffix-format", "prefix", "digits"}}.parse(args, nil)
	prefix, suffix := "xx", ""
	if p := append(vals["f"], vals["prefix"]...); len(p) > 0 {
		prefix = p[len(p)-1]
	}
	if b := append(vals["b"], vals["suffix-format"]...); len(b) > 0 {
		suffix = b[len(b)-1]
	}
	return []string{prefix + suffix}
}

func mktempTargets(args []string, _ map[int]bool) []string {
	pos, vals, _ := optSpec{short: "p"}.parse(args, nil)
	dirs := append(vals["p"], vals["tmpdir"]...)
	out := append(append([]string(nil), dirs...), pos...)
	for _, d := range dirs {
		for _, p := range pos {
			if d != "" && p != "" {
				out = append(out, filepath.Join(d, p))
			}
		}
	}
	return out
}

func yqTargets(args []string, _ map[int]bool) []string {
	pos, _, flags := optSpec{short: "Iops", long: []string{"indent", "output-format", "input-format", "split-exp", "expression"}}.parse(args, nil)
	if flags["i"] || flags["inplace"] {
		return pos
	}
	return nil
}

// targetDirs returns the -t / --target-directory values of cp, mv, and ln.
func targetDirs(vals map[string][]string) []string {
	return append(append([]string(nil), vals["t"]...), vals["target-directory"]...)
}

// chmodTargets returns the files chmod changes: every operand but the mode,
// which is the first operand unless --reference supplies it. A mode can start
// with a dash (chmod -w file), so a dash argument that is not made of chmod's
// own flags (-R, -v, -c, -f) is the mode, and every operand is a file.
func chmodTargets(args []string) []string {
	var pos []string
	modeSeen := false
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "--") {
			if strings.HasPrefix(a, "--reference") {
				modeSeen = true
			}
			continue
		}
		if len(a) > 1 && a[0] == '-' {
			if strings.Trim(a[1:], "Rvcf") != "" {
				modeSeen = true
			}
			continue
		}
		pos = append(pos, a)
	}
	if !modeSeen && len(pos) > 0 {
		return pos[1:]
	}
	return pos
}
