package bash_sandboxed

import (
	"context"

	"mvdan.cc/sh/v3/syntax"
)

// commandTable is every command the sandbox knows more about than its name
// (see commandSpec): one statically declared table, so a command's whole
// treatment is in one entry and a name listed twice does not compile. The
// whitelist itself is allowedCommands, the profiles, and the config's
// sections.
//
// It is a function rather than a package variable because the validators
// it names look commands up in it (validateSubCommand), which Go refuses as
// an initialization cycle; lookupCommand builds it once, on first use.
func commandTable() map[string]commandSpec {
	bash := commandSpec{
		validate: validateBashArgs, script: shellScript, notWrappable: true, revalidatesItself: true, inProcess: true,
		run: func(ctx context.Context, s *Sandbox, args []string, _ execEnv) (bool, error) {
			return true, s.executeBash(ctx, args)
		},
	}
	source := commandSpec{validate: validateSourceArgs, script: sourcedFile, sourcesScript: true}
	grep := commandSpec{args: grepLayout}
	less := commandSpec{validate: validateLessArgs}
	wrapper := commandSpec{validate: validateWrapperArgs, unwrap: unwrapWrapper}
	// python and python3 run in the embedded monty interpreter (python.go).
	// A wrapper would spawn the real CPython from $PATH, which has none of
	// monty's isolation (notWrappable; see pythonOptedOutToHost for the
	// exception).
	python := commandSpec{validate: validatePythonArgs, nonPathArgs: pythonNonPathArgIndices, notWrappable: true, inProcess: true, run: runPythonHook}
	copyCommand := func(name string) commandSpec {
		return commandSpec{
			validate:     validateCopyCommand,
			nonPathArgs:  copyNonPathArgIndices,
			writeTargets: func(args []string, _ map[int]bool) []string { return copyWrites(args) },
			checkPaths:   copyReadPaths(name),
		}
	}
	return map[string]commandSpec{
		// Shell interpreters the sandbox runs itself: bash and sh -c scripts
		// and sourced files go back through the sandbox interpreter, awk runs
		// as goawk with system() and file writes disabled. A wrapper would
		// spawn the host's instead, with none of that (notWrappable).
		"bash": bash,
		"sh":   bash,
		"awk": {
			validate: validateAwkArgs, notWrappable: true, revalidatesItself: true, inProcess: true,
			run: func(ctx context.Context, _ *Sandbox, args []string, _ execEnv) (bool, error) {
				return true, executeAwk(ctx, args)
			},
		},
		"source": source,
		".":      source,
		// At the top level `time` is a shell keyword (a TimeClause whose
		// inner command is walked and validated); as a real /usr/bin/time
		// exec it is a command wrapper of its own (and -o can write files),
		// so a wrapper reaching it would run its child command unvalidated.
		"time": {notWrappable: true},

		// Command wrappers (wrappers.go).
		"xargs":   wrapper,
		"env":     wrapper,
		"timeout": wrapper,
		"nice":    wrapper,
		"nohup":   wrapper,
		"setsid":  wrapper,
		"stdbuf":  wrapper,

		// Readers with a validator.
		"rg":     {validate: validateRgArgs},
		"find":   {validate: validateFindArgs},
		"diff3":  {validate: validateDiff3Args},
		"sdiff":  {validate: validateSdiffArgs},
		"less":   less,
		"zless":  less,
		"bzless": less,
		"xzless": less,
		"arch":   {validate: validateArchArgs},
		"xzcat":  {validate: validateXzArgs},

		// Readers whose patterns, delimiters, or program names are not paths.
		"grep": grep, "egrep": grep, "fgrep": grep, "rgrep": grep,
		"zgrep": grep, "zegrep": grep, "zfgrep": grep,
		"bzgrep": grep, "bzegrep": grep, "bzfgrep": grep,
		"xzgrep": grep, "xzegrep": grep, "xzfgrep": grep,
		"pidof": {nonPathArgs: allArgsNonPaths},
		"pgrep": {validate: validatePgrepArgs, nonPathArgs: pgrepNonPathArgIndices},
		"cut":   {noFlagPaths: true}, // cut -d/, -f
		"tr":    {noFlagPaths: true}, // character classes

		// Writers: every path argument is checked against the write set, and
		// the ones they write against agent configuration too.
		"rm":        {writes: true, validate: validateRmArgs, args: writesOperands(optSpec{})},
		"tee":       {writes: true, args: writesOperands(optSpec{})},
		"unlink":    {writes: true, args: writesOperands(optSpec{})},
		"rmdir":     {writes: true, args: writesOperands(optSpec{})},
		"touch":     {writes: true, args: writesOperands(optSpec{short: "dtr", long: []string{"date", "reference", "time"}})},
		"mkdir":     {writes: true, args: writesOperands(optSpec{short: "m", long: []string{"mode"}, flags: []string{"context", "parents", "verbose"}})},
		"mkfifo":    {writes: true, args: writesOperands(optSpec{short: "m", long: []string{"mode"}, flags: []string{"context"}})},
		"shred":     {writes: true, args: writesOperands(optSpec{short: "ns", long: []string{"iterations", "size", "random-source"}, flags: []string{"remove"}})},
		"truncate":  {writes: true, args: writesOperands(optSpec{short: "sr", long: []string{"size", "reference"}})},
		"fallocate": {writes: true, args: writesOperands(optSpec{short: "lo", long: []string{"length", "offset"}})},
		"mv":        {writes: true, args: mvLayout},
		"cp":        {writes: true, args: cpLayout},
		"ln":        {writes: true, args: lnLayout},
		"link":      {writes: true, args: &argLayout{lead: 1, operands: roleWrite}},
		"chmod":     {writes: true, args: chmodLayout},
		"chown":     {writes: true, args: chownLayout},
		"chgrp":     {writes: true, args: chownLayout},
		"install":   {writes: true, validate: validateInstallArgs, args: installLayout},
		"sed":       {writes: true, validate: validateSedArgs, args: sedLayout},

		// Readers that write only some of their arguments: those are checked
		// against the write set and agent configuration.
		"gzip":    {validate: validateGzipArgs, args: gzipLayout},
		"gunzip":  {validate: validateGzipArgs, args: gzipLayout},
		"xz":      {validate: validateXzArgs, args: xzLayout},
		"unxz":    {validate: validateXzArgs, args: xzLayout},
		"bzip2":   {args: bzip2Layout},
		"bunzip2": {args: bzip2Layout},
		"split":   {validate: validateSplitArgs, args: splitLayout},
		"csplit":  {args: csplitLayout},
		"shuf":    {args: outputOptionLayout(optSpec{short: "ino", long: []string{"input-range", "head-count", "output", "random-source"}})},
		"sort":    {noFlagPaths: true, validate: validateSortArgs, args: outputOptionLayout(sortSpec)}, // sort -t<sep>
		"iconv":   {args: outputOptionLayout(optSpec{short: "fto", long: []string{"from-code", "to-code", "output"}})},
		"uniq":    {args: secondOperandLayout(optSpec{short: "fsw", long: []string{"skip-fields", "skip-chars", "check-chars"}})},
		"xxd":     {args: secondOperandLayout(optSpec{short: "cglosnR"})},
		"yq":      {args: yqLayout},
		// dd's operands are KEY=VALUE: if= is read-checked, of= write-checked.
		"dd": {
			nonPathArgs:  allArgsNonPaths,
			writeTargets: func(args []string, _ map[int]bool) []string { return ddOperands(args, "of") },
			checkPaths: func(args []string, workDir string, sets resolvedPathSets) error {
				return validateDdReads(args, workDir, sets.read)
			},
		},
		// mktemp writes under $TMPDIR, contained by the OS sandbox's private
		// /tmp (see allowedCommands); only its agent-config check applies.
		"mktemp": {args: mktempLayout, targetsConfinedElsewhere: true},

		// Archivers (validators_archive.go).
		"tar": {
			validate: validateTarArgs,
			checkPaths: func(args []string, workDir string, sets resolvedPathSets) error {
				if err := validateTarCreateReads(args, workDir, sets.read); err != nil {
					return err
				}
				return validateArchiveWrites("tar", args, workDir, sets.write)
			},
		},
		"unzip": {validate: validateUnzipArgs, checkPaths: archiveWrites("unzip")},
		"zip":   {validate: validateZipArgs, checkPaths: archiveWrites("zip")},
		"ar":    {validate: validateArArgs},

		// git's global path flags (-C, --git-dir, ...) say where it runs, not
		// what it reads; what it writes in the work tree is confined by its
		// level checks, so only agent configuration is checked against its
		// targets.
		"git": {
			validate:                 validateGitCommand,
			nonPathArgs:              gitGlobalPathArgIndices,
			writeTargets:             func(args []string, _ map[int]bool) []string { return gitWriteTargets(args) },
			targetsConfinedElsewhere: true,
		},

		// Gated by the config (commands.go).
		"aws":    {validate: validateAWSCommand},
		"docker": {validate: validateDockerCommand},

		// The ssh section's commands (validators_ssh*.go).
		"ssh": {
			validate:     validateSSHCommand,
			nonPathArgs:  sshNonPathArgIndices,
			writeTargets: func(args []string, _ map[int]bool) []string { return sshControlPathWrites(args) },
		},
		"sshpass": {
			validate:    validateSSHPassCommand,
			nonPathArgs: sshpassNonPathArgIndices,
			writeTargets: func(args []string, _ map[int]bool) []string {
				if inner := sshpassCopyArgs(args); inner != nil {
					return copyWrites(inner)
				}
				if cmdIdx, _, _, err := parseSSHPassArgs(args); err == nil && cmdIdx < len(args) && args[cmdIdx] == "ssh" {
					return sshControlPathWrites(args[cmdIdx:])
				}
				return nil
			},
			checkPaths: copyReadPaths("sshpass"),
		},
		"scp":   copyCommand("scp"),
		"rsync": copyCommand("rsync"),

		// The commands a profile (config/profiles.go) whitelists that the
		// sandbox knows more about than their name. The sandbox never asks
		// which profile is enabled — it is handed one commands list with
		// each enabled profile's commands already in it
		// (config.Config.Effective) — so a validator runs whenever its
		// command runs, whitelisted or not: in denylist mode an unlisted
		// `go run pkg@latest` is still refused. gofmt, rustc, swiftc,
		// flutter/dart/fvm, and uvx have nothing to validate: gofmt is a
		// pure formatter, rustc and swiftc compile what they are given, the
		// Flutter tools and uvx run code the OS sandbox confines like
		// `go test`.
		//
		// go generate runs the shell commands in //go:generate directives;
		// go install writes the host's GOBIN.
		"go": {validate: func(s *Sandbox, args []*syntax.Word) error {
			return validateGoArgs(args, s.extraAllowsTokens("go", "generate"), s.extraAllowsTokens("go", "install"))
		}},
		"pnpm": {validate: func(s *Sandbox, args []*syntax.Word) error {
			return validatePnpmArgs(args, s.extraAllowsTokens("pnpm", "publish"))
		}},
		"cargo": {validate: func(s *Sandbox, args []*syntax.Word) error {
			return validateCargoArgs(args, s.extraAllowsTokens("cargo", "publish"))
		}},
		"deno": {
			validate: func(s *Sandbox, args []*syntax.Word) error {
				return validateDenoArgs(args, s.extraAllowsTokens("deno", "publish"), s.getConfig().ProfileOption("deno", "allow_import"))
			},
			prepareExec: denoPrepareExec,
		},
		"uv": {validate: func(s *Sandbox, args []*syntax.Word) error {
			return validateUvArgs(args, s.extraAllowsTokens("uv", "publish"))
		}},
		// gh runs in a worker of its own holding the token
		// (validators_gh.go); the files gh api and --attach upload are
		// read-checked.
		"gh": {
			validate:    validateGhCommand,
			nonPathArgs: ghNonPathArgIndices,
			checkPaths: func(args []string, workDir string, sets resolvedPathSets) error {
				return validateGhReads(args, workDir, sets.read)
			},
		},
		"python":  python,
		"python3": python,
		// The xcode profile's tools (validators_xcode.go). swiftc compiles
		// what it is given, like rustc, so it has no validator; nor has
		// xcodegen, whose spec's preGenCommand/postGenCommand run under the
		// OS sandbox like a build script.
		"xcodebuild":   {validate: validateXcodebuildArgs, prepareExec: xcodePrepareExec},
		"xcrun":        {validate: validateXcrunArgs, unwrap: unwrapXcrunArgs, prepareExec: xcodePrepareExec},
		"swift":        {validate: validateSwiftArgs, prepareExec: xcodePrepareExec},
		"xcode-select": {validate: validateXcodeSelectArgs},
	}
}
