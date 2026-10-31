package bash_sandboxed

import (
	"context"
	"fmt"
	"sync"

	"mvdan.cc/sh/v3/syntax"
)

// commandSpec is everything the sandbox knows about how one command treats
// its arguments, beyond whether it may run at all (the whitelist:
// allowedCommands, the profiles, the ssh section). The generic validation
// layers — the static walk, the runtime Call/Exec handlers, the path
// checks, the .claude write check, wrapper recursion, and unsandboxed
// routing — look a command up here instead of switching on its name, so a
// command's behavior lives in one registration next to its validator.
//
// Supporting a new command takes one entry in commandTable (plus its
// whitelist entry); none of the layers change. A command with no entry is a
// plain reader: every path-like argument is checked against the read set,
// and it has no validator.
type commandSpec struct {
	// validate is the argument validator: it refuses the invocations, or
	// the flags, the sandbox cannot let run (find -delete, git push). It
	// runs on the AST in the static pass, on the expanded argv in the
	// runtime pass (unless revalidatesItself), and on a wrapped command.
	validate argValidator

	// writes checks every path-like argument against the write set rather
	// than the read set (cp, rm, sed). A command that writes only some of
	// its arguments (dd of=, sort -o) is a reader with writeTargets.
	writes bool
	// writeTargets returns the arguments that name a file the command
	// creates, modifies, or removes; each is checked against the write set
	// (validateWriteTargets) and the read-only .claude directories
	// (validateClaudeDirWrites). skip holds the arguments nonPathArgs
	// reported. It errs toward listing an argument.
	writeTargets func(args []string, skip map[int]bool) []string
	// targetsConfinedElsewhere leaves writeTargets to the .claude check
	// alone: the command's writes are confined by its own validator (git)
	// or land under $TMPDIR (mktemp).
	targetsConfinedElsewhere bool
	// nonPathArgs returns the indices of args (the command name at 0) that
	// are not file paths whatever they look like — patterns, scripts,
	// hosts, URL paths — so the generic path check skips them.
	nonPathArgs func(args []string) map[int]bool
	// args declares the command's options and what its option values and
	// operands are; nonPathArgs and writeTargets are derived from it.
	args *argLayout
	// noFlagPaths: the values attached to its flags are never paths
	// (cut -d/), so they are not extracted for the path check.
	noFlagPaths bool
	// checkPaths checks the paths the generic pass cannot see: files read
	// or written through an option's value or the command's own syntax
	// (dd if=, tar -c's operands under -C, what unzip extracts into).
	checkPaths func(args []string, workDir string, sets resolvedPathSets) error

	// script returns the index in args of the shell script the command
	// runs, or -1, so the static pass can validate the script's commands
	// before anything runs (validateScriptContents): the file it reads
	// (bash's script operand, source's file), or with inline the script
	// itself (bash -c's command string).
	script func(args []*syntax.Word) (idx int, inline bool)
	// sourcesScript: script runs in the calling shell (source, .), so the
	// functions it declares can be called after it (collectDeclaredFunctions).
	sourcesScript bool

	// unwrap returns the command a wrapper runs (command name first), or
	// nil when it runs none, so the path checks and unsandboxed routing
	// see through it (see unwrapWrapperArgs).
	unwrap func(args []string) []string
	// notWrappable refuses the command under a wrapper (find -exec,
	// xargs, env, ...): its safety relies on the sandbox interpreter
	// running it (see validateSubCommand).
	notWrappable bool
	// revalidatesItself skips validate on the runtime layer: the command
	// is dispatched to a dedicated executor that re-parses and re-validates
	// what it runs (bash, sh, awk).
	revalidatesItself bool
	// inProcess: the command runs inside the lite-sandbox process and opens
	// its file operands with the host's descriptors, so a standard-stream
	// name (/dev/stdout) there is not the command's own (isStdStreamArg).
	inProcess bool

	// prepareExec rewrites the expanded argv once every gate has passed and
	// before it runs, to make the command honor the sandbox's policy
	// (deno's permission flags) or work inside it (SwiftPM's nested
	// sandbox).
	prepareExec func(ctx context.Context, s *Sandbox, args []string, x execEnv) []string
	// run executes the command in place of a host program: awk as goawk,
	// bash and sh through the sandbox interpreter, python in monty.
	// handled is false to run it the ordinary way after all.
	run func(ctx context.Context, s *Sandbox, args []string, x execEnv) (handled bool, err error)
}

// execEnv is what the ExecHandler hands a command's prepareExec and run: the
// boundary it runs under and whether it runs in the OS sandbox.
type execEnv struct {
	useOSSandbox                        bool
	readAllowedPaths, writeAllowedPaths []string
	sets                                resolvedPathSets
}

// argValidator is a per-command argument validator. It receives the
// *Sandbox so it can read the config (git levels, profile options).
type argValidator func(s *Sandbox, args []*syntax.Word) error

var (
	commandSpecsOnce sync.Once
	commandSpecs     map[string]*commandSpec
)

// lookupCommand returns name's spec (see commandTable), or the plain
// reader's.
func lookupCommand(name string) *commandSpec {
	commandSpecsOnce.Do(func() { commandSpecs = buildCommandSpecs(commandTable()) })
	if sp, ok := commandSpecs[name]; ok {
		return sp
	}
	return noSpec
}

// buildCommandSpecs fills in what a spec's argLayout derives.
func buildCommandSpecs(table map[string]commandSpec) map[string]*commandSpec {
	out := make(map[string]*commandSpec, len(table))
	for name, spec := range table {
		if spec.args != nil {
			if spec.nonPathArgs != nil || spec.writeTargets != nil {
				panic(fmt.Sprintf("command %q has both an argLayout and its own argument roles", name))
			}
			spec.nonPathArgs = spec.args.nonPathArgs
			spec.writeTargets = spec.args.writeTargets
		}
		out[name] = &spec
	}
	return out
}

// noSpec is what an unregistered command looks up: a plain reader.
var noSpec = &commandSpec{}

// validator returns the argument validator s holds for name: the remote
// table's for a remote-command checker (Sandbox.argValidators), the
// command's commandSpec's otherwise.
func (s *Sandbox) validator(name string) (argValidator, bool) {
	if s.argValidators != nil {
		v, ok := s.argValidators[name]
		return v, ok
	}
	v := lookupCommand(name).validate
	return v, v != nil
}

// allArgsNonPaths is a nonPathArgs for a command none of whose operands are
// paths (pidof's program names, dd's KEY=VALUE pairs).
func allArgsNonPaths(args []string) map[int]bool {
	skip := make(map[int]bool, len(args))
	for i := 1; i < len(args); i++ {
		skip[i] = true
	}
	return skip
}
