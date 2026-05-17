package bash_sandboxed

import (
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

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

// isFindExecTerminator reports whether lit is a find -exec sequence terminator.
// find accepts \; (backslash-semicolon) or + as terminators.
func isFindExecTerminator(lit string) bool {
	return lit == ";" || lit == `\;` || lit == "+"
}

// validateFindArgs checks that find is not called with dangerous flags.
// For -exec/-execdir/-ok/-okdir, the embedded subcommand is extracted and
// validated recursively against the command whitelist.
func validateFindArgs(s *Sandbox, args []*syntax.Word) error {
	i := 1 // skip command name
	for i < len(args) {
		lit := args[i].Lit()
		if lit == "" {
			i++
			continue
		}
		if findExecFlags[lit] {
			execFlag := lit
			i++
			var subArgs []*syntax.Word
			for i < len(args) {
				subLit := args[i].Lit()
				if isFindExecTerminator(subLit) {
					i++
					break
				}
				subArgs = append(subArgs, args[i])
				i++
			}
			if len(subArgs) == 0 {
				return fmt.Errorf("find %s has no command to execute", execFlag)
			}
			if err := validateSubCommand(s, subArgs); err != nil {
				return fmt.Errorf("find %s: %w", execFlag, err)
			}
			continue
		}
		if reason, blocked := blockedFindFlags[lit]; blocked {
			return fmt.Errorf("find flag %q is not allowed: %s", lit, reason)
		}
		i++
	}
	return nil
}

// subCommandDenylist names commands that are unsafe to invoke via find -exec
// or xargs because their sandbox safety relies on runtime hooks that only
// fire when the sandbox interpreter is the direct caller:
//   - bash, sh: validateBashArgs explicitly defers -c content validation to
//     executeBash, which only runs when the sandbox interp invokes them.
//   - awk: executeAwk swaps the binary for goawk with NoExec/NoFileWrites,
//     but find/xargs spawn the system awk that has system() etc.
//
// When find or xargs spawns these as native processes, the runtime hooks are
// bypassed entirely, so the -c / awk program would execute unvalidated.
var subCommandDenylist = map[string]bool{
	"bash": true,
	"sh":   true,
	"awk":  true,
}

// validateSubCommand validates a command name and its arguments against the
// whitelist, including any per-command argument validators. args[0] must be
// the command name. Used for recursive validation of commands embedded in
// find -exec and xargs.
func validateSubCommand(s *Sandbox, args []*syntax.Word) error {
	if len(args) == 0 {
		return fmt.Errorf("empty command")
	}
	cmdName := args[0].Lit()
	if cmdName == "" {
		return fmt.Errorf("dynamic command names are not allowed")
	}
	if subCommandDenylist[cmdName] {
		return fmt.Errorf("command %q is not allowed as a find -exec or xargs subcommand", cmdName)
	}
	extra := s.getExtraCommands()
	if !allowedCommands[cmdName] && !extra[cmdName] {
		return fmt.Errorf("command %q is not allowed", cmdName)
	}
	if validator, ok := s.argValidators[cmdName]; ok {
		if err := validator(s, args); err != nil {
			return err
		}
	}
	return nil
}

// xargsArgConsumingFlags lists xargs short flags that consume the next
// argument as their value (e.g., -I {}, -n 5).
var xargsArgConsumingFlags = map[string]bool{
	"-d": true, // GNU: delimiter character
	"-E": true, // logical EOF string
	"-I": true, // replace string
	"-J": true, // BSD: insert-position replace string
	"-L": true, // max input lines per invocation
	"-n": true, // max args per invocation
	"-P": true, // max parallel processes
	"-R": true, // BSD: max replacements for -I
	"-S": true, // BSD: max replace size for -I
	"-s": true, // max chars per command line
}

// validateXargsArgs validates xargs by extracting the utility command from
// its arguments and recursively validating it against the command whitelist.
// If no command is given, xargs defaults to echo which is safe.
func validateXargsArgs(s *Sandbox, args []*syntax.Word) error {
	i := 1 // skip "xargs"
	for i < len(args) {
		lit := args[i].Lit()
		// End of options marker
		if lit == "--" {
			i++
			if i < len(args) {
				return validateSubCommand(s, args[i:])
			}
			return nil
		}
		// Non-flag argument = start of the utility command
		if !strings.HasPrefix(lit, "-") {
			return validateSubCommand(s, args[i:])
		}
		// Long option (--foo or --foo=val): always a single token
		if strings.HasPrefix(lit, "--") {
			i++
			continue
		}
		// Short flag: if exactly 2 chars ("-X") and it consumes the next arg,
		// skip both. A longer token like "-I{}" has the value attached.
		if len(lit) >= 2 && len(lit) == 2 && xargsArgConsumingFlags[lit[:2]] {
			i += 2
			continue
		}
		i++
	}
	// No explicit command — xargs defaults to echo, which is safe
	return nil
}

// blockedTarOps lists tar operation flags that are not read-only.
var blockedTarOps = map[byte]string{
	'x': "extracts files",
	'c': "creates archives",
	'r': "appends to archives",
	'u': "updates archives",
}

// validateTarArgs ensures tar is invoked in list mode only (-t/--list).
// Blocks extract (-x), create (-c), append (-r), update (-u), and --delete.
func validateTarArgs(_ *Sandbox, args []*syntax.Word) error {
	hasListMode := false
	for _, arg := range args[1:] { // skip command name
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		// Check long options
		if lit == "--list" {
			hasListMode = true
			continue
		}
		if lit == "--extract" || lit == "--get" {
			return fmt.Errorf("tar flag %q is not allowed: extracts files", lit)
		}
		if lit == "--create" {
			return fmt.Errorf("tar flag %q is not allowed: creates archives", lit)
		}
		if lit == "--append" {
			return fmt.Errorf("tar flag %q is not allowed: appends to archives", lit)
		}
		if lit == "--update" {
			return fmt.Errorf("tar flag %q is not allowed: updates archives", lit)
		}
		if lit == "--delete" {
			return fmt.Errorf("tar flag %q is not allowed: deletes from archives", lit)
		}
		// Check short options: could be combined like -tzf or standalone like -t
		if len(lit) > 0 && lit[0] == '-' && !strings.HasPrefix(lit, "--") {
			flags := lit[1:]
			for i := 0; i < len(flags); i++ {
				if reason, blocked := blockedTarOps[flags[i]]; blocked {
					return fmt.Errorf("tar flag '-%c' is not allowed: %s", flags[i], reason)
				}
				if flags[i] == 't' {
					hasListMode = true
				}
			}
			continue
		}
		// Handle old-style tar flags without leading dash (e.g., "tf", "tzf")
		// These are common: tar tf archive.tar, tar tzf archive.tar.gz
		if len(lit) > 0 && lit[0] != '-' && arg == args[1] {
			// First non-command argument without dash — could be old-style flags
			for i := 0; i < len(lit); i++ {
				if reason, blocked := blockedTarOps[lit[i]]; blocked {
					return fmt.Errorf("tar flag '%c' is not allowed: %s", lit[i], reason)
				}
				if lit[i] == 't' {
					hasListMode = true
				}
			}
		}
	}
	if !hasListMode {
		return fmt.Errorf("tar is only allowed in list mode (-t/--list)")
	}
	return nil
}

// validateUnzipArgs ensures unzip is invoked in list/test mode only.
// Requires -l (list), -Z (zipinfo mode), or -t (test integrity).
func validateUnzipArgs(_ *Sandbox, args []*syntax.Word) error {
	hasReadOnlyFlag := false
	for _, arg := range args[1:] {
		lit := arg.Lit()
		if lit == "" {
			continue
		}
		if lit == "-l" || lit == "-Z" || lit == "-t" {
			hasReadOnlyFlag = true
		}
		// Check for combined flags like -lv
		if len(lit) > 1 && lit[0] == '-' && !strings.HasPrefix(lit, "--") {
			flags := lit[1:]
			for i := 0; i < len(flags); i++ {
				if flags[i] == 'l' || flags[i] == 'Z' || flags[i] == 't' {
					hasReadOnlyFlag = true
				}
			}
		}
	}
	if !hasReadOnlyFlag {
		return fmt.Errorf("unzip is only allowed with -l (list), -Z (zipinfo), or -t (test) flags")
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
