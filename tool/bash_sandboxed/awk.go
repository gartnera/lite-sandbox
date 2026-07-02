package bash_sandboxed

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	goawkinterp "github.com/benhoyt/goawk/interp"
	"github.com/benhoyt/goawk/parser"
	"mvdan.cc/sh/v3/interp"
	"mvdan.cc/sh/v3/syntax"
)

// validateAwkArgs validates awk command arguments at the AST level.
// The most significant restrictions are enforced at execution time via goawk:
//   - system() calls and pipe-based getline/print are blocked (NoExec)
//   - file writes via print > file are blocked (NoFileWrites)
//
// Path validation for -f script files and input file arguments is handled
// by the standard validatePaths and CallHandler mechanisms.
func validateAwkArgs(s *Sandbox, args []*syntax.Word) error {
	i := 1 // skip command name
	for i < len(args) {
		lit := args[i].Lit()
		switch {
		case lit == "-f", lit == "-v", lit == "-F":
			i += 2 // flag + value
		case lit == "--":
			return nil
		case strings.HasPrefix(lit, "-f"), strings.HasPrefix(lit, "-v"), strings.HasPrefix(lit, "-F"):
			i++
		case strings.HasPrefix(lit, "-"):
			return fmt.Errorf("awk flag %q is not supported in the sandbox", lit)
		default:
			// Inline program or file argument — allowed.
			i++
		}
	}
	return nil
}

// executeAwk runs an awk command via goawk with unsafe features disabled.
// It is called from the ExecHandler in executeWithInterp when args[0] == "awk".
//
// Disabled features (enforced by goawk):
//   - system() function and command pipes (NoExec)
//   - Writing to files via print > / print >> (NoFileWrites)
//
// Input file arguments are already path-validated by the CallHandler before
// this function is called. The -f program file is read here after the path
// has been validated by the static validatePaths pass.
func executeAwk(ctx context.Context, args []string) error {
	hc := interp.HandlerCtx(ctx)

	var progSrc []byte
	var awkArgs []string // input files / var=value items for ARGV[1..]
	var vars []string   // -v name=value global assignments

	i := 1
	for i < len(args) {
		arg := args[i]
		switch {
		case arg == "-f":
			i++
			if i >= len(args) {
				return fmt.Errorf("awk: -f requires a filename argument")
			}
			data, err := readAwkFile(args[i], hc.Dir)
			if err != nil {
				return fmt.Errorf("awk: %w", err)
			}
			progSrc = data

		case strings.HasPrefix(arg, "-f"):
			data, err := readAwkFile(arg[2:], hc.Dir)
			if err != nil {
				return fmt.Errorf("awk: %w", err)
			}
			progSrc = data

		case arg == "-v":
			i++
			if i >= len(args) {
				return fmt.Errorf("awk: -v requires a var=value argument")
			}
			vars = appendVar(vars, args[i])

		case strings.HasPrefix(arg, "-v"):
			vars = appendVar(vars, arg[2:])

		case arg == "-F":
			i++
			if i >= len(args) {
				return fmt.Errorf("awk: -F requires a field separator argument")
			}
			vars = appendVar(vars, "FS="+args[i])

		case strings.HasPrefix(arg, "-F"):
			vars = appendVar(vars, "FS="+arg[2:])

		case arg == "--":
			// Everything after -- is a file arg (or inline program if not yet seen).
			i++
			if progSrc == nil && i < len(args) {
				progSrc = []byte(args[i])
				i++
			}
			for ; i < len(args); i++ {
				awkArgs = append(awkArgs, absPath(args[i], hc.Dir))
			}
			i = len(args) // exit loop

		default:
			if progSrc == nil {
				progSrc = []byte(arg)
			} else {
				awkArgs = append(awkArgs, absPath(arg, hc.Dir))
			}
		}
		i++
	}

	if progSrc == nil {
		return fmt.Errorf("awk: no program specified")
	}

	prog, err := parser.ParseProgram(progSrc, nil)
	if err != nil {
		return fmt.Errorf("awk: %w", err)
	}

	status, err := goawkinterp.ExecProgram(prog, &goawkinterp.Config{
		Stdin:  hc.Stdin,
		Output: hc.Stdout,
		Error:  hc.Stderr,
		Argv0:  "awk",
		Args:   awkArgs,
		Vars:   vars,
		// Block system() and all command pipes (cmd | getline, print | cmd).
		NoExec: true,
		// Block awk-level file writes (print > file, print >> file).
		// Users can use shell output redirections instead.
		NoFileWrites: true,
	})
	if err != nil {
		return fmt.Errorf("awk: %w", err)
	}
	if status != 0 {
		return interp.ExitStatus(status)
	}
	return nil
}

// readAwkFile reads an awk program from a file, resolving relative paths
// against dir.
func readAwkFile(path, dir string) ([]byte, error) {
	path = absPath(path, dir)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", path, err)
	}
	return data, nil
}

// absPath returns path unchanged if it is already absolute, otherwise
// joins it with dir to produce an absolute path.
func absPath(path, dir string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(dir, path)
}

// appendVar appends a "name=value" string to vars in goawk's interleaved
// format: ["name", "value", ...].
func appendVar(vars []string, assignment string) []string {
	eq := strings.IndexByte(assignment, '=')
	if eq < 0 {
		// Not a valid assignment; pass as-is and let goawk report the error.
		return append(vars, assignment, "")
	}
	return append(vars, assignment[:eq], assignment[eq+1:])
}
