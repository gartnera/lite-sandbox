package bash_sandboxed

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// IsClaudeConfigPath reports whether the absolute path is inside (or is) a
// .claude directory: the agent's own configuration — settings with hooks and
// permission rules, skills, agents, commands — which Claude Code runs or
// obeys outside the sandbox, so sandboxed commands may read it but not write
// it. Like Claude Code's own protected-path list, .claude/worktrees (where
// Claude Code puts its git worktrees) is not part of it; a .claude inside
// such a worktree is. The name is matched case-insensitively, since on a
// case-insensitive filesystem (macOS by default) .Claude is the same
// directory.
func IsClaudeConfigPath(path string) bool {
	parts := strings.Split(path, string(filepath.Separator))
	for i, p := range parts {
		if strings.EqualFold(p, ".claude") && (i+1 >= len(parts) || !strings.EqualFold(parts[i+1], "worktrees")) {
			return true
		}
	}
	return false
}

// checkClaudeDirWrite rejects a write to a path inside a .claude directory
// (see IsClaudeConfigPath). Both the path as written and its symlink
// resolution are checked: a .claude that is itself a symlink resolves to a
// target without the name, and a link to .claude resolves into it.
func checkClaudeDirWrite(orig, path, workDir string) error {
	abs := path
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(workDir, abs)
	}
	abs = filepath.Clean(abs)
	resolved := ResolvePath(abs, workDir)
	if IsClaudeConfigPath(abs) || IsClaudeConfigPath(resolved) {
		return tagRule(rulePathBoundary, resolved, fmt.Errorf("path %q is inside a .claude directory, which is read-only in the sandbox; ask the user to make this change", orig))
	}
	return nil
}

// validateClaudeDirWrites rejects a command that writes inside a .claude
// directory. Only the arguments the command writes are checked (see
// writeTargets), so reading .claude stays possible — `sed -n 1p
// .claude/settings.json`, `cp .claude/settings.json backup.json` — while
// `sort -o .claude/settings.json`, which the read/write split of
// writeCommands does not see as a write, is refused. A target is resolved
// against workDir, which at runtime is the shell's current directory, so a
// bare name written from inside .claude (cd .claude && touch x) is caught.
// Empty targets are non-literal words in the static pass, re-checked after
// expansion.
func validateClaudeDirWrites(cmdName string, args []string, workDir string, skip map[int]bool) error {
	for _, t := range writeTargets(cmdName, args, skip) {
		if t == "" || t == "-" {
			continue
		}
		if err := checkClaudeDirWrite(t, t, workDir); err != nil {
			return err
		}
	}
	return nil
}

// writeTargets returns the arguments of a whitelisted command that name a
// file or directory it creates, modifies, or removes. skip holds the indices
// that are not paths (sed's script). It errs toward listing an argument: a
// non-target listed by mistake only matters if it resolves into .claude.
// What a command writes without naming it (git checkout switching branches,
// tar extracting entries) is left to the OS sandbox.
func writeTargets(cmdName string, args []string, skip map[int]bool) []string {
	switch cmdName {
	case "rm", "touch", "tee", "mkdir":
		spec := map[string]optSpec{
			"touch": {short: "dtr", long: []string{"date", "reference"}},
			"mkdir": {short: "m", long: []string{"mode", "context"}},
		}[cmdName]
		pos, _, _ := spec.parse(args, nil)
		return pos
	case "mv":
		pos, vals, _ := optSpec{short: "tS", long: []string{"target-directory", "suffix"}}.parse(args, nil)
		return append(pos, targetDirs(vals)...)
	case "cp", "ln":
		pos, vals, _ := optSpec{short: "tS", long: []string{"target-directory", "suffix"}}.parse(args, nil)
		if dirs := targetDirs(vals); len(dirs) > 0 {
			return dirs
		}
		switch {
		case len(pos) >= 2:
			return pos[len(pos)-1:]
		case len(pos) == 1 && cmdName == "ln":
			// ln TARGET creates the link in the current directory.
			return []string{"."}
		}
		return nil
	case "chmod":
		return chmodTargets(args)
	case "sed":
		pos, _, flags := optSpec{short: "efl", long: []string{"expression", "file", "line-length"}}.parse(args, skip)
		if flags["i"] || flags["in-place"] {
			return pos
		}
		return nil
	case "sort":
		_, vals, _ := optSpec{
			short: "ktSTo",
			long:  []string{"key", "field-separator", "buffer-size", "temporary-directory", "output", "batch-size", "compress-program", "files0-from", "parallel", "random-source", "sort"},
		}.parse(args, nil)
		return append(vals["o"], vals["output"]...)
	case "iconv":
		_, vals, _ := optSpec{short: "fto", long: []string{"from-code", "to-code", "output"}}.parse(args, nil)
		return append(vals["o"], vals["output"]...)
	case "uniq", "xxd":
		// uniq [INPUT [OUTPUT]], xxd [infile [outfile]]
		spec := optSpec{short: "fsw", long: []string{"skip-fields", "skip-chars", "check-chars"}}
		if cmdName == "xxd" {
			spec = optSpec{short: "cglosnR"}
		}
		pos, _, _ := spec.parse(args, nil)
		if len(pos) >= 2 {
			return pos[1:]
		}
		return nil
	case "mktemp":
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
	case "yq":
		pos, _, flags := optSpec{short: "Iops", long: []string{"indent", "output-format", "input-format", "split-exp", "expression"}}.parse(args, nil)
		if flags["i"] || flags["inplace"] {
			return pos
		}
		return nil
	case "git":
		return gitWriteTargets(args)
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

// gitWriteSubcommands are the git subcommands whose path operands are
// working-tree files they create, rewrite, or delete.
var gitWriteSubcommands = map[string]bool{
	"mv":             true,
	"rm":             true,
	"checkout":       true,
	"restore":        true,
	"checkout-index": true,
}

// gitWriteTargets returns the files a git invocation writes that its
// arguments name (see gitSubcommandWriteTargets), relative to the -C
// directories that precede the subcommand.
func gitWriteTargets(args []string) []string {
	base := ""
	for i := 1; i < len(args); i++ {
		a := args[i]
		if gitGlobalValueFlags[a] {
			if a == "-C" && i+1 < len(args) {
				if args[i+1] == "" {
					return nil // non-literal; re-checked after expansion
				}
				base = filepath.Join(base, args[i+1])
			}
			i++
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if a == "" {
			return nil
		}
		var out []string
		for _, t := range gitSubcommandWriteTargets(args[i:]) {
			if t != "" && t != "-" {
				out = append(out, filepath.Join(base, t))
			}
		}
		return out
	}
	return nil
}

// gitSubcommandWriteTargets returns the files that args (starting with the
// subcommand) write: the operands of gitWriteSubcommands, the output files
// and directories of the subcommands that take one, and "." for those that
// write into the current directory by default. Any subcommand's --output=
// counts (git diff --output=FILE and its log/show relatives).
func gitSubcommandWriteTargets(args []string) []string {
	var out []string
	for _, a := range args[1:] {
		if a == "--" {
			break
		}
		if v, ok := strings.CutPrefix(a, "--output="); ok {
			out = append(out, v)
		}
	}
	switch sub := args[0]; {
	case gitWriteSubcommands[sub]:
		pos, vals, _ := optSpec{long: []string{"prefix", "stage"}}.parse(args, nil)
		return append(append(out, pos...), vals["prefix"]...)
	case sub == "merge-file":
		// Writes the result over the first file, unless -p prints it.
		pos, _, flags := optSpec{short: "L"}.parse(args, nil)
		if !flags["p"] && !flags["stdout"] && len(pos) > 0 {
			out = append(out, pos[0])
		}
	case sub == "interpret-trailers":
		pos, _, flags := optSpec{long: []string{"trailer", "where", "if-exists", "if-missing"}}.parse(args, nil)
		if flags["in-place"] {
			out = append(out, pos...)
		}
	case sub == "archive":
		_, vals, _ := optSpec{short: "o", long: []string{"output", "format", "prefix", "add-file", "add-virtual-file", "remote", "exec"}}.parse(args, nil)
		out = append(append(out, vals["o"]...), vals["output"]...)
	case sub == "format-patch", sub == "bugreport", sub == "diagnose":
		_, vals, flags := optSpec{short: "o", long: []string{"output-directory"}}.parse(args, nil)
		dirs := append(vals["o"], vals["output-directory"]...)
		if len(dirs) == 0 && !flags["stdout"] {
			dirs = []string{"."}
		}
		out = append(out, dirs...)
	case sub == "mailsplit":
		_, vals, _ := optSpec{short: "o"}.parse(args, nil)
		out = append(out, vals["o"]...)
	case sub == "bundle":
		pos, _, _ := optSpec{}.parse(args, nil)
		if len(pos) > 1 && pos[0] == "create" {
			out = append(out, pos[1])
		}
	case sub == "pack-objects":
		// Writes <base-name>-<hash>.pack and .idx.
		pos, _, flags := optSpec{}.parse(args, nil)
		if !flags["stdout"] && len(pos) > 0 {
			out = append(out, pos[0])
		}
	case sub == "fast-export", sub == "fast-import":
		_, vals, _ := optSpec{long: []string{"export-marks"}}.parse(args, nil)
		out = append(out, vals["export-marks"]...)
	case sub == "read-tree":
		_, vals, _ := optSpec{long: []string{"index-output"}}.parse(args, nil)
		out = append(out, vals["index-output"]...)
	case sub == "unpack-file":
		out = append(out, ".")
	}
	return out
}

// optSpec describes a command's options well enough to tell its operands
// from option values: short holds the short options that take a value
// (attached, -oFILE, or as the next argument), long the long options that
// take one as the next argument when it is not attached with "=".
type optSpec struct {
	short string
	long  []string
}

// parse splits args (with the command name at index 0) into the operands, the
// values of value-taking options (keyed by option name without dashes; every
// --name=value is recorded), and the options seen. Arguments in skip are
// dropped. Everything after "--" is an operand; a lone "-" is an operand.
func (sp optSpec) parse(args []string, skip map[int]bool) (pos []string, vals map[string][]string, flags map[string]bool) {
	vals = map[string][]string{}
	flags = map[string]bool{}
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case skip[i]:
		case a == "--":
			for j := i + 1; j < len(args); j++ {
				if !skip[j] {
					pos = append(pos, args[j])
				}
			}
			return pos, vals, flags
		case strings.HasPrefix(a, "--"):
			name, val, hasVal := strings.Cut(a[2:], "=")
			flags[name] = true
			switch {
			case hasVal:
				vals[name] = append(vals[name], val)
			case slices.Contains(sp.long, name) && i+1 < len(args):
				i++
				vals[name] = append(vals[name], args[i])
			}
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				c := string(a[j])
				flags[c] = true
				if strings.Contains(sp.short, c) {
					val := a[j+1:]
					if val == "" && i+1 < len(args) {
						i++
						val = args[i]
					}
					vals[c] = append(vals[c], val)
					break
				}
			}
		default:
			pos = append(pos, a)
		}
	}
	return pos, vals, flags
}
