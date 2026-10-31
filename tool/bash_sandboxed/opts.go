package bash_sandboxed

import (
	"slices"
	"strings"
)

// The option-parsing library the per-command code shares: optSpec tells a
// command's operands from its option values the way getopt_long does, and
// scanOptions/refusedOption list or refuse the options an invocation uses.

// optSpec describes a command's options well enough to tell its operands
// from option values: short holds the short options that take a value
// (attached, -oFILE, or as the next argument), long the long options that
// take one as the next argument when it is not attached with "=".
type optSpec struct {
	short string
	long  []string
}

// longName expands name to the one entry of long it abbreviates, the way
// getopt_long and git's option parser accept any unambiguous prefix
// (--target for --target-directory). An exact or ambiguous name is returned
// as is.
func (sp optSpec) longName(name string) string {
	if name == "" || slices.Contains(sp.long, name) {
		return name
	}
	match := ""
	for _, l := range sp.long {
		if strings.HasPrefix(l, name) {
			if match != "" {
				return name
			}
			match = l
		}
	}
	if match == "" {
		return name
	}
	return match
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
			name = sp.longName(name)
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

// scanOptions walks args (command name at index 0) the way getopt_long does,
// options anywhere before "--", and returns each option seen: "-x" for a
// short one, "--name" for a long one, with an abbreviated long name expanded
// against allLong (an ambiguous or unknown one is returned as written). spec
// lists the options that take a value, so a value is never read as an option.
func scanOptions(args []string, spec optSpec, allLong []string) []string {
	all := optSpec{long: allLong}
	var opts []string
	for i := 1; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return opts
		case strings.HasPrefix(a, "--"):
			name, _, hasVal := strings.Cut(a[2:], "=")
			name = all.longName(name)
			opts = append(opts, "--"+name)
			if !hasVal && slices.Contains(spec.long, name) {
				i++
			}
		case len(a) > 1 && a[0] == '-':
			for j := 1; j < len(a); j++ {
				opts = append(opts, "-"+string(a[j]))
				if strings.IndexByte(spec.short, a[j]) >= 0 {
					if j == len(a)-1 {
						i++
					}
					break
				}
			}
		}
	}
	return opts
}

// refusedOption returns the first option of args that is one of refused
// ("-x" or "--full-name"), or "" when there is none. See scanOptions.
func refusedOption(args []string, spec optSpec, allLong []string, refused ...string) string {
	for _, opt := range scanOptions(args, spec, allLong) {
		if slices.Contains(refused, opt) {
			return opt
		}
	}
	return ""
}
