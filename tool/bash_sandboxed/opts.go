package bash_sandboxed

import (
	"slices"
	"strings"

	"github.com/jonathonwebb/getopt"
)

// The option parsing every per-command check shares. A command's argv is
// parsed the way its own getopt_long parses it, by a getopt port
// (github.com/jonathonwebb/getopt, checked against glibc), from a
// declaration of its options (optSpec). Nothing here walks an argv by hand:
// a hand-written walker that reads a command line differently from the
// command (an abbreviated long option, a clustered short one, an option
// after an operand) puts a check on the wrong word, and the word the
// command really reads goes unchecked.
//
// getopt.State reports where it is (OptInd) but not where each option came
// from, so scan runs it in POSIX mode, where OptInd is exact, one option at
// a time, and carries on past each operand itself the way GNU getopt
// permutes.

// optSpec declares a command's options the way its getopt_long call does.
// Only the options that take a value must be listed for operands and values
// to be told apart; the rest are flags, listed for abbreviations only.
type optSpec struct {
	// short holds the short options that take a value: attached (-oFILE)
	// or the next word.
	short string
	// long holds the long options that take a value: after "=" or the
	// next word.
	long []string
	// optional holds the short options with an optional value, which
	// getopt only reads attached (sed -i[SUFFIX], xargs -i[R]).
	optional string
	// flags holds the other long options (with no value, or an optional
	// one, which getopt only reads after "="), so an abbreviation expands
	// the way getopt_long expands it: --reg for --regexp, but not --fi when
	// --files-with-matches exists too.
	flags []string
	// alias maps a long option to the short one it spells (regexp to e),
	// so both are reported under the short name.
	alias map[string]string
	// stopAtOperand ends the options at the first operand, as getopt does
	// with a "+" optstring, POSIXLY_CORRECT, or a BSD libc.
	stopAtOperand bool
}

// parsedOpt is one option of a parsed command line.
type parsedOpt struct {
	// name is the option without dashes, a long one under its alias.
	name string
	// long is the long option's full name, when it was given as one.
	long string
	// index is the word the option is in.
	index int
	// value is its value, when hasValue: attached to the option's word, or
	// the word at valueIndex (-1 when attached).
	value      string
	hasValue   bool
	valueIndex int
}

// parsedArgs is a command line as its getopt reads it.
type parsedArgs struct {
	args     []string
	opts     []parsedOpt
	operands []int // indices of the operands
	// dashdash: a "--" ended the options.
	dashdash bool
}

// scan parses args (the command name at index 0).
func (sp optSpec) scan(args []string) parsedArgs {
	p := parsedArgs{args: args}
	sp.scanFrom(&p, 1)
	return p
}

// scanFrom parses args from index start into p.
func (sp optSpec) scanFrom(p *parsedArgs, start int) {
	args := p.args
	cfg := sp.config()
	for start < len(args) {
		// The state's argv is args[start:] behind the command name, so its
		// index i is args' index start+i-1.
		st := getopt.NewState(append([]string{args[0]}, args[start:]...))
		at := func(i int) int { return start + i - 1 }
		restart := -1
		for restart < 0 {
			before := st.OptInd()
			if before >= len(st.Args()) {
				return // every word parsed
			}
			word := args[at(before)]
			res, err := st.GetOpt(cfg)
			if err == getopt.ErrDone {
				if word == "--" {
					p.dashdash = true
					p.addOperands(at(before)+1, len(args))
					return
				}
				// An operand: GNU getopt carries on past it.
				p.operands = append(p.operands, at(before))
				if sp.stopAtOperand {
					p.addOperands(at(before)+1, len(args))
					return
				}
				restart = at(before) + 1
				continue
			}
			o := parsedOpt{name: res.Name, long: res.Name, index: at(before), valueIndex: -1}
			if res.Name == "" {
				o.name = string(res.Char)
			} else if a, ok := sp.alias[res.Name]; ok {
				o.name = a
			}
			after := st.OptInd()
			switch {
			case strings.HasPrefix(word, "--") && strings.Contains(word, "="):
				// --name=VALUE carries its value, even an empty one; the
				// port (v1.0.2) takes the next word for an empty one, where
				// glibc does not, so parsing resumes at that word.
				_, v, _ := strings.Cut(word, "=")
				o.value, o.hasValue = v, true
				if after > before+1 {
					restart = at(before) + 1
				}
			case after == before+2:
				o.value, o.hasValue, o.valueIndex = args[at(after-1)], true, at(after-1)
			case res.OptArg != "":
				o.value, o.hasValue = res.OptArg, true
			}
			p.opts = append(p.opts, o)
		}
		start = restart
	}
}

// addOperands records args[from:to] as operands.
func (p *parsedArgs) addOperands(from, to int) {
	for i := from; i < to; i++ {
		p.operands = append(p.operands, i)
	}
}

// config is sp as a getopt.Config. A short option it does not list is
// parsed as a flag (getopt reports it unknown and moves on), as is a long
// one; an ambiguous abbreviation, which the command itself refuses, is
// taken as its first match.
func (sp optSpec) config() getopt.Config {
	var c getopt.Config
	for _, r := range sp.short {
		c.Opts = append(c.Opts, getopt.Opt{Char: r, HasArg: getopt.RequiredArgument})
	}
	for _, r := range sp.optional {
		c.Opts = append(c.Opts, getopt.Opt{Char: r, HasArg: getopt.OptionalArgument})
	}
	for _, l := range sp.long {
		c.LongOpts = append(c.LongOpts, getopt.LongOpt{Name: l, HasArg: getopt.RequiredArgument})
	}
	for _, l := range sp.flags {
		if !slices.Contains(sp.long, l) {
			c.LongOpts = append(c.LongOpts, getopt.LongOpt{Name: l, HasArg: getopt.OptionalArgument})
		}
	}
	c.Func = getopt.FuncGetOptLong
	c.Mode = getopt.ModePOSIX
	return c
}

// has reports whether one of the options names was given.
func (p parsedArgs) has(names ...string) bool {
	return slices.ContainsFunc(p.opts, func(o parsedOpt) bool { return slices.Contains(names, o.name) })
}

// values returns the values given to the options names, in order.
func (p parsedArgs) values(names ...string) []string {
	var out []string
	for _, o := range p.opts {
		if o.hasValue && slices.Contains(names, o.name) {
			out = append(out, o.value)
		}
	}
	return out
}

// operandWords returns the operands.
func (p parsedArgs) operandWords() []string {
	out := make([]string, len(p.operands))
	for i, idx := range p.operands {
		out[i] = p.args[idx]
	}
	return out
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
// --name=value is recorded), and the options seen. Operands in skip are
// dropped.
func (sp optSpec) parse(args []string, skip map[int]bool) (pos []string, vals map[string][]string, flags map[string]bool) {
	p := sp.scan(args)
	vals = map[string][]string{}
	flags = map[string]bool{}
	for _, o := range p.opts {
		flags[o.name] = true
		if o.hasValue {
			vals[o.name] = append(vals[o.name], o.value)
		}
	}
	for _, i := range p.operands {
		if !skip[i] {
			pos = append(pos, args[i])
		}
	}
	return pos, vals, flags
}

// scanOptions returns each option args uses: "-x" for a short one, "--name"
// for a long one, with an abbreviated long name expanded against allLong
// (an ambiguous or unknown one is returned as written). spec lists the
// options that take a value, so a value is never read as an option.
func scanOptions(args []string, spec optSpec, allLong []string) []string {
	spec.flags = append(slices.Clone(spec.flags), allLong...)
	var opts []string
	for _, o := range spec.scan(args).opts {
		if o.long != "" {
			opts = append(opts, "--"+o.long)
		} else {
			opts = append(opts, "-"+o.name)
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
