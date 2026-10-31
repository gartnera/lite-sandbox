package bash_sandboxed

import (
	"maps"
	"slices"
	"sync"
)

// argRole is what a word of a command line is to the path checks.
type argRole int

const (
	// roleDefault leaves the word to the generic path check, which checks
	// it when it looks like a path, against the command's read or write
	// set.
	roleDefault argRole = iota
	// roleNonPath: the word is not a path whatever it looks like (a
	// pattern, a script, a number, a process name).
	roleNonPath
	// roleWrite: the word names a file the command creates, modifies, or
	// removes; it is checked against the write set and agent configuration
	// even when it does not look like a path.
	roleWrite
)

// argLayout declares what a command's option values and operands are, over
// its getopt parse. A command with an argLayout gets its commandSpec's
// nonPathArgs and writeTargets from it, so it has no argv walker of its own.
type argLayout struct {
	// opts is how the command parses its options. Unless it stops at the
	// first operand, the command line is also read as if it did (as it is
	// under POSIXLY_CORRECT, or by a BSD tool), and a word is a non-path
	// only if it is one both ways, a target if it is one either way.
	opts optSpec
	// bsd, when set, is a BSD implementation's different option table,
	// read the same way alongside opts (BSD sed's -i takes a value).
	bsd *optSpec
	// values gives the role of an option's value, by option name.
	values map[string]argRole
	// otherValues is the role of the values of the options values does
	// not list.
	otherValues argRole
	// operands is the role of the operands.
	operands argRole
	// lead and leadRole: the first lead operands have leadRole (grep's
	// pattern, sed's script, chmod's mode) unless one of leadUnless's
	// options supplies it.
	lead       int
	leadRole   argRole
	leadUnless []string
	// adjust changes the roles where the shape above does not fit: cp
	// writes only its last operand, ln TARGET creates "." as well.
	adjust func(p parsedArgs, r *argRoles)

	// compiled caches readings: a command line is read several times per
	// command, on the interpreter's per-command path.
	once     sync.Once
	compiled []optSpec
}

// argRoles is the role of each word of one reading of a command line, and
// the files it writes that are not a word of their own (an attached
// -oFILE, a file a target names implicitly).
type argRoles struct {
	index map[int]argRole
	extra []string
}

// set gives the word at index i role r.
func (r *argRoles) set(i int, role argRole) { r.index[i] = role }

// write records a written file that is not a word of its own.
func (r *argRoles) write(name string) { r.extra = append(r.extra, name) }

// readings returns the option tables the command line is read with: each
// table (GNU, and BSD's where it differs) as it permutes, and stopping at the
// first operand.
func (l *argLayout) readings() []optSpec {
	l.once.Do(func() {
		tables := []optSpec{l.opts}
		if l.bsd != nil {
			tables = append(tables, *l.bsd)
		}
		for _, t := range tables {
			t = t.compiled()
			l.compiled = append(l.compiled, t)
			if !t.stopAtOperand {
				t.stopAtOperand = true
				l.compiled = append(l.compiled, t)
			}
		}
	})
	return l.compiled
}

// roles reads args with sp and assigns each word its role.
func (l *argLayout) roles(sp optSpec, args []string) argRoles {
	p := sp.scan(args)
	r := argRoles{index: map[int]argRole{}}
	for _, o := range p.opts {
		role, ok := l.values[o.name]
		if !ok {
			role = l.otherValues
		}
		switch {
		case !o.hasValue:
		case o.valueIndex >= 0:
			r.set(o.valueIndex, role)
		case role == roleWrite:
			r.write(o.value)
		}
	}
	lead := l.lead
	if p.has(l.leadUnless...) {
		lead = 0
	}
	for k, i := range p.operands {
		if k < lead {
			r.set(i, l.leadRole)
		} else {
			r.set(i, l.operands)
		}
	}
	if l.adjust != nil {
		l.adjust(p, &r)
	}
	return r
}

// nonPathArgs returns the indices that are non-paths in every reading.
func (l *argLayout) nonPathArgs(args []string) map[int]bool {
	var out map[int]bool
	for _, sp := range l.readings() {
		r := l.roles(sp, args)
		skip := map[int]bool{}
		for i, role := range r.index {
			if role == roleNonPath && (out == nil || out[i]) {
				skip[i] = true
			}
		}
		out = skip
	}
	return out
}

// writeTargets returns the files written in any reading.
func (l *argLayout) writeTargets(args []string, _ map[int]bool) []string {
	var out []string
	seen := map[int]bool{}
	for _, sp := range l.readings() {
		r := l.roles(sp, args)
		for _, i := range slices.Sorted(maps.Keys(r.index)) {
			if r.index[i] == roleWrite && !seen[i] {
				seen[i] = true
				out = append(out, args[i])
			}
		}
		for _, e := range r.extra {
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	return out
}

// lastOperand returns the index of p's last operand.
func lastOperand(p parsedArgs) (int, bool) {
	if len(p.operands) == 0 {
		return 0, false
	}
	return p.operands[len(p.operands)-1], true
}
