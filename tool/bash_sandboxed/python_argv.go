package bash_sandboxed

import (
	"fmt"
	"regexp"
	"strings"
)

// monty has no sys.argv. Its `sys` module is built in Rust from a fixed
// attribute list, and module objects have no __dict__, so a program cannot
// assign one either (`sys.argv = [...]` raises AttributeError). Without help,
// `python3 script.py --flag input.csv` would run with its arguments silently
// invisible — the kind of failure that produces a wrong answer rather than an
// error.
//
// So lite-sandbox supplies argv itself: a prologue defines a shim object
// carrying argv (and proxying the real sys attributes so nothing else breaks),
// and the few statements that would rebind `sys` back to the real module are
// rewritten to re-apply the shim.
//
// Two things keep this honest:
//
//   - It only happens when the program mentions "argv" at all. A program that
//     never asks for it is handed to monty exactly as written.
//   - The rewrite only ever appends an assignment to a shim we control, whose
//     contents are a list of strings. It cannot widen what Python can reach:
//     every file operation still goes through the OS-call boundary in
//     python_oscall.go.
//
// The prologue shifts line numbers, so executePython subtracts the offset from
// tracebacks and the agent sees its own numbering.

// pythonShimName is the prologue-defined class the shim instances come from.
// The leading underscores keep it out of the way of user names.
const pythonShimName = "_lite_sandbox_sys"

// argvPrologue builds the statements prepended to a program that wants argv.
// The shim proxies the real sys attributes so that rebinding `sys` to it does
// not cost the program sys.version, sys.platform and friends.
func argvPrologue(argv []string) string {
	var b strings.Builder
	b.WriteString("import sys as _lite_sandbox_real_sys\n")
	b.WriteString("class " + pythonShimName + ":\n")
	b.WriteString("    argv = " + pythonListLiteral(argv) + "\n")
	for _, attr := range []string{"version", "version_info", "platform", "stdout", "stderr"} {
		b.WriteString("    " + attr + " = _lite_sandbox_real_sys." + attr + "\n")
	}
	b.WriteString("sys = " + pythonShimName + "()\n")
	return b.String()
}

// pythonListLiteral renders strings as a Python list literal. Every value is
// quoted and escaped, so an argument containing quotes, backslashes or newlines
// cannot terminate the literal and become code.
func pythonListLiteral(values []string) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = pythonStringLiteral(v)
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// pythonStringLiteral renders one Go string as a Python string literal.
// Non-printable bytes go out as \xNN escapes rather than raw, so the literal
// stays on one line and the prologue's line count remains predictable.
func pythonStringLiteral(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				b.WriteString(fmt.Sprintf(`\x%02x`, r))
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// The statements that would rebind `sys` (or bind argv) back to the real
// module. Each is matched against a whole *statement*, so a mention inside a
// larger expression is left alone.
var (
	reImportSys      = regexp.MustCompile(`^(\s*)import\s+sys([ \t]*)$`)
	reImportSysAs    = regexp.MustCompile(`^(\s*)import\s+sys\s+as\s+([A-Za-z_]\w*)([ \t]*)$`)
	reFromSysArgv    = regexp.MustCompile(`^(\s*)from\s+sys\s+import\s+argv([ \t]*)$`)
	reFromSysArgvAs  = regexp.MustCompile(`^(\s*)from\s+sys\s+import\s+argv\s+as\s+([A-Za-z_]\w*)([ \t]*)$`)
	pythonArgvMarker = "argv"
)

// applyArgvShim returns the program to hand to monty and the number of lines
// the prologue added. When the program never mentions argv it is returned
// unchanged with a zero offset.
func applyArgvShim(code string, argv []string) (string, int) {
	if !strings.Contains(code, pythonArgvMarker) {
		return code, 0
	}
	prologue := argvPrologue(argv)
	return prologue + rewriteSysBindings(code), strings.Count(prologue, "\n")
}

// rewriteSysBindings re-applies the shim after any statement that would rebind
// `sys` to the real module. No rewrite inserts a newline, so line numbers shift
// only by the prologue's fixed offset.
//
// Statements are delimited by newlines and by semicolons that are not inside a
// string literal or comment, so `import sys; print(sys.argv)` is handled and a
// line reading `import sys` inside a triple-quoted block is left as the text it
// is.
func rewriteSysBindings(code string) string {
	literal, commentAt := literalMask(code)
	var b strings.Builder
	b.Grow(len(code) + 64)

	start := 0
	flush := func(end int, sep string) {
		// A trailing comment is not part of the statement, but it would stop
		// the whole-statement patterns from matching, so set it aside and put
		// it back afterwards.
		stmtEnd := end
		for j := start; j < end; j++ {
			if commentAt[j] {
				stmtEnd = j
				break
			}
		}
		b.WriteString(rewriteStatement(code[start:stmtEnd]))
		b.WriteString(code[stmtEnd:end])
		b.WriteString(sep)
	}
	for i := 0; i < len(code); i++ {
		if literal[i] {
			continue
		}
		if code[i] == '\n' || code[i] == ';' {
			flush(i, string(code[i]))
			start = i + 1
		}
	}
	flush(len(code), "")
	return b.String()
}

// rewriteStatement returns stmt with the shim re-applied, or stmt unchanged.
func rewriteStatement(stmt string) string {
	switch {
	case reImportSys.MatchString(stmt):
		return reImportSys.ReplaceAllString(stmt, "${1}import sys; sys = "+pythonShimName+"()${2}")
	case reImportSysAs.MatchString(stmt):
		return reImportSysAs.ReplaceAllString(stmt, "${1}import sys as ${2}; ${2} = "+pythonShimName+"()${3}")
	case reFromSysArgv.MatchString(stmt):
		// The real sys has no argv to import, so this becomes a plain
		// assignment rather than an import that would raise ImportError.
		return reFromSysArgv.ReplaceAllString(stmt, "${1}argv = "+pythonShimName+".argv${2}")
	case reFromSysArgvAs.MatchString(stmt):
		return reFromSysArgvAs.ReplaceAllString(stmt, "${1}${2} = "+pythonShimName+".argv${3}")
	}
	return stmt
}

// literalMask reports, for each byte of src, whether it sits inside a string
// literal or a comment, and separately where each comment begins. It is a
// deliberately small Python scanner: it only has to know where program text
// *is not*, which is enough to keep the rewrite above out of string contents,
// to find real statement separators, and to trim trailing comments.
func literalMask(src string) (mask, commentAt []bool) {
	mask = make([]bool, len(src))
	commentAt = make([]bool, len(src))
	var (
		inString  bool
		triple    bool
		delim     byte
		escaped   bool
		inComment bool
	)
	for i := 0; i < len(src); i++ {
		c := src[i]
		if c == '\n' {
			// A newline inside a triple-quoted string is part of the string,
			// not a statement separator — without this the scanner would treat
			// each line of a docstring as program text.
			if inString && triple {
				mask[i] = true
				escaped = false
				continue
			}
			// A comment ends at the newline, and so does an unterminated
			// single-quoted string (Python would reject it; not tracking that
			// would leave the scanner stuck for the rest of the file).
			inComment = false
			inString = false
			escaped = false
			continue
		}
		if inComment {
			mask[i] = true
			continue
		}
		if inString {
			mask[i] = true
			if escaped {
				escaped = false
				continue
			}
			switch {
			case c == '\\':
				escaped = true
			case c == delim && triple && strings.HasPrefix(src[i:], strings.Repeat(string(delim), 3)):
				mask[i+1], mask[i+2] = true, true
				i += 2
				inString = false
			case c == delim && !triple:
				inString = false
			}
			continue
		}
		switch c {
		case '#':
			inComment = true
			mask[i] = true
			commentAt[i] = true
		case '\'', '"':
			inString = true
			delim = c
			mask[i] = true
			if strings.HasPrefix(src[i:], strings.Repeat(string(c), 3)) {
				mask[i+1], mask[i+2] = true, true
				i += 2
				triple = true
			} else {
				triple = false
			}
		}
	}
	return mask, commentAt
}

// shiftTracebackLines rewrites the line numbers in a monty traceback back into
// the program's own numbering, undoing the prologue's offset.
var reTracebackLine = regexp.MustCompile(`(, line )(\d+)`)

func shiftTracebackLines(traceback string, offset int) string {
	if offset == 0 {
		return traceback
	}
	return reTracebackLine.ReplaceAllStringFunc(traceback, func(m string) string {
		parts := reTracebackLine.FindStringSubmatch(m)
		n := 0
		for _, c := range parts[2] {
			n = n*10 + int(c-'0')
		}
		if n <= offset {
			// A frame inside the prologue itself; there is no user line to
			// point at, so leave it rather than inventing one.
			return m
		}
		return fmt.Sprintf("%s%d", parts[1], n-offset)
	})
}
