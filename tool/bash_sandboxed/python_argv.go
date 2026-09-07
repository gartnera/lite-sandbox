package bash_sandboxed

import (
	"fmt"
	"regexp"
	"strings"

	montygo "github.com/fugue-labs/monty-go"
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

// pythonStdinInput is the name the prologue reads sys.stdin from. It is
// supplied as an interpreter input carrying a file handle, not baked into the
// source, because stdin's contents are not known at compile time. See
// python_stdin.go.
const pythonStdinInput = "_lite_sandbox_stdin"

// sysPrologue builds the statements prepended to a program that wants argv or
// stdin. The shim proxies the real sys attributes so that rebinding `sys` to it
// does not cost the program sys.version, sys.platform and friends.
//
// Both argv and stdin are always defined, whichever of the two the program
// asked for: the shim replaces `sys` wholesale, so leaving one out would make
// mentioning argv the reason stdin stopped working.
func sysPrologue(argv []string) string {
	var b strings.Builder
	b.WriteString("import sys as _lite_sandbox_real_sys\n")
	b.WriteString("class " + pythonShimName + ":\n")
	b.WriteString("    argv = " + pythonListLiteral(argv) + "\n")
	b.WriteString("    stdin = " + pythonStdinInput + "\n")
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
	reImportStmt = regexp.MustCompile(`^(\s*)import\s+(\S.*?)([ \t]*)$`)
	reSysAsName  = regexp.MustCompile(`^sys\s+as\s+([A-Za-z_]\w*)$`)
	reFromSys    = regexp.MustCompile(`^(\s*)from\s+sys\s+import\s+(argv|stdin)([ \t]*)$`)
	reFromSysAs  = regexp.MustCompile(`^(\s*)from\s+sys\s+import\s+(argv|stdin)\s+as\s+([A-Za-z_]\w*)([ \t]*)$`)
	// The attributes the shim supplies that the real sys module lacks, and so
	// the only reason to prepend a prologue at all.
	pythonSysMarkers = []string{"argv", "stdin"}
)

// applySysShim returns the program to hand to monty, the number of lines the
// prologue added, and the interpreter inputs the prologue expects. When the
// program never mentions the shimmed attributes it is returned unchanged, with
// a zero offset and no inputs.
func applySysShim(code string, argv []string) (string, int, map[string]any) {
	wanted := false
	for _, marker := range pythonSysMarkers {
		if strings.Contains(code, marker) {
			wanted = true
			break
		}
	}
	if !wanted {
		return code, 0, nil
	}
	prologue := sysPrologue(argv)
	inputs := map[string]any{
		pythonStdinInput: montygo.FileHandle{Path: pythonStdinPath, Mode: "r"},
	}
	return prologue + rewriteSysBindings(code), strings.Count(prologue, "\n"), inputs
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
	if rewritten, ok := rewriteImport(stmt); ok {
		return rewritten
	}
	switch {
	case reFromSys.MatchString(stmt):
		// The real sys has neither attribute to import, so this becomes a
		// plain assignment rather than an import that would raise ImportError.
		return reFromSys.ReplaceAllString(stmt, "${1}${2} = "+pythonShimName+".${2}${3}")
	case reFromSysAs.MatchString(stmt):
		return reFromSysAs.ReplaceAllString(stmt, "${1}${3} = "+pythonShimName+".${2}${4}")
	}
	return stmt
}

// rewriteImport re-applies the shim after an `import` statement that binds the
// real sys module, and reports whether it did.
//
// It handles the multi-module forms too (`import sys, json`, `import json, sys
// as system`), which the one-liners an agent writes reach for constantly. Only
// an entry that is exactly `sys`, or `sys as <name>`, counts: a module merely
// starting with those letters (`syslog`) binds nothing this shim owns.
//
// The rewrite only ever appends `; <name> = <shim>()` to the statement, so it
// adds no newline and the program's line numbering is untouched.
func rewriteImport(stmt string) (string, bool) {
	m := reImportStmt.FindStringSubmatch(stmt)
	if m == nil {
		return stmt, false
	}
	indent, modules, trailing := m[1], m[2], m[3]

	var bound []string
	for _, entry := range strings.Split(modules, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "sys" {
			bound = append(bound, "sys")
			continue
		}
		if as := reSysAsName.FindStringSubmatch(entry); as != nil {
			bound = append(bound, as[1])
		}
	}
	if len(bound) == 0 {
		return stmt, false
	}

	var b strings.Builder
	b.WriteString(indent + "import " + modules)
	for _, name := range bound {
		b.WriteString("; " + name + " = " + pythonShimName + "()")
	}
	b.WriteString(trailing)
	return b.String(), true
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
