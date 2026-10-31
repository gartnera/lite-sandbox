package bash_sandboxed

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// shellWord is a word's value once the shell removes its quotes, and whether
// the shell expands it further (an unquoted glob or brace expansion), so its
// value is only known when the command runs.
type shellWord struct {
	val  string
	glob bool
}

// shellWordVals returns the values of ws.
func shellWordVals(ws []shellWord) []string {
	out := make([]string, len(ws))
	for i, w := range ws {
		out[i] = w.val
	}
	return out
}

// wordValues returns each word's value once quotes are removed (see
// literalWord), or "" for a word that is not literal text, whose value is
// only known after expansion; the runtime layer re-runs the validators on
// the expanded argv.
func wordValues(words []*syntax.Word) []string {
	out := make([]string, len(words))
	for i, w := range words {
		if v, bad := literalWord(w); bad == nil {
			out[i] = v.val
		}
	}
	return out
}

// wordLiteral returns the value of a word made only of literal text, quoted
// or not (see literalWord), and false for a word with an expansion in it.
func wordLiteral(w *syntax.Word) (string, bool) {
	v, bad := literalWord(w)
	return v.val, bad == nil
}

// literalWord returns w's value as the shell sees it once quotes are removed,
// for a word made only of literal text, quoted or not. Otherwise it returns
// the first part that is not: an expansion, or $'...' or $"..." quoting,
// which shells disagree on.
//
// A word with no position is an argument the runtime layer has already
// expanded (literalWords): its text is its value.
func literalWord(w *syntax.Word) (shellWord, syntax.WordPart) {
	var out shellWord
	if !w.Pos().IsValid() {
		out.val = w.Lit()
		return out, nil
	}
	var sb strings.Builder
	for _, part := range w.Parts {
		switch p := part.(type) {
		case *syntax.Lit:
			v, glob := unescapeUnquoted(p.Value)
			sb.WriteString(v)
			out.glob = out.glob || glob
		case *syntax.SglQuoted:
			if p.Dollar {
				return out, p
			}
			sb.WriteString(p.Value)
		case *syntax.DblQuoted:
			if p.Dollar {
				return out, p
			}
			for _, dp := range p.Parts {
				lit, ok := dp.(*syntax.Lit)
				if !ok {
					return out, dp
				}
				sb.WriteString(unescapeDoubleQuoted(lit.Value))
			}
		default:
			return out, part
		}
	}
	out.val = sb.String()
	return out, nil
}

// unescapeUnquoted removes the backslashes of an unquoted word part and
// reports whether it has an unescaped glob character or brace expansion
// (a { other than find's {} placeholder).
func unescapeUnquoted(s string) (string, bool) {
	var sb strings.Builder
	glob := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			if s[i] != '\n' {
				sb.WriteByte(s[i])
			}
			continue
		}
		switch c {
		case '*', '?', '[':
			glob = true
		case '{':
			if !strings.HasPrefix(s[i:], "{}") {
				glob = true
			}
		}
		sb.WriteByte(c)
	}
	return sb.String(), glob
}

// unescapeDoubleQuoted removes the backslashes that escape a character
// inside double quotes ($, `, ", \, and a newline).
func unescapeDoubleQuoted(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
			i++
			if s[i] != '\n' {
				sb.WriteByte(s[i])
			}
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}
