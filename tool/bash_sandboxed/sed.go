package bash_sandboxed

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// sedSpec is GNU sed's option table, and sedLongOpts all of its long
// options (BSD sed has none; see bsdSedOpts).
var (
	sedSpec = optSpec{
		short:    "efl",
		long:     []string{"expression", "file", "line-length"},
		optional: "i",
		flags: []string{
			"in-place", "quiet", "silent", "debug", "posix", "regexp-extended", "separate",
			"sandbox", "unbuffered", "null-data", "zero-terminated", "follow-symlinks", "binary",
			"help", "version",
		},
		alias: map[string]string{"expression": "e", "file": "f", "line-length": "l", "in-place": "i"},
	}
	sedLongOpts = append(slices.Clone(sedSpec.long), sedSpec.flags...)
)

// sedScripts returns the scripts a sed invocation runs (argv[0] is "sed"):
// its -e/--expression values, or else its first operand. -i and -I take the
// rest of their word as the backup suffix; written bare, BSD sed takes the
// next argument as the suffix instead (sed -i ” 's/a/b/' f), and the script
// is the second operand. That one is returned in maybe, as it is a file name
// to GNU sed: the caller checks it only when it parses as a script, which a
// BSD sed would otherwise refuse too (its grammar is a subset of what
// sedScriptCheck parses). Then a first operand starting with "." (a suffix;
// no sed command does) is not taken as a script either.
func sedScripts(argv []string) (scripts, maybe []string) {
	args := slices.Clone(argv)
	bareInPlace := false
	for i := 1; i < len(args); i++ {
		a := args[i]
		if a == "--" || len(a) < 2 || a[0] != '-' {
			continue
		}
		if name, ok := strings.CutPrefix(a, "--"); ok {
			if !strings.Contains(name, "=") && slices.Contains(sedSpec.long, sedSpec.longName(name)) {
				i++
			}
			continue
		}
		for j := 1; j < len(a); j++ {
			c := a[j]
			if c == 'i' || c == 'I' {
				args[i] = a[:j+1]
				bareInPlace = bareInPlace || j == len(a)-1
				break
			}
			if strings.IndexByte(sedSpec.short, c) >= 0 {
				if j == len(a)-1 {
					i++
				}
				break
			}
		}
	}
	pos, vals, _ := sedSpec.parse(args, nil)
	scripts = append(slices.Clone(vals["e"]), vals["expression"]...)
	if len(scripts) > 0 || len(pos) == 0 {
		return scripts, nil
	}
	if !bareInPlace || !strings.HasPrefix(pos[0], ".") {
		scripts = pos[:1]
	}
	if bareInPlace && len(pos) > 1 {
		maybe = pos[1:2]
	}
	return scripts, maybe
}

// errSedRefused is sedScriptCheck's refusal of a command it was told to
// refuse, or of the s///w and s///e flags.
var errSedRefused = errors.New("refused sed command")

// sedScriptCheck parses a sed script (GNU syntax, which covers POSIX and BSD
// sed) and returns errSedRefused for the commands in refused (of e, r, R, w,
// and W) and the s///w and s///e flags, which write a file or run a command.
// What it does not understand it refuses.
func sedScriptCheck(s, refused string) error {
	i := 0
	skipBlank := func() {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
	}
	// toEnd skips to the end of the line; toCmdEnd (a label) to the end of
	// the line, a ";", or a blank, whichever comes first.
	toEnd := func() {
		for i < len(s) && s[i] != '\n' {
			i++
		}
	}
	toCmdEnd := func() {
		for i < len(s) && s[i] != '\n' && s[i] != ';' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
	}
	// delimited skips a delimited part (after the delimiter) and the closing
	// delimiter.
	delimited := func(d byte) error {
		for i < len(s) {
			switch s[i] {
			case '\\':
				i += 2
				continue
			case d:
				i++
				return nil
			}
			i++
		}
		return fmt.Errorf("unterminated sed command")
	}
	address := func() error {
		switch {
		case i < len(s) && s[i] == '/':
			i++
			if err := delimited('/'); err != nil {
				return err
			}
		case i+1 < len(s) && s[i] == '\\':
			d := s[i+1]
			i += 2
			if err := delimited(d); err != nil {
				return err
			}
		case i < len(s) && s[i] == '$':
			i++
			return nil
		default:
			for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '~' || s[i] == '+') {
				i++
			}
			return nil
		}
		for i < len(s) && (s[i] == 'I' || s[i] == 'M') {
			i++
		}
		return nil
	}
	for i < len(s) {
		skipBlank()
		if i >= len(s) {
			break
		}
		switch s[i] {
		case '\n', ';', '}':
			i++
			continue
		case '#':
			toEnd()
			continue
		}
		if err := address(); err != nil {
			return err
		}
		skipBlank()
		if i < len(s) && s[i] == ',' {
			i++
			skipBlank()
			if err := address(); err != nil {
				return err
			}
		}
		for skipBlank(); i < len(s) && s[i] == '!'; skipBlank() {
			i++
		}
		if i >= len(s) {
			return fmt.Errorf("missing sed command")
		}
		c := s[i]
		i++
		switch c {
		case '{', '=', 'd', 'D', 'g', 'G', 'h', 'H', 'n', 'N', 'p', 'P', 'x', 'z', 'F':
		case 'l', 'L', 'q', 'Q':
			skipBlank()
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
			}
		case 'a', 'i', 'c':
			// Text up to an unescaped newline.
			for i < len(s) && s[i] != '\n' {
				if s[i] == '\\' {
					i++
				}
				i++
			}
		case ':', 'b', 't', 'T', 'v':
			toCmdEnd()
		case 'r', 'R':
			if strings.IndexByte(refused, c) >= 0 {
				return errSedRefused
			}
			toEnd()
		case 's', 'y':
			if i >= len(s) || s[i] == '\n' || s[i] == '\\' {
				return fmt.Errorf("unterminated sed command")
			}
			d := s[i]
			i++
			if err := delimited(d); err != nil {
				return err
			}
			if err := delimited(d); err != nil {
				return err
			}
			if c == 'y' {
				break
			}
			for i < len(s) && s[i] != ';' && s[i] != '\n' && s[i] != '}' && s[i] != '#' && s[i] != ' ' && s[i] != '\t' {
				switch f := s[i]; {
				case f == 'w' || f == 'e':
					return errSedRefused
				case f == 'g' || f == 'p' || f == 'i' || f == 'I' || f == 'm' || f == 'M' || f >= '0' && f <= '9':
				default:
					return fmt.Errorf("unknown s flag %q", f)
				}
				i++
			}
		case 'w', 'W', 'e':
			if strings.IndexByte(refused, c) >= 0 {
				return errSedRefused
			}
			toEnd()
		default:
			return fmt.Errorf("unknown sed command %q", c)
		}
	}
	return nil
}
