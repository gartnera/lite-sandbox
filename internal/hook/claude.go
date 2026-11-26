package hook

import (
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

// ClaudeModelPath mirrors how Claude Code cleans a file tool's path before
// resolving it against the working directory (its expandPath): the path is
// trimmed with JavaScript's String.prototype.trim, and a leading ~ or ~/
// expands to the home directory. Without this, "~/.aws/credentials" or
// " /etc/shadow" would be judged relative to the working directory and pass,
// while Claude Code opens the real file. A path that trims to nothing is
// returned as "": Claude Code resolves it to the working directory.
func ClaudeModelPath(p string) string {
	out := strings.TrimFunc(p, IsTrimmedByJS)
	if out == "~" || strings.HasPrefix(out, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, out[1:])
		}
	}
	return out
}

// IsTrimmedByJS reports whether JavaScript's String.prototype.trim strips r:
// white space (Unicode Zs, tab, vertical tab, form feed, and the byte order
// mark) and line terminators (LF, CR, U+2028, U+2029). That is Go's
// unicode.IsSpace plus U+FEFF, minus U+0085 (NEL), which JavaScript keeps.
func IsTrimmedByJS(r rune) bool {
	return r == '\uFEFF' || (unicode.IsSpace(r) && r != '\u0085')
}
