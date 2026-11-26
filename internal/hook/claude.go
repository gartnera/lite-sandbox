package hook

import (
	"os"
	"os/user"
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
	if out == "~" {
		return claudeHomeDir()
	}
	if rest, ok := strings.CutPrefix(out, "~/"); ok {
		return filepath.Join(claudeHomeDir(), rest)
	}
	return out
}

// claudeHomeDir is the directory Node's os.homedir() reports, which Claude
// Code expands ~ to: $HOME when it is set, even to "", otherwise the user's
// passwd entry. With an empty home, Claude Code joins "~/x" to the relative
// "x", as filepath.Join does here.
func claudeHomeDir() string {
	if home, ok := os.LookupEnv("HOME"); ok {
		return home
	}
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

// IsTrimmedByJS reports whether JavaScript's String.prototype.trim strips r:
// white space (Unicode Zs, tab, vertical tab, form feed, and the byte order
// mark) and line terminators (LF, CR, U+2028, U+2029). That is Go's
// unicode.IsSpace plus U+FEFF, minus U+0085 (NEL), which JavaScript keeps.
func IsTrimmedByJS(r rune) bool {
	return r == '\uFEFF' || (unicode.IsSpace(r) && r != '\u0085')
}
