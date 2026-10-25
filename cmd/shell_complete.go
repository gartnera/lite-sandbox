package cmd

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

// completer completes the word under the cursor at the shell's prompt: a
// command name where a command starts, a path anywhere else.
type completer struct {
	sandbox *bash_sandboxed.Sandbox
	sess    *bash_sandboxed.Session
}

// wordBreaks end the word being completed, looking back from the cursor. =
// is one so the value of --flag=path or VAR=path completes as a path.
const wordBreaks = " \t\n|;&<>()`="

func (c *completer) complete(line string, pos int) (head string, completions []string, tail string) {
	before, tail := line[:pos], line[pos:]
	start := strings.LastIndexAny(before, wordBreaks) + 1
	head, word := before[:start], before[start:]
	if commandPosition(head) && !strings.Contains(word, "/") && !strings.HasPrefix(word, "~") {
		names := append(c.sandbox.CommandNames(), c.sess.Functions()...)
		completions = completeCommand(word, names)
	} else {
		home, _ := os.UserHomeDir()
		completions = completePath(word, c.sess.Dir(), home)
	}
	return head, completions, tail
}

// commandPosition reports whether a word after head starts a command: head
// is empty, or ends in an operator or a keyword that a command follows.
func commandPosition(head string) bool {
	trimmed := strings.TrimRight(head, " \t")
	if trimmed == "" || strings.ContainsAny(trimmed[len(trimmed)-1:], "|;&(`\n{") {
		return true
	}
	fields := strings.Fields(trimmed)
	switch fields[len(fields)-1] {
	case "then", "do", "else", "elif", "if", "while", "until", "!", "time":
		return true
	}
	return false
}

// completeCommand returns the names starting with word, sorted and unique,
// each followed by a space.
func completeCommand(word string, names []string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, name := range names {
		if strings.HasPrefix(name, word) && !seen[name] {
			seen[name] = true
			out = append(out, name+" ")
		}
	}
	sort.Strings(out)
	return out
}

// completePath returns the entries of word's directory (relative to dir; a
// leading ~/ is home) that start with its last element: a directory with a
// trailing /, anything else with a space. Dot entries are offered only when
// the element starts with a dot.
func completePath(word, dir, home string) []string {
	expanded := word
	if home != "" && (word == "~" || strings.HasPrefix(word, "~/")) {
		if word == "~" {
			return []string{"~/"}
		}
		expanded = home + word[1:]
	}
	parent, base := filepath.Split(expanded)
	// What the user typed of the directory is kept as typed.
	typedParent := word[:len(word)-len(base)]
	searchDir := parent
	if searchDir == "" {
		searchDir = dir
	} else if !filepath.IsAbs(searchDir) {
		searchDir = filepath.Join(dir, searchDir)
	}
	entries, err := os.ReadDir(searchDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, base) || (strings.HasPrefix(name, ".") && !strings.HasPrefix(base, ".")) {
			continue
		}
		suffix := " "
		// Stat follows a symlink to a directory.
		if info, err := os.Stat(filepath.Join(searchDir, name)); err == nil && info.IsDir() {
			suffix = "/"
		}
		out = append(out, typedParent+shellEscape(name)+suffix)
	}
	sort.Strings(out)
	return out
}

// shellEscape backslash-escapes the characters the shell would otherwise
// split a word on or expand.
func shellEscape(name string) string {
	const special = " \t\n\\'\"`$&;|<>()*?[]#~!{}"
	if !strings.ContainsAny(name, special) {
		return name
	}
	var b strings.Builder
	for _, r := range name {
		if strings.ContainsRune(special, r) {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}
