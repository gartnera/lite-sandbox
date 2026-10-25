package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func TestShellPrompt(t *testing.T) {
	tests := []struct {
		dir, home string
		width     int
		want      string
	}{
		{"/home/u", "/home/u", 80, "sandbox:~$ "},
		{"/home/u/proj", "/home/u", 80, "sandbox:~/proj$ "},
		{"/home/user2/proj", "/home/u", 80, "sandbox:/home/user2/proj$ "},
		{"/srv/proj", "", 0, "sandbox:/srv/proj$ "},
		// Cut to the last element when it would take over half the line.
		{"/srv/a/very/deep/tree/proj", "/home/u", 40, "sandbox:…/proj$ "},
	}
	for _, tt := range tests {
		if got := shellPrompt(tt.dir, tt.home, tt.width); got != tt.want {
			t.Errorf("shellPrompt(%q, %q, %d) = %q, want %q", tt.dir, tt.home, tt.width, got, tt.want)
		}
	}
}

func TestCommandPosition(t *testing.T) {
	for head, want := range map[string]bool{
		"":                  true,
		"  ":                true,
		"ls | ":             true,
		"ls |":              true,
		"true && ":          true,
		"a; ":               true,
		"echo $(":           true,
		"if true; then ":    true,
		"for i in 1; do ":   true,
		"ls ":               false,
		"git log --format=": false,
	} {
		if got := commandPosition(head); got != want {
			t.Errorf("commandPosition(%q) = %v, want %v", head, got, want)
		}
	}
}

func TestCompleteCommand(t *testing.T) {
	got := completeCommand("gr", []string{"grep", "ls", "greet", "grep"})
	want := []string{"greet ", "grep "}
	if !slices.Equal(got, want) {
		t.Errorf("completeCommand = %q, want %q", got, want)
	}
}

func TestCompletePath(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	for _, name := range []string{"alpha.txt", "alphabet.txt", ".hidden", "with space"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, d := range []string{filepath.Join(dir, "sub"), filepath.Join(home, "docs")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "inner.go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		word string
		want []string
	}{
		{"al", []string{"alpha.txt ", "alphabet.txt "}},
		{"", []string{"alpha.txt ", "alphabet.txt ", "sub/", `with\ space `}},
		{".h", []string{".hidden "}},
		{"su", []string{"sub/"}},
		{"sub/", []string{"sub/inner.go "}},
		{"./sub/i", []string{"./sub/inner.go "}},
		{filepath.Join(dir, "sub") + "/", []string{filepath.Join(dir, "sub", "inner.go") + " "}},
		{"~/d", []string{"~/docs/"}},
		{"~", []string{"~/"}},
		{"nothing", nil},
	}
	for _, tt := range tests {
		if got := completePath(tt.word, dir, home); !slices.Equal(got, tt.want) {
			t.Errorf("completePath(%q) = %q, want %q", tt.word, got, tt.want)
		}
	}
}

func TestHistoryEntries(t *testing.T) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	tests := []struct {
		command   string
		multiLine bool
		want      []string
	}{
		{"ls -la", false, []string{"ls -la"}},
		{"for i in 1 2\ndo echo $i\ndone", true, []string{"for i in 1 2; do echo $i; done"}},
		{"echo 'a\nb'", true, []string{"echo 'a", "b'"}},
		{"cat <<EOF\nhi\nEOF", true, []string{"cat <<EOF", "hi", "EOF"}},
	}
	for _, tt := range tests {
		if got := historyEntries(parser, tt.command, tt.multiLine); !slices.Equal(got, tt.want) {
			t.Errorf("historyEntries(%q) = %q, want %q", tt.command, got, tt.want)
		}
	}
}
