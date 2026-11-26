package hook

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"unicode/utf8"
)

// jsTrimmed lists the code points JavaScript's String.prototype.trim strips,
// as Node reports them (every code point c for which ("a" + c).trim() === "a").
var jsTrimmed = []rune{
	0x9, 0xA, 0xB, 0xC, 0xD, 0x20, 0xA0, 0x1680,
	0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A,
	0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF,
}

func TestIsTrimmedByJS(t *testing.T) {
	want := map[rune]bool{}
	for _, r := range jsTrimmed {
		want[r] = true
	}
	for r := rune(0); r <= utf8.MaxRune; r++ {
		if got := IsTrimmedByJS(r); got != want[r] {
			t.Errorf("IsTrimmedByJS(%U) = %v, want %v", r, got, want[r])
		}
	}
}

func TestClaudeModelPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	tests := []struct{ in, want string }{
		{"/etc/shadow", "/etc/shadow"},
		{" /etc/shadow", "/etc/shadow"},
		{"/etc/shadow\n", "/etc/shadow"},
		{"\uFEFF\u2028/etc/shadow\u3000", "/etc/shadow"},
		{"\u0085/etc/shadow", "\u0085/etc/shadow"},
		{"~", home},
		{" ~ ", home},
		{"~/.aws/credentials", filepath.Join(home, ".aws", "credentials")},
		{"\t~/.ssh/id_rsa", filepath.Join(home, ".ssh", "id_rsa")},
		{"~/../etc/passwd", filepath.Dir(home) + "/etc/passwd"},
		{"~user/x", "~user/x"},
		{"a/~/b", "a/~/b"},
		{"relative/a.txt", "relative/a.txt"},
		{"  ", ""},
	}
	for _, tt := range tests {
		if got := ClaudeModelPath(tt.in); got != tt.want {
			t.Errorf("ClaudeModelPath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestClaudeModelPathHome checks ~ against the home directory Node's
// os.homedir() reports: an empty $HOME is kept, an unset one falls back to the
// passwd entry.
func TestClaudeModelPathHome(t *testing.T) {
	t.Setenv("HOME", "")
	if got := ClaudeModelPath("~/.aws/credentials"); got != filepath.Join(".aws", "credentials") {
		t.Errorf("empty HOME: got %q, want .aws/credentials", got)
	}
	u, err := user.Current()
	if err != nil || u.HomeDir == "" {
		t.Skip("no passwd entry for the current user")
	}
	os.Unsetenv("HOME")
	if got, want := ClaudeModelPath("~/.aws/credentials"), filepath.Join(u.HomeDir, ".aws", "credentials"); got != want {
		t.Errorf("unset HOME: got %q, want %q", got, want)
	}
	if got := ClaudeModelPath("~"); got != u.HomeDir {
		t.Errorf("unset HOME: got %q for ~, want %q", got, u.HomeDir)
	}
}
