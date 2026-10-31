package bash_sandboxed

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// TestArgLayoutPathBypasses: every spelling getopt_long accepts reaches the
// path check. Each of these read /etc/passwd past the boundary when grep and
// sed had walkers of their own (abbreviated long options, clustered short
// ones, options after an operand).
func TestArgLayoutPathBypasses(t *testing.T) {
	s := NewSandbox()
	wd := t.TempDir()
	for _, cmd := range []string{
		"grep --reg=root /etc/passwd",
		"grep --regex root /etc/passwd",
		"grep -ieroot /etc/passwd",
		"grep /etc/passwd -e root",
		"grep --regexp= /etc/passwd",
		"egrep -iwe root /etc/passwd",
		"sed --expr=p /etc/passwd",
		"sed -nep /etc/passwd",
		"sed -n /etc/passwd -e p",
		"pgrep -lF /etc/passwd",
		"pgrep -l --pid /etc/passwd",
	} {
		err := s.ValidateCommand(cmd, wd, []string{wd}, []string{wd})
		if err == nil || !strings.Contains(err.Error(), "/etc/passwd") {
			t.Errorf("%s: want the path refused, got %v", cmd, err)
		}
	}
	if out, err := s.Execute(context.Background(), "grep --reg=root /etc/passwd", wd, []string{wd}, []string{wd}); err == nil {
		t.Errorf("grep --reg=root /etc/passwd ran: %q", out)
	}
	for _, cmd := range []string{
		"grep -e /api/v1 -r .",
		"grep -rn /api/v1 .",
		"grep -A 3 -m 1 /usr/ .",
		"sed -n s/a/b/p ./f",
		"sed -e s/a/b/ -e s/c/d/ ./f",
		"pgrep -f /usr/bin/node",
		"pgrep -lf /usr/bin/node",
	} {
		if err := s.ValidateCommand(cmd, wd, []string{wd}, []string{wd}); err != nil {
			t.Errorf("%s: want allowed, got %v", cmd, err)
		}
	}
}

// TestArgLayoutWriteTargets pins what the writers' layouts report written.
func TestArgLayoutWriteTargets(t *testing.T) {
	cases := []struct {
		argv []string
		want []string
	}{
		{[]string{"cp", "a", "b", "dst"}, []string{"dst"}},
		{[]string{"cp", "-t", "dst", "a", "b"}, []string{"dst"}},
		{[]string{"cp", "--target=dst", "a"}, []string{"dst"}},
		{[]string{"cp", "a", "dst", "-v"}, []string{"dst", "-v"}}, // GNU permutes; a POSIX reading writes -v
		{[]string{"ln", "-s", "target"}, []string{"."}},
		{[]string{"mv", "a", "b"}, []string{"a", "b"}},
		{[]string{"chmod", "755", "f"}, []string{"f"}},
		{[]string{"chmod", "-w", "f"}, []string{"f"}},
		{[]string{"chmod", "-R", "u+x", "d"}, []string{"d"}},
		{[]string{"chmod", "--reference=r", "f"}, []string{"f"}},
		{[]string{"chown", "me", "f"}, []string{"f"}},
		{[]string{"sed", "-i", "s/a/b/", "f"}, []string{"f"}},
		{[]string{"sed", "--in-place=.bak", "-e", "s/a/b/", "f"}, []string{"f"}},
		{[]string{"sed", "-n", "p", "f"}, nil},
		{[]string{"sort", "-o", "out", "in"}, []string{"out"}},
		{[]string{"sort", "-oout", "in"}, []string{"out"}},
		{[]string{"gzip", "-c", "f"}, nil},
		{[]string{"gzip", "f"}, []string{"f"}},
		{[]string{"split", "in"}, []string{"x"}},
		{[]string{"split", "in", "pre"}, []string{"pre"}},
		{[]string{"install", "-d", "a", "b"}, []string{"a", "b"}},
		{[]string{"install", "-m", "644", "a", "b"}, []string{"b"}},
		{[]string{"mkdir", "--context", "d"}, []string{"d"}}, // --context's value is optional
		{[]string{"mktemp", "-p", "dir", "tmp.XXX"}, []string{"dir", "tmp.XXX", "dir/tmp.XXX"}},
	}
	for _, c := range cases {
		got := writeTargets(c.argv[0], c.argv, nil)
		if !slices.Equal(got, c.want) {
			t.Errorf("writeTargets(%q) = %q, want %q", c.argv, got, c.want)
		}
	}
}

// getoptVectors are command lines for the differential test, with the
// option table they are parsed with.
var getoptVectors = []struct {
	spec optSpec
	argv []string
}{
	{grepOpts, []string{"grep", "--reg=root", "/etc/passwd"}},
	{grepOpts, []string{"grep", "--regexp=", "/etc/passwd"}},
	{grepOpts, []string{"grep", "-ieroot", "/etc/passwd"}},
	{grepOpts, []string{"grep", "/etc/passwd", "-e", "root", "--", "-x"}},
	{grepOpts, []string{"grep", "-A3", "-B", "2", "--context=1", "-", "pat", "f"}},
	{grepOpts, []string{"grep", "--max", "3", "pat"}},
	{grepOpts, []string{"grep", "--color=always", "--color", "pat", "f"}},
	{grepOpts, []string{"grep", "", "-e", "", "f"}},
	{sedSpec, []string{"sed", "-i.bak", "-nes/a/b/p", "f", "-i", "g"}},
	{sedSpec, []string{"sed", "--in-place", "--expression", "p", "--in-pl=x", "f"}},
	{cpOpts, []string{"cp", "-at", "dst", "a", "--suffix", "~", "b", "--target-dir=d2"}},
	{chmodLayout.opts, []string{"chmod", "-R", "-wx", "u+x", "-0", "f"}},
	{pgrepOpts, []string{"pgrep", "-lF", "pidfile", "pat", "--pid=f", "-d,"}},
	{wrapperSpecs["xargs"].opts, []string{"xargs", "-0n", "1", "-a", "list", "--max-args", "2", "-i{}", "--repl", "rm"}},
	{wrapperSpecs["env"].opts, []string{"env", "-iu", "FOO", "--uns", "BAR", "-C/", "cmd", "-u", "x"}},
	{wrapperSpecs["timeout"].opts, []string{"timeout", "--sig", "KILL", "-vk1", "5", "cmd"}},
}

// TestGetoptMatchesGlibc runs each vector through util-linux getopt(1),
// which parses with glibc's getopt_long, and requires scan to read the
// options, values, and operands as it does.
func TestGetoptMatchesGlibc(t *testing.T) {
	if err := exec.Command("getopt", "-T").Run(); err == nil || err.(*exec.ExitError).ExitCode() != 4 {
		t.Skip("needs util-linux getopt(1)")
	}
	for _, v := range getoptVectors {
		for _, posix := range []bool{false, true} {
			sp := v.spec
			sp.stopAtOperand = sp.stopAtOperand || posix
			want, err := glibcGetopt(sp, v.argv)
			if err != nil {
				t.Fatalf("%q: %v", v.argv, err)
			}
			if got := canonicalParse(sp, v.argv); got != want {
				t.Errorf("%q (stopAtOperand=%v):\n got  %s\n want %s", v.argv, sp.stopAtOperand, got, want)
			}
		}
	}
}

// glibcGetopt returns getopt(1)'s reading of argv under sp, in
// canonicalParse's form.
func glibcGetopt(sp optSpec, argv []string) (string, error) {
	short := ""
	if sp.stopAtOperand {
		short = "+"
	}
	letters := map[rune]string{}
	for _, r := range sp.short {
		letters[r] = ":"
	}
	for _, r := range sp.optional {
		letters[r] = "::"
	}
	// Every other letter the vectors use is a flag.
	for _, w := range argv[1:] {
		if len(w) > 1 && w[0] == '-' && w[1] != '-' {
			for _, r := range w[1:] {
				if _, ok := letters[r]; !ok {
					letters[r] = ""
				}
			}
		}
	}
	for r, suffix := range letters {
		short += string(r) + suffix
	}
	var long []string
	for _, l := range sp.long {
		long = append(long, l+":")
	}
	for _, l := range sp.flags {
		if !slices.Contains(sp.long, l) {
			long = append(long, l+"::")
		}
	}
	args := append([]string{"-q", "-o", short, "-l", strings.Join(long, ","), "--"}, argv[1:]...)
	cmd := exec.Command("getopt", args...)
	cmd.Env = []string{"LC_ALL=C"} // GETOPT_COMPATIBLE, set at all, selects the old output
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("getopt %q: %v", args, err)
	}
	// The output: each option, followed by its value when it takes one
	// ('' when an optional one was not given), then "--" and the operands.
	kind := func(word string) string {
		if name, ok := strings.CutPrefix(word, "--"); ok {
			switch {
			case slices.Contains(sp.long, name):
				return ":"
			case slices.Contains(sp.flags, name):
				return "::"
			}
			return ""
		}
		return letters[rune(word[1])]
	}
	words := shellSplit(strings.TrimSpace(string(out)))
	var b strings.Builder
	i := 0
	for ; i < len(words) && words[i] != "--"; i++ {
		name := strings.TrimLeft(words[i], "-")
		if a, ok := sp.alias[name]; ok {
			name = a
		}
		k := kind(words[i])
		if k != "" && i+1 < len(words) {
			i++
			if k == ":" || words[i] != "" {
				fmt.Fprintf(&b, "%s=%q ", name, words[i])
				continue
			}
		}
		fmt.Fprintf(&b, "%s ", name)
	}
	b.WriteString("|")
	for _, w := range words[min(i+1, len(words)):] {
		fmt.Fprintf(&b, " %q", w)
	}
	return b.String(), nil
}

// canonicalParse is scan's reading of argv in glibcGetopt's form.
func canonicalParse(sp optSpec, argv []string) string {
	p := sp.scan(argv)
	var b strings.Builder
	for _, o := range p.opts {
		// getopt(1) cannot tell an optional value given empty from none.
		if o.hasValue && (o.value != "" || o.valueIndex >= 0 || slices.Contains(sp.long, o.long)) {
			fmt.Fprintf(&b, "%s=%q ", o.name, o.value)
		} else {
			fmt.Fprintf(&b, "%s ", o.name)
		}
	}
	b.WriteString("|")
	for _, w := range p.operandWords() {
		fmt.Fprintf(&b, " %q", w)
	}
	return b.String()
}

// shellSplit splits getopt(1)'s output, whose words are single-quoted with
// ' written '\”.
func shellSplit(s string) []string {
	var out []string
	var cur strings.Builder
	in, started := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case in && c == '\'':
			in = false
		case in:
			cur.WriteByte(c)
		case c == '\'':
			in, started = true, true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			started = true
		case c == ' ':
			if started {
				out = append(out, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteByte(c)
			started = true
		}
	}
	if started {
		out = append(out, cur.String())
	}
	return out
}
