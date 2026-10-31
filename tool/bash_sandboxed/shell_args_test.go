package bash_sandboxed

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

// shellVectors are shell command lines with the word each shell runs: C is a
// -c command string candidate, S a script file candidate. The real-shell
// test replaces each with something that prints its own index.
var shellVectors = []struct {
	argv []string
	// run is the index of the word the shell runs (command or script).
	run int
	// bashOnly: dash refuses the line (long options, -O).
	bashOnly bool
}{
	{argv: []string{"sh", "-c", "C"}, run: 2},
	{argv: []string{"sh", "-c", "C", "C"}, run: 2}, // the second is $0
	{argv: []string{"sh", "-ec", "C"}, run: 2},
	{argv: []string{"sh", "-ce", "C"}, run: 2},
	{argv: []string{"sh", "-c", "-e", "C"}, run: 3},
	{argv: []string{"sh", "-c", "-x", "-u", "C"}, run: 4},
	{argv: []string{"sh", "-c", "--", "C"}, run: 3},
	{argv: []string{"sh", "-c", "-", "C"}, run: 3},
	{argv: []string{"sh", "-c", "+", "C"}, run: 3},
	{argv: []string{"sh", "+c", "C"}, run: 2},
	{argv: []string{"sh", "-c", "+x", "C"}, run: 3},
	{argv: []string{"sh", "+e", "-c", "C"}, run: 3},
	{argv: []string{"sh", "-o", "errexit", "-c", "C"}, run: 4},
	{argv: []string{"sh", "-co", "errexit", "C"}, run: 3},
	{argv: []string{"sh", "-oc", "errexit", "C"}, run: 3},
	{argv: []string{"sh", "-c", "-o", "errexit", "C"}, run: 4},
	{argv: []string{"sh", "+o", "errexit", "-c", "C"}, run: 4},
	{argv: []string{"sh", "-e", "-c", "C", "-x"}, run: 3},
	{argv: []string{"sh", "S"}, run: 1},
	{argv: []string{"sh", "-e", "S", "-c"}, run: 2},
	{argv: []string{"sh", "-x", "--", "S", "arg"}, run: 3},
	{argv: []string{"sh", "-", "S"}, run: 2},
	{argv: []string{"sh", "-o", "errexit", "S"}, run: 3},
	{argv: []string{"bash", "--norc", "-c", "C"}, run: 3, bashOnly: true},
	{argv: []string{"bash", "--norc", "--noprofile", "-e", "S"}, run: 4, bashOnly: true},
	{argv: []string{"bash", "-O", "extglob", "-c", "C"}, run: 4, bashOnly: true},
	{argv: []string{"bash", "-cO", "extglob", "C"}, run: 3, bashOnly: true},
	{argv: []string{"bash", "+O", "extglob", "S"}, run: 3, bashOnly: true},
	{argv: []string{"bash", "-O", "extglob", "S"}, run: 3, bashOnly: true},
}

func TestParseShellArgs(t *testing.T) {
	for _, v := range shellVectors {
		inv, err := parseShellArgs(literalWords(v.argv), blockedBashFlags)
		if err != nil {
			t.Errorf("%q: %v", v.argv, err)
			continue
		}
		got := inv.script
		if v.argv[v.run] == "C" {
			got = inv.command
		}
		if got != v.run || !inv.complete {
			t.Errorf("%q: got command %d script %d (complete %v), want %d to run", v.argv, inv.command, inv.script, inv.complete, v.run)
		}
	}
}

// TestShellArgsMatchRealShells runs each vector through bash and dash, with
// each C a command string and each S a script that prints its own index,
// and requires the shell to run the word parseShellArgs picked.
func TestShellArgsMatchRealShells(t *testing.T) {
	dir := t.TempDir()
	for _, shell := range []string{"bash", "dash"} {
		if _, err := exec.LookPath(shell); err != nil {
			t.Logf("%s not installed", shell)
			continue
		}
		for _, v := range shellVectors {
			if v.bashOnly && shell != "bash" {
				continue
			}
			args := make([]string, len(v.argv)-1)
			for i, w := range v.argv[1:] {
				switch w {
				case "C":
					args[i] = "echo " + strconv.Itoa(i+1)
				case "S":
					args[i] = filepath.Join(dir, strconv.Itoa(i+1))
					if err := os.WriteFile(args[i], []byte(fmt.Sprintf("echo %d\n", i+1)), 0o644); err != nil {
						t.Fatal(err)
					}
				default:
					args[i] = w
				}
			}
			cmd := exec.Command(shell, args...)
			cmd.Stdin = strings.NewReader("")
			out, err := cmd.Output()
			if err != nil {
				t.Errorf("%s %q: %v", shell, args, err)
				continue
			}
			if got := strings.TrimSpace(string(out)); got != strconv.Itoa(v.run) {
				t.Errorf("%s %q ran word %s, want %d", shell, args, got, v.run)
			}
		}
	}
}

func TestParseShellArgsRefuses(t *testing.T) {
	tests := []struct {
		argv    []string
		blocked map[string]string
		errMsg  string
	}{
		{[]string{"bash", "-i"}, blockedBashFlags, `flag "-i" is not allowed`},
		{[]string{"bash", "+s"}, blockedBashFlags, `flag "-s" (in "+s")`},
		{[]string{"bash", "+l", "-c", "ls"}, blockedBashFlags, `flag "-l" (in "+l")`},
		{[]string{"bash", "-c", "-l", "ls"}, blockedBashFlags, `flag "-l" is not allowed`},
		{[]string{"bash", "--login", "-c", "ls"}, blockedBashFlags, `flag "--login" is not allowed`},
		{[]string{"bash", "--rcf", "x", "-c", "ls"}, nil, `unknown option "--rcf"`},
		{[]string{"bash", "--norc=1", "-c", "ls"}, nil, `unknown option "--norc=1"`},
		{[]string{"bash", "-e", "--norc", "-c", "ls"}, nil, `must come before`},
		// bash reads these as long options, dash as letters (-norc's o
		// takes the next word): `bash -norc S -c ls` runs S.
		{[]string{"bash", "-norc", "S", "-c", "ls"}, nil, `write --norc`},
		{[]string{"bash", "-login", "-c", "ls"}, nil, `write --login`},
		{[]string{"bash", "-c"}, nil, `-c requires a command string`},
		{[]string{"bash", "-e", "-c"}, nil, `-c requires a command string`},
	}
	for _, tt := range tests {
		_, err := parseShellArgs(literalWords(tt.argv), tt.blocked)
		if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
			t.Errorf("%q: got %v, want an error containing %q", tt.argv, err, tt.errMsg)
		}
	}
}

func TestParseShellArgsStatic(t *testing.T) {
	parse := func(src string) shellInvocation {
		t.Helper()
		f, err := ParseBash(src)
		if err != nil {
			t.Fatal(err)
		}
		inv, err := parseShellArgs(f.Stmts[0].Cmd.(*syntax.CallExpr).Args, blockedBashFlags)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		return inv
	}
	// A word only known after expansion may be an option or the operand.
	if inv := parse(`bash $flag -c 'ls'`); inv.complete || inv.readsStdin() {
		t.Errorf("bash $flag -c: got %+v, want an incomplete parse", inv)
	}
	if inv := parse(`bash -e`); !inv.readsStdin() {
		t.Errorf("bash -e: got %+v, want it to read stdin", inv)
	}
	if inv := parse(`bash -e "$script"`); inv.complete {
		t.Errorf(`bash -e "$script": got %+v, want an incomplete parse ("$script" may be -x)`, inv)
	}
	if inv := parse(`bash -e script.sh "$arg"`); inv.script != 2 {
		t.Errorf(`bash -e script.sh "$arg": got %+v, want script 2`, inv)
	}
	inv := parse(`bash -ex +u -o pipefail -O extglob -c 'ls'`)
	if got := strings.Join(inv.set, " "); got != "-e -x +u -o pipefail" || inv.command != 8 {
		t.Errorf("got set %q, command %d", got, inv.command)
	}
}
