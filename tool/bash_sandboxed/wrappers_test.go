package bash_sandboxed

import (
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// TestWrapperCommandIndex pins the walker to where each wrapper itself finds
// its command (checked against GNU findutils 4.9 xargs and coreutils 9.4 env,
// timeout, nice, and stdbuf; BSD-only options per their getopt strings).
func TestWrapperCommandIndex(t *testing.T) {
	cases := []struct {
		argv []string
		want string // the command, "" for none, "rejected"
	}{
		{[]string{"xargs", "rm"}, "rm"},
		{[]string{"xargs"}, ""},
		{[]string{"xargs", "-n", "1", "rm"}, "rm"},
		{[]string{"xargs", "-n1", "rm"}, "rm"},
		{[]string{"xargs", "-0n", "1", "rm"}, "rm"},
		{[]string{"xargs", "--max-args", "1", "rm"}, "rm"},
		{[]string{"xargs", "--max-args=1", "rm"}, "rm"},
		{[]string{"xargs", "--arg", "list", "rm"}, "rm"}, // --arg-file
		{[]string{"xargs", "-a", "list", "rm"}, "rm"},
		{[]string{"xargs", "-I", "{}", "rm", "{}"}, "rm"},
		{[]string{"xargs", "-i", "rm", "{}"}, "rm"}, // -i's value is optional, attached only
		{[]string{"xargs", "-J", "%", "rm", "%"}, "rm"},
		{[]string{"xargs", "--", "rm"}, "rm"},

		{[]string{"timeout", "5", "rm"}, "rm"},
		{[]string{"timeout", "-s", "KILL", "5", "rm"}, "rm"},
		{[]string{"timeout", "-sKILL", "5", "rm"}, "rm"},
		{[]string{"timeout", "--sig", "KILL", "5", "rm"}, "rm"},
		{[]string{"timeout", "--kill", "1", "5", "rm"}, "rm"},
		{[]string{"timeout", "-vk", "1", "5", "rm"}, "rm"},
		{[]string{"timeout", "5"}, ""},

		{[]string{"env", "rm"}, "rm"},
		{[]string{"env", "FOO=1", "rm"}, "rm"},
		{[]string{"env", "a-b=1", "rm"}, "rm"},
		{[]string{"env", "./x=y", "rm"}, "rm"},
		{[]string{"env", "-", "FOO=1", "rm"}, "rm"},
		{[]string{"env", "-u", "FOO", "rm"}, "rm"},
		{[]string{"env", "--uns", "FOO", "rm"}, "rm"},
		{[]string{"env", "-iu", "FOO", "rm"}, "rm"},
		{[]string{"env", "-P", "/usr/bin", "rm"}, "rm"}, // BSD altpath
		{[]string{"env", "-C", "/", "rm"}, "rm"},
		{[]string{"env", "FOO=1"}, ""},
		{[]string{"env", "-S", "rm x"}, "rejected"},
		{[]string{"env", "-iS", "rm x"}, "rejected"},
		{[]string{"env", "--split", "rm x"}, "rejected"},

		{[]string{"nice", "-n", "5", "rm"}, "rm"},
		{[]string{"nice", "--adj", "5", "rm"}, "rm"},
		{[]string{"nice", "-10", "rm"}, "rm"},
		{[]string{"stdbuf", "-o", "L", "rm"}, "rm"},
		{[]string{"stdbuf", "--out", "L", "rm"}, "rm"},
		{[]string{"setsid", "-w", "rm"}, "rm"},
		{[]string{"nohup", "rm"}, "rm"},
	}
	for _, c := range cases {
		idx := wrapperCommandIndex(c.argv)
		got := ""
		switch {
		case idx == wrapperRejected:
			got = "rejected"
		case idx >= 0:
			got = c.argv[idx]
		}
		if got != c.want {
			t.Errorf("%q: command = %q, want %q", c.argv, got, c.want)
		}
	}
}

// TestWrapperDenyList: in denylist mode the deny list is the only check a
// wrapped command meets, so every spelling of a wrapper's options must still
// lead it to the command the wrapper runs.
func TestWrapperDenyList(t *testing.T) {
	workDir := t.TempDir()
	s, _ := newDenySandbox(t, config.ModeDenylist, workDir, config.Config{})
	paths := []string{workDir}
	for _, cmd := range []string{
		"timeout --sig KILL 5 lite-sandbox config mode set open",
		"timeout -sKILL 5 lite-sandbox config mode set open",
		"echo open | xargs --max-args 1 lite-sandbox config mode set",
		"echo open | xargs -0n 1 lite-sandbox config mode set",
		"xargs -a args.txt lite-sandbox config mode set",
		"env a-b=1 lite-sandbox config mode set open",
		"env -P /usr/local/bin lite-sandbox config mode set open",
		"stdbuf --out L lite-sandbox config mode set open",
	} {
		err := s.ValidateCommand(cmd, workDir, paths, paths)
		if err == nil || !strings.Contains(err.Error(), "command deny list") {
			t.Errorf("%s should be denied: %v", cmd, err)
		}
	}
}

// TestWrapperUnwrapAgreesWithValidation: path checks and routing see the
// same wrapped command the validator does.
func TestWrapperUnwrapAgreesWithValidation(t *testing.T) {
	got := unwrapWrapperArgs([]string{"timeout", "--sig", "KILL", "5", "env", "a-b=1", "xargs", "--max-args", "1", "rm", "x"})
	if want := []string{"rm", "x"}; !slices.Equal(got, want) {
		t.Errorf("unwrapWrapperArgs = %q, want %q", got, want)
	}
}
