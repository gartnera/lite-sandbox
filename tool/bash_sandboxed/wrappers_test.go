package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
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
		{[]string{"env", "-P", "/usr/bin", "rm"}, "rejected"}, // BSD altpath
		{[]string{"env", "-C", "/", "rm"}, "rejected"},
		{[]string{"env", "-iC/", "rm"}, "rejected"},
		{[]string{"env", "--chdir=/", "rm"}, "rejected"},
		{[]string{"env", "--ch", "/", "rm"}, "rejected"},
		{[]string{"env", "-a", "x", "rm"}, "rm"},
		{[]string{"env", "--", "-C", "/", "rm"}, "-C"},
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
		"env -u FOO lite-sandbox config mode set open",
		"stdbuf --out L lite-sandbox config mode set open",
	} {
		err := s.ValidateCommand(cmd, workDir, paths, paths)
		if err == nil || !strings.Contains(err.Error(), "command deny list") {
			t.Errorf("%s should be denied: %v", cmd, err)
		}
	}
}

// TestEnvAssignmentsAreOperands: only env's NAME=VALUE operands are held
// to the blocked variables, not an option's value that contains "=".
func TestEnvAssignmentsAreOperands(t *testing.T) {
	s := NewSandbox()
	wd := t.TempDir()
	if err := s.ValidateCommand("env -u LD_PRELOAD=x ls", wd, []string{wd}, []string{wd}); err != nil {
		t.Errorf("env -u NAME=x unsets a variable, sets none: %v", err)
	}
	if err := s.ValidateCommand("env LD_PRELOAD=x ls", wd, []string{wd}, []string{wd}); err == nil {
		t.Error("env LD_PRELOAD=x ls should be refused")
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

// TestEnvRefusesRelocatingOptions: env -C/--chdir and BSD -P make env run a
// different file than the one validation, the whitelist, and no_sandbox
// routing resolved against the shell's own directory and PATH, so they are
// refused, statically and at runtime.
func TestEnvRefusesRelocatingOptions(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	for _, f := range []string{"host.sh", "evil/host.sh"} {
		path := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("#!/bin/bash\necho "+f+" > "+marker+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	yes := true
	s := NewSandbox()
	s.updateConfig(&config.Config{
		Commands: []config.CommandEntry{{Command: "./host.sh", Allow: &yes, NoSandbox: true}},
		Profiles: []config.ProfileEntry{{Name: "xcode"}},
	}, dir)
	paths := []string{dir}

	if err := s.ValidateCommand("env ./host.sh", dir, paths, paths); err != nil {
		t.Fatalf("env ./host.sh should be allowed: %v", err)
	}
	for cmd, want := range map[string]string{
		"env -C evil ./host.sh":           "--chdir is not allowed",
		"env -iC evil ./host.sh":          "--chdir is not allowed",
		"env --chdir=evil ./host.sh":      "--chdir is not allowed",
		"env --ch evil ./host.sh":         "--chdir is not allowed",
		"timeout 5 env -C evil ./host.sh": "--chdir is not allowed",
		"env -P evil host.sh":             "env -P is not allowed",
		"env -P evil ls":                  "env -P is not allowed",
	} {
		if err := s.ValidateCommand(cmd, dir, paths, paths); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: want error containing %q, got %v", cmd, want, err)
		}
	}
	// The runtime layer re-runs the validator on the expanded argv, so an
	// option only known at runtime is refused there too.
	if err := s.runtimeArgValidator(context.Background(), "env", []string{"env", "-C", "evil", "./host.sh"}); err == nil || !strings.Contains(err.Error(), "--chdir is not allowed") {
		t.Errorf("runtime env -C: want refusal, got %v", err)
	}
	if _, err := executeInDirWithSandbox(t, s, dir, "env -C evil ./host.sh"); err == nil {
		t.Error("env -C evil ./host.sh should be refused")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a refused env -C still ran a script")
	}
	// A replace string put in a wrapper's own words smuggles the options
	// in after validation: with input Cevil, `xargs -I{} env -{} ./host.sh`
	// runs env -Cevil ./host.sh.
	for _, cmd := range []string{
		"printf 'Cevil\\n' | xargs -I{} env -{} ./host.sh",
		"printf 'Cevil\\n' | xargs -i env -{} ./host.sh",
		"printf 'Cevil\\n' | xargs --replace env -{} ./host.sh",
		"printf 'chdir=evil\\n' | xargs -I% env --% ./host.sh",
		"printf 'Cevil\\n' | xargs -J% env -% ./host.sh",
		"printf 'Cevil\\n' | xargs -I{} timeout 5 env -{} ./host.sh",
		"printf 'Cevil\\n' | xargs -I{} env {}=x ./host.sh",
		"printf 'x\\n' | xargs -I{} timeout {} ./host.sh",
		"find . -maxdepth 0 -exec env -{} ./host.sh \\;",
		"find . -maxdepth 0 -exec nice env -i{} ./host.sh \\;",
		"printf 'Pevil\\n' | xargs -I{} xcrun env -{} ./host.sh",
		"find . -maxdepth 0 -exec xcrun env -{} ./host.sh \\;",
		"printf 'Cevil\\n' | xargs -I% find . -maxdepth 0 -exec env -% ./host.sh \\;",
		"printf 'Cevil\\n' | xargs -I% find . -maxdepth 0 -execdir timeout 5 env -% ./host.sh \\;",
	} {
		if err := s.ValidateCommand(cmd, dir, paths, paths); err == nil || !strings.Contains(err.Error(), "replace string") {
			t.Errorf("%s: want a replace-string refusal, got %v", cmd, err)
		}
	}
	// Elsewhere the input stays an argument or an assignment's value.
	for _, cmd := range []string{
		"printf 'a\\n' | xargs -I{} env FOO={} ./host.sh",
		"printf 'a\\n' | xargs -I{} timeout 5 ./host.sh {}",
		"printf 'a\\n' | xargs env -i ./host.sh",
		"find . -maxdepth 0 -exec env ./host.sh {} \\;",
		"printf 'a\\n' | xargs -I{} xcrun env ./host.sh {}",
		"printf 'a\\n' | xargs -I% find . -maxdepth 0 -exec env ./host.sh % {} \\;",
	} {
		if err := s.ValidateCommand(cmd, dir, paths, paths); err != nil {
			t.Errorf("%s should be allowed: %v", cmd, err)
		}
	}
	if got := s.execIsUnsandboxed(context.Background(), []string{"env", "-C", "evil", "./host.sh"}); got {
		t.Error("env -C evil ./host.sh must not route to the host")
	}
}
