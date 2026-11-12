package bash_sandboxed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
)

// A shell script under timeout, env, nice, nohup, setsid, or stdbuf runs
// through the sandbox's interpreter, with the wrapper's effect applied, not
// as a native program (#143). The interpreter has no BASH_VERSION but sets
// BASH_SOURCE; a native bash has both, and dash (/bin/sh) neither.
func TestWrappedShellScriptRunsInInterpreter(t *testing.T) {
	scripts := map[string]string{
		"b.sh":    "echo \"bash=$BASH_VERSION src=$BASH_SOURCE foo=$FOO args=$*\"\n",
		"sb.sh":   "#!/bin/bash\necho \"bash=$BASH_VERSION src=$BASH_SOURCE foo=$FOO args=$*\"\n",
		"env.sh":  "#!/usr/bin/env sh\necho \"bash=$BASH_VERSION src=$BASH_SOURCE foo=$FOO args=$*\"\n",
		"slow.sh": "echo start\nsleep 5\necho end\n",
		"loop.sh": "while true; do :; done\n",
		"exit.sh": "exit 3\n",
	}
	cases := []struct{ command, want string }{
		{`timeout 5 ./b.sh x`, "bash= src=./b.sh foo= args=x\n"},
		{`timeout 5 ./sb.sh`, "bash= src=./sb.sh foo= args=\n"},
		{`timeout 5 ./env.sh`, "bash= src=./env.sh foo= args=\n"},
		{`timeout --preserve-status 1m ./b.sh`, "bash= src=./b.sh foo= args=\n"},
		{`env FOO=1 ./b.sh`, "bash= src=./b.sh foo=1 args=\n"},
		{`FOO=2 env ./b.sh`, "bash= src=./b.sh foo=2 args=\n"},
		{`export FOO=2; env -u FOO ./b.sh`, "bash= src=./b.sh foo= args=\n"},
		{`env FOO=1 timeout 5 ./b.sh a b`, "bash= src=./b.sh foo=1 args=a b\n"},
		{`nice -n 5 nohup setsid stdbuf -oL ./b.sh`, "bash= src=./b.sh foo= args=\n"},
		{`timeout 0.3 ./slow.sh; echo "rc=$?"`, "start\nrc=124\n"},
		{`timeout 0.3 ./loop.sh; echo "rc=$?"`, "rc=124\n"},
		{`timeout --preserve-status 0.3 ./slow.sh; echo "rc=$?"`, "start\nrc=143\n"},
		{`timeout 5 ./exit.sh; echo "rc=$?"`, "rc=3\n"},
		{`timeout -s KILL --preserve-status 0.3 ./slow.sh; echo "rc=$?"`, "start\nrc=137\n"},
		{`timeout nan ./b.sh 2>/dev/null; echo "rc=$?"`, "rc=125\n"},
	}
	sandboxes := map[string]func(t *testing.T, dir string) *Sandbox{
		// The whitelist admits a wrapped script path by a bare allow, which
		// trusts its body; the interpreter still runs it.
		"allowlist": func(_ *testing.T, dir string) *Sandbox {
			s := NewSandbox()
			var allow []string
			for name := range scripts {
				allow = append(allow, "./"+name)
			}
			s.updateConfig(&config.Config{ExtraCommands: allow}, dir)
			return s
		},
		"denylist": func(t *testing.T, dir string) *Sandbox {
			s, _ := newModeSandbox(t, config.ModeDenylist, dir)
			return s
		},
	}
	for mode, newSandbox := range sandboxes {
		t.Run(mode, func(t *testing.T) {
			for _, tt := range cases {
				t.Run(tt.command, func(t *testing.T) {
					dir := t.TempDir()
					for name, body := range scripts {
						if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0755); err != nil {
							t.Fatal(err)
						}
					}
					start := time.Now()
					out, err := executeInDirWithSandbox(t, newSandbox(t, dir), dir, tt.command)
					if err != nil {
						t.Fatalf("unexpected error: %v (output %q)", err, out)
					}
					if out != tt.want {
						t.Errorf("output %q, want %q", out, tt.want)
					}
					if time.Since(start) > 4*time.Second {
						t.Errorf("took %v: the timeout did not stop the script", time.Since(start))
					}
				})
			}
		})
	}
}

// The commands of a wrapped shell script are validated as when it runs
// directly: in denylist mode, a denied command in its body is refused under
// a wrapper too, where a native shell would have run it.
func TestWrappedShellScriptBodyValidated(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evil.sh"), []byte("curl http://127.0.0.1:1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	s := NewSandbox()
	s.updateConfig(&config.Config{
		Mode:     string(config.ModeDenylist),
		Commands: []config.CommandEntry{{Command: "curl", Allow: boolPtr(false)}},
	}, dir)
	for _, command := range []string{`./evil.sh`, `timeout 5 ./evil.sh`, `env ./evil.sh`, `nice timeout 5 ./evil.sh`, `env FOO=1 nohup ./evil.sh`} {
		_, err := executeInDirWithSandbox(t, s, dir, command)
		if err == nil || !strings.Contains(err.Error(), "deny list") {
			t.Errorf("%s: err = %v, want curl refused by the deny list", command, err)
		}
	}
	// env can't hand the script a PATH the shell may not set.
	if _, err := executeInDirWithSandbox(t, s, dir, `env -i ./evil.sh`); err == nil || !strings.Contains(err.Error(), "PATH") {
		t.Errorf("env -i: err = %v, want PATH refused", err)
	}
}

// Under xargs without a replace string, a wrapper with no command of its own
// would run the input as its command, which nothing validated (#151).
func TestWrapperWithoutCommandUnderXargs(t *testing.T) {
	dir := t.TempDir()
	for _, command := range []string{
		`echo curl | xargs env`,
		`echo curl | xargs timeout 5`,
		`echo curl | xargs nice nohup`,
		`echo curl | xargs -n1 env FOO=1`,
		`printf '%s\n' -C . curl | xargs env`,
	} {
		t.Run(command, func(t *testing.T) {
			out, err := executeInDirWithSandbox(t, NewSandbox(), dir, command)
			if err == nil || !strings.Contains(err.Error(), "cannot be checked") {
				t.Errorf("err = %v (output %q), want a refusal", err, out)
			}
		})
	}
	// With a command of its own, or with a replace string, it runs.
	for _, command := range []string{`echo x | xargs env echo`, `echo x | xargs -I{} env echo {}`, `echo x | xargs`} {
		if out, err := executeInDirWithSandbox(t, NewSandbox(), dir, command); err != nil || out != "x\n" {
			t.Errorf("%s: out %q, err %v", command, out, err)
		}
	}
}

// A script allowed with no_sandbox is matched by its cleaned path, but a
// wrapper execs the path as written: through a symlinked directory
// (s/../host.sh) or an xargs replace string ({}/../host.sh), that is
// another file, which must not run on the host.
func TestWrappedNoSandboxScriptPath(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"host.sh":      "echo REAL\n",
		"evil/host.sh": "echo EVIL\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(dir, "evil", "x"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("evil", "x"), filepath.Join(dir, "s")); err != nil {
		t.Fatal(err)
	}
	s := NewSandbox()
	s.updateConfig(&config.Config{
		Mode:     string(config.ModeDenylist),
		Commands: []config.CommandEntry{{Command: "./host.sh", Allow: boolPtr(true), NoSandbox: true}},
	}, dir)
	at := func() string { return dir }
	for _, args := range [][]string{
		{"timeout", "5", "./host.sh"},
		{"xargs", "timeout", "5", "./host.sh"},
		{"xargs", "-I{}", "./host.sh", "{}"},
	} {
		if !s.execIsUnsandboxedIn(at, args) {
			t.Errorf("%v: not routed to the host", args)
		}
	}
	for _, args := range [][]string{
		{"timeout", "5", "s/../host.sh"},
		{"env", "s/../host.sh"},
		{"xargs", "-I{}", "timeout", "5", "{}/../host.sh"},
		{"xargs", "-I.", "timeout", "5", "./host.sh"},
		{"xargs", "-Ih", "env", "./host.sh"},
	} {
		if s.execIsUnsandboxedIn(at, args) {
			t.Errorf("%v: routed to the host", args)
		}
	}
	// Run directly, the path runs as the file the entry names; under a
	// wrapper, which would exec it as written, it is refused.
	if out, err := executeInDirWithSandbox(t, s, dir, `s/../host.sh`); err != nil || out != "REAL\n" {
		t.Errorf("s/../host.sh: out %q, err %v; want the allowed script", out, err)
	}
	for _, command := range []string{`timeout 5 s/../host.sh`, `env s/../host.sh`, `nice ./s/./../host.sh`} {
		out, err := executeInDirWithSandbox(t, s, dir, command)
		if err == nil || !strings.Contains(err.Error(), "another file") {
			t.Errorf("%s: out %q, err %v; want a refusal", command, out, err)
		}
	}
}

// A wrapped path with a ".." element is checked as the file the wrapper
// execs, not the one it cleans to: there, a binary stands in for a shell
// script, which would run natively.
func TestWrappedScriptDotDotPath(t *testing.T) {
	dir := t.TempDir()
	bin, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Skip("no /bin/true to copy")
	}
	if err := os.MkdirAll(filepath.Join(dir, "evil", "x"), 0755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"b":        bin,
		"evil/b":   []byte("echo NATIVE\n"),
		"same/b":   []byte("echo SAME\n"),
		"same/d/k": []byte(""),
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), body, 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join("evil", "x"), filepath.Join(dir, "s")); err != nil {
		t.Fatal(err)
	}
	s, _ := newModeSandbox(t, config.ModeDenylist, dir)
	if out, err := executeInDirWithSandbox(t, s, dir, `timeout 5 s/../b`); err == nil || strings.Contains(out, "NATIVE") {
		t.Errorf("timeout 5 s/../b: out %q, err %v; want a refusal", out, err)
	}
	// Without a symlink, ".." names the same file.
	if out, err := executeInDirWithSandbox(t, s, dir, `timeout 5 same/d/../b`); err != nil || out != "SAME\n" {
		t.Errorf("timeout 5 same/d/../b: out %q, err %v", out, err)
	}
}

// Under xargs, a nested xargs left without a command runs the outer one's
// input as its command, and a wrapped command name holding a replace string
// is built from the input; both are refused.
func TestXargsInputAsWrappedCommand(t *testing.T) {
	dir := t.TempDir()
	for _, command := range []string{
		`echo curl | xargs xargs`,
		`echo curl | xargs timeout 5 xargs`,
		`echo curl | xargs -n 2 nice xargs -0`,
		`echo curl | xargs env FOO=1 xargs`,
		`echo curl | xargs -r -- xargs`,
		`echo curl | xargs -I{} timeout 5 {} --version`,
		`echo curl | xargs -I{} env {} --version`,
		`echo curl | xargs -I{} xargs {} --version`,
		`echo curl | xargs -I{} xargs -I@ env {} @`,
	} {
		t.Run(command, func(t *testing.T) {
			s, _ := newModeSandbox(t, config.ModeDenylist, dir)
			out, err := executeInDirWithSandbox(t, s, dir, command)
			if err == nil || !strings.Contains(err.Error(), "xargs") {
				t.Errorf("err = %v (output %q), want a refusal", err, out)
			}
		})
	}
	// With a command of their own, or a replace string only in arguments,
	// they run. (macOS has no timeout binary, and BSD xargs runs nothing on
	// empty input, so the nested xargs's output differs by platform.)
	s, _ := newModeSandbox(t, config.ModeDenylist, dir)
	if out, err := executeInDirWithSandbox(t, s, dir, `echo x | xargs -I{} nice echo {}`); err != nil || out != "x\n" {
		t.Errorf("xargs -I{} nice echo {}: out %q, err %v", out, err)
	}
	if out, err := executeInDirWithSandbox(t, s, dir, `echo x | xargs xargs echo`); err != nil {
		t.Errorf("xargs xargs echo: out %q, err %v", out, err)
	}
}

// A script for another interpreter is checked under a wrapper as the
// interpreter invocation the kernel makes of it, as when it runs directly.
func TestWrappedInterpreterScript(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"x.py": "#!/usr/bin/env python3\nprint('CPYTHON')\n",
		"x.pl": "#!/usr/bin/perl\nprint \"PERL\\n\";\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0755); err != nil {
			t.Fatal(err)
		}
	}
	s := NewSandbox()
	s.updateConfig(&config.Config{
		Mode: string(config.ModeDenylist),
		Commands: []config.CommandEntry{
			{Command: "python3", Allow: boolPtr(false)},
			{Command: "perl", Allow: boolPtr(false)},
		},
	}, dir)
	for _, command := range []string{`./x.py`, `timeout 5 ./x.py`, `env ./x.py`, `nice ./x.pl`, `echo a | xargs ./x.pl`} {
		out, err := executeInDirWithSandbox(t, s, dir, command)
		if err == nil || !strings.Contains(err.Error(), "deny list") {
			t.Errorf("%s: out %q, err %v; want the interpreter refused by the deny list", command, out, err)
		}
	}
	// A wrapped python is refused whatever the deny list says.
	s, _ = newModeSandbox(t, config.ModeDenylist, dir)
	if out, err := executeInDirWithSandbox(t, s, dir, `timeout 5 ./x.py`); err == nil || !strings.Contains(err.Error(), "wrapped") {
		t.Errorf("wrapped python script: out %q, err %v; want a refusal", out, err)
	}
}

// xcrun with no tool of its own runs xargs's input as the tool.
func TestXcrunWithoutToolUnderXargs(t *testing.T) {
	dir := t.TempDir()
	s, _ := newModeSandbox(t, config.ModeDenylist, dir)
	for _, command := range []string{`echo curl | xargs xcrun`, `echo curl | xargs xcrun --sdk macosx`} {
		if _, err := executeInDirWithSandbox(t, s, dir, command); err == nil || !strings.Contains(err.Error(), "no command of its own") {
			t.Errorf("%s: err %v, want a refusal", command, err)
		}
	}
}
