package bash_sandboxed

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// runPython executes a command against a sandbox rooted at dir, with dir both
// readable and writable, and returns the combined output plus any error.
func runPython(t *testing.T, s *Sandbox, dir, command string) (string, error) {
	t.Helper()
	return s.Execute(context.Background(), command, dir, []string{dir}, []string{dir})
}

// pythonTestDir builds a working directory with a file to read, a .git
// directory, and a symlink pointing at a file outside the boundary. It returns
// the working directory and the outside directory.
func pythonTestDir(t *testing.T) (dir, outside string) {
	t.Helper()
	dir = t.TempDir()
	outside = t.TempDir()

	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(dir, "in.txt"), "hello world")
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(filepath.Join(dir, ".git", "config"), "[remote]")
	write(filepath.Join(outside, "secret.txt"), "TOPSECRET")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(dir, "escape.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "escapedir")); err != nil {
		t.Fatal(err)
	}
	return dir, outside
}

// TestPythonPathBoundary is the core security test: Python file I/O must obey
// exactly the same read/write boundary as bash. Every denial here is a case
// where monty asked the host to touch a file and the host said no.
func TestPythonPathBoundary(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()

	tests := []struct {
		name    string
		program string
		// wantErr is a fragment of the expected denial. Empty means the
		// program must succeed.
		wantErr string
		wantOut string
	}{
		{
			name:    "read inside the working directory",
			program: `print(Path('in.txt').read_text())`,
			wantOut: "hello world\n",
		},
		{
			name:    "write inside the working directory",
			program: `Path('out.txt').write_text('written'); print(Path('out.txt').read_text())`,
			wantOut: "written\n",
		},
		{
			name:    "read an absolute path outside the boundary",
			program: `print(Path(OUTSIDE + '/secret.txt').read_text())`,
			wantErr: "outside allowed directories",
		},
		{
			name:    "write an absolute path outside the boundary",
			program: `Path(OUTSIDE + '/pwned.txt').write_text('x')`,
			wantErr: "outside allowed directories",
		},
		{
			name:    "read through a symlink that escapes the boundary",
			program: `print(Path('escape.txt').read_text())`,
			wantErr: "outside allowed directories",
		},
		{
			name:    "write through a symlinked directory that escapes",
			program: `Path('escapedir/pwned.txt').write_text('x')`,
			wantErr: "outside allowed directories",
		},
		{
			name:    "traverse out with ..",
			program: `print(Path('../../etc/passwd').read_text())`,
			wantErr: "outside allowed directories",
		},
		{
			name:    "read inside .git",
			program: `print(Path('.git/config').read_text())`,
			wantErr: ".git directory which is not allowed",
		},
		{
			name:    "write inside .git",
			program: `Path('.git/hooks').mkdir()`,
			wantErr: ".git directory which is not allowed",
		},
		{
			name:    "stat outside the boundary",
			program: `print(Path(OUTSIDE + '/secret.txt').stat())`,
			wantErr: "outside allowed directories",
		},
		{
			name:    "iterdir outside the boundary",
			program: `print(list(Path(OUTSIDE).iterdir()))`,
			wantErr: "outside allowed directories",
		},
		{
			name:    "unlink outside the boundary",
			program: `Path(OUTSIDE + '/secret.txt').unlink()`,
			wantErr: "outside allowed directories",
		},
		{
			name:    "rename a file out of the boundary",
			program: `Path('in.txt').rename(OUTSIDE + '/stolen.txt')`,
			wantErr: "outside allowed directories",
		},
		{
			// An existing file outside the boundary is a denial rather than
			// False. A *non-existent* absolute path is not: checkPathBoundary
			// lets those through on the read side, so exists() is the same
			// one-bit oracle for host paths that bash already is. Matching
			// bash exactly is the point; see TestPythonExistsMatchesBash.
			name:    "exists on a file outside the boundary is denied",
			program: `print(Path(OUTSIDE + '/secret.txt').exists())`,
			wantErr: "outside allowed directories",
		},
		{
			name:    "mkdir and rmdir inside the boundary",
			program: `Path('sub/deep').mkdir(parents=True); print(Path('sub/deep').is_dir()); Path('sub/deep').rmdir(); print(Path('sub/deep').exists())`,
			wantOut: "True\nFalse\n",
		},
		{
			name:    "rename inside the boundary",
			program: `Path('a.txt').write_text('v'); Path('a.txt').rename('b.txt'); print(Path('b.txt').read_text())`,
			wantOut: "v\n",
		},
		{
			name:    "iterdir hides .git",
			program: `print([str(p) for p in sorted(Path('.').iterdir()) if 'git' in str(p)])`,
			wantOut: "[]\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Each case gets a fresh tree so writes from one do not leak into
			// the next.
			dir, outside := pythonTestDir(t)
			program := strings.ReplaceAll(tt.program, "OUTSIDE", "'"+outside+"'")
			cmd := `python3 -c "from pathlib import Path
` + program + `"`

			out, err := runPython(t, s, dir, cmd)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected denial containing %q, got success with output %q", tt.wantErr, out)
				}
				combined := err.Error() + out
				if !strings.Contains(combined, tt.wantErr) {
					t.Fatalf("expected denial containing %q, got %v (output %q)", tt.wantErr, err, out)
				}
				// A denial must never also produce the protected content.
				if strings.Contains(combined, "TOPSECRET") {
					t.Fatalf("denial leaked the protected file's contents: %v", combined)
				}
				return
			}
			if err != nil {
				t.Fatalf("expected success, got %v (output %q)", err, out)
			}
			if out != tt.wantOut {
				t.Fatalf("got output %q, want %q", out, tt.wantOut)
			}
		})
	}
}

// TestPythonReadOnlyPath checks the read and write sets are honoured
// separately: a directory that is readable but not writable must accept reads
// and refuse writes, exactly as it does for bash.
func TestPythonReadOnlyPath(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()

	workDir := t.TempDir()
	readOnly := t.TempDir()
	if err := os.WriteFile(filepath.Join(readOnly, "ref.txt"), []byte("reference"), 0o644); err != nil {
		t.Fatal(err)
	}

	read := []string{workDir, readOnly}
	write := []string{workDir}

	out, err := s.Execute(context.Background(),
		`python3 -c "from pathlib import Path; print(Path('`+readOnly+`/ref.txt').read_text())"`,
		workDir, read, write)
	if err != nil {
		t.Fatalf("reading a readable path failed: %v (output %q)", err, out)
	}
	if out != "reference\n" {
		t.Fatalf("got %q, want %q", out, "reference\n")
	}

	out, err = s.Execute(context.Background(),
		`python3 -c "from pathlib import Path; Path('`+readOnly+`/new.txt').write_text('x')"`,
		workDir, read, write)
	if err == nil {
		t.Fatalf("writing to a read-only path succeeded (output %q)", out)
	}
	if !strings.Contains(err.Error(), "outside allowed directories") {
		t.Fatalf("expected a boundary denial, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(readOnly, "new.txt")); statErr == nil {
		t.Fatal("the denied write created the file anyway")
	}
}

// TestPythonScriptFileIsPathChecked covers the script argument itself: it is a
// file read like any other and must not be a way around the boundary.
func TestPythonScriptFileIsPathChecked(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()

	dir, outside := pythonTestDir(t)
	scriptOutside := filepath.Join(outside, "evil.py")
	if err := os.WriteFile(scriptOutside, []byte("print('ran')\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := runPython(t, s, dir, "python3 "+scriptOutside); err == nil {
		t.Fatal("running a script from outside the boundary succeeded")
	} else if !strings.Contains(err.Error(), "outside allowed directories") {
		t.Fatalf("expected a boundary denial, got %v", err)
	}

	// The same script inside the boundary runs.
	if err := os.WriteFile(filepath.Join(dir, "ok.py"), []byte("print('ran')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runPython(t, s, dir, "python3 ok.py")
	if err != nil {
		t.Fatalf("running a script inside the boundary failed: %v", err)
	}
	if out != "ran\n" {
		t.Fatalf("got %q, want %q", out, "ran\n")
	}
}

// TestPythonNoEnvironment checks that Python cannot read the host environment.
// The rest of the sandbox goes to some trouble to mask credentials; an
// os.getenv that reached through would undo it.
func TestPythonNoEnvironment(t *testing.T) {
	t.Setenv("LITE_SANDBOX_SECRET_TEST", "leaked")

	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	out, err := runPython(t, s, dir,
		`python3 -c "import os; print(os.getenv('LITE_SANDBOX_SECRET_TEST')); print(os.getenv('X', 'fallback')); print(len(os.environ))"`)
	if err != nil {
		t.Fatalf("unexpected error: %v (output %q)", err, out)
	}
	want := "None\nfallback\n0\n"
	if out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}

func TestParsePythonArgs(t *testing.T) {
	readScript := func(path string) (string, error) { return "# " + path, nil }

	tests := []struct {
		name            string
		args            []string
		stdin           string
		wantCode        string
		wantName        string
		wantArgv        []string
		wantSyntaxCheck []string
		wantErr         string
	}{
		{
			name:     "inline code",
			args:     []string{"python3", "-c", "print(1)"},
			wantCode: "print(1)",
			wantName: "-c",
		},
		{
			name:     "script file",
			args:     []string{"python3", "s.py"},
			wantCode: "# s.py",
			wantName: "s.py",
		},
		{
			name:     "stdin",
			args:     []string{"python3", "-"},
			stdin:    "print(2)",
			wantCode: "print(2)",
			wantName: "<stdin>",
		},
		{
			name:     "ignorable flags before a script",
			args:     []string{"python3", "-u", "-B", "s.py"},
			wantCode: "# s.py",
			wantName: "s.py",
		},
		{
			name:    "module execution",
			args:    []string{"python3", "-m", "json.tool"},
			wantErr: "is not supported",
		},
		{
			name:     "arguments after a script become sys.argv",
			args:     []string{"python3", "s.py", "arg"},
			wantCode: "# s.py",
			wantName: "s.py",
			wantArgv: []string{"s.py", "arg"},
		},
		{
			name:     "arguments after inline code become sys.argv",
			args:     []string{"python3", "-c", "print(1)", "arg"},
			wantCode: "print(1)",
			wantName: "-c",
			wantArgv: []string{"-c", "arg"},
		},
		{
			name:            "py_compile is served as a syntax check",
			args:            []string{"python3", "-m", "py_compile", "a.py", "b.py"},
			wantName:        "py_compile",
			wantSyntaxCheck: []string{"a.py", "b.py"},
		},
		{
			name:    "missing code for -c",
			args:    []string{"python3", "-c"},
			wantErr: "argument to -c is missing",
		},
		{
			name:    "unsupported flag",
			args:    []string{"python3", "-X", "dev"},
			wantErr: `flag "-X" is not supported`,
		},
		{
			name:    "no program starts no REPL",
			args:    []string{"python3"},
			wantErr: "interactive interpreter is not available",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inv, err := parsePythonArgs(tt.args, strings.NewReader(tt.stdin), readScript)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got %+v", tt.wantErr, inv)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if inv.code != tt.wantCode {
				t.Errorf("code = %q, want %q", inv.code, tt.wantCode)
			}
			if inv.name != tt.wantName {
				t.Errorf("name = %q, want %q", inv.name, tt.wantName)
			}
			if tt.wantArgv != nil && !slices.Equal(inv.argv, tt.wantArgv) {
				t.Errorf("argv = %q, want %q", inv.argv, tt.wantArgv)
			}
			if !slices.Equal(inv.syntaxCheck, tt.wantSyntaxCheck) {
				t.Errorf("syntaxCheck = %q, want %q", inv.syntaxCheck, tt.wantSyntaxCheck)
			}
		})
	}
}

// TestPythonUnsupportedFeaturesExplainThemselves covers the failure mode that
// makes or breaks this feature: monty is a Python subset, and an agent that
// hits one of its walls must be told what it hit and what to do instead,
// otherwise the next move is `pip install`.
func TestPythonUnsupportedFeaturesExplainThemselves(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	tests := []struct {
		name     string
		command  string
		wantAll  []string
		wantExit bool
	}{
		{
			name:    "third-party import",
			command: `python3 -c "import numpy"`,
			wantAll: []string{"ModuleNotFoundError", "monty", "not CPython", "uv run"},
		},

		{
			name:    "open() has no file object",
			command: `python3 -c "print(open('x.txt').read())"`,
			wantAll: []string{"open() is not supported", "monty", "read_text"},
		},
		{
			name:    "an unavailable module names the one that works",
			command: `python3 -m http.server`,
			wantAll: []string{"is not supported", "py_compile", "uv run"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runPython(t, s, dir, tt.command)
			if err == nil {
				t.Fatalf("expected a failure, got success with output %q", out)
			}
			combined := out + err.Error()
			for _, want := range tt.wantAll {
				if !strings.Contains(combined, want) {
					t.Errorf("message does not mention %q:\n%s", want, combined)
				}
			}
		})
	}
}

// TestPythonTracebackNamesTheScript checks the traceback points at the file the
// agent actually ran. monty labels every frame "script.py" regardless.
func TestPythonTracebackNamesTheScript(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "boom.py"), []byte("x = 1\nraise ValueError('boom')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runPython(t, s, dir, "python3 boom.py")
	if err == nil {
		t.Fatal("expected the script to fail")
	}
	combined := out + err.Error()
	if !strings.Contains(combined, `File "boom.py"`) {
		t.Errorf("traceback does not name boom.py:\n%s", combined)
	}
	if strings.Contains(combined, `File "script.py"`) {
		t.Errorf("traceback still uses monty's placeholder name:\n%s", combined)
	}
	if !strings.Contains(combined, "line 2") {
		t.Errorf("traceback lost the line number:\n%s", combined)
	}
}

// TestPythonExitStatus checks a failing program behaves like an interpreter, so
// shell control flow around it works.
func TestPythonExitStatus(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	out, err := runPython(t, s, dir, `python3 -c "raise SystemError('x')" || echo handled`)
	if err != nil {
		t.Fatalf("unexpected error: %v (output %q)", err, out)
	}
	if !strings.Contains(out, "handled") {
		t.Errorf("a failing program did not report a non-zero status: %q", out)
	}

	out, err = runPython(t, s, dir, `python3 -c "print('ok')" && echo chained`)
	if err != nil {
		t.Fatalf("unexpected error: %v (output %q)", err, out)
	}
	if !strings.Contains(out, "ok") || !strings.Contains(out, "chained") {
		t.Errorf("a successful program did not report success: %q", out)
	}
}

// TestPythonPipesAndRedirection checks the interpreter is wired into the shell
// the way an external command would be.
func TestPythonPipesAndRedirection(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	out, err := runPython(t, s, dir, `python3 -c "print('b'); print('a')" | sort`)
	if err != nil {
		t.Fatalf("unexpected error: %v (output %q)", err, out)
	}
	if out != "a\nb\n" {
		t.Errorf("got %q, want %q", out, "a\nb\n")
	}

	out, err = runPython(t, s, dir, `echo "print(6*7)" | python3 -`)
	if err != nil {
		t.Fatalf("unexpected error: %v (output %q)", err, out)
	}
	if out != "42\n" {
		t.Errorf("got %q, want %q", out, "42\n")
	}

	if out, err := runPython(t, s, dir, `python3 -c "print('redirected')" > out.txt && cat out.txt`); err != nil {
		t.Fatalf("unexpected error: %v (output %q)", err, out)
	} else if out != "redirected\n" {
		t.Errorf("got %q, want %q", out, "redirected\n")
	}
}

// TestPythonRuntimeToggle covers the config switch. Python is the one runtime
// that defaults on, so both directions are worth pinning down.
func TestPythonRuntimeToggle(t *testing.T) {
	dir := t.TempDir()

	t.Run("enabled by default with no config at all", func(t *testing.T) {
		s := newTestSandbox()
		defer s.Close()
		if out, err := runPython(t, s, dir, `python3 -c "print('on')"`); err != nil {
			t.Fatalf("python should be enabled by default: %v (output %q)", err, out)
		}
	})

	t.Run("enabled when other runtimes are configured", func(t *testing.T) {
		s := newTestSandboxWithRuntimesConfig(&config.RuntimesConfig{
			Go: &config.GoConfig{Enabled: boolPtr(true)},
		})
		defer s.Close()
		if out, err := runPython(t, s, dir, `python3 -c "print('on')"`); err != nil {
			t.Fatalf("python should stay enabled: %v (output %q)", err, out)
		}
	})

	t.Run("disabled by config", func(t *testing.T) {
		s := newTestSandboxWithRuntimesConfig(&config.RuntimesConfig{
			Python: &config.PythonConfig{Enabled: boolPtr(false)},
		})
		defer s.Close()
		for _, cmd := range []string{`python3 -c "print(1)"`, `python -c "print(1)"`} {
			_, err := runPython(t, s, dir, cmd)
			if err == nil {
				t.Fatalf("%s should be rejected when the runtime is disabled", cmd)
			}
			if !strings.Contains(err.Error(), "runtimes.python.enabled is disabled") {
				t.Fatalf("expected the config key in the error, got %v", err)
			}
		}
	})

	t.Run("explicitly enabled", func(t *testing.T) {
		s := newTestSandboxWithRuntimesConfig(&config.RuntimesConfig{
			Python: &config.PythonConfig{Enabled: boolPtr(true)},
		})
		defer s.Close()
		if out, err := runPython(t, s, dir, `python3 -c "print('on')"`); err != nil {
			t.Fatalf("unexpected error: %v (output %q)", err, out)
		}
	})
}

// TestPythonDeniedInsideWrappers checks the disabled switch is not escapable
// through the wrappers that run other commands.
func TestPythonDeniedInsideWrappers(t *testing.T) {
	s := newTestSandboxWithRuntimesConfig(&config.RuntimesConfig{
		Python: &config.PythonConfig{Enabled: boolPtr(false)},
	})
	defer s.Close()
	dir := t.TempDir()

	for _, cmd := range []string{
		`bash -c 'python3 -c "print(1)"'`,
		`echo x | xargs python3`,
		`find . -exec python3 {} \;`,
		`CMD=python3; $CMD -c "print(1)"`,
	} {
		if _, err := runPython(t, s, dir, cmd); err == nil {
			t.Errorf("%s was allowed with the python runtime disabled", cmd)
		}
	}
}

// TestPythonSuspensionLimit checks the host-call budget stops a script that
// loops on filesystem operations. The command timeout cannot: time spent in
// host calls does not advance monty's own duration accounting.
func TestPythonSuspensionLimit(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	out, err := runPython(t, s, dir, `python3 -c "from pathlib import Path
n = 0
while n < `+strconv.Itoa(montyMaxSuspensions+1000)+`:
    Path('x').exists()
    n = n + 1
print(n)"`)
	if err == nil {
		t.Fatalf("a host-call loop ran to completion: %q", out)
	}
	combined := out + err.Error()
	if !strings.Contains(combined, "suspensions") {
		t.Fatalf("expected the suspension limit to stop it, got %v", err)
	}
	if !strings.Contains(combined, "filesystem operations") {
		t.Errorf("the limit was not explained to the agent:\n%s", combined)
	}
}

// TestPythonWithOSSandboxEnabled checks Python is dispatched before the OS
// sandbox worker is ever consulted. monty is in-process wasm, so it does not
// (and cannot) run inside the bwrap/sandbox-exec worker; its file access is
// confined by os.Root instead. This test therefore passes on a host with no
// bubblewrap installed, which is exactly the property being asserted.
func TestPythonWithOSSandboxEnabled(t *testing.T) {
	s := newTestSandboxWithOSSandbox()
	defer s.Close()

	dir, outside := pythonTestDir(t)

	out, err := runPython(t, s, dir,
		`python3 -c "from pathlib import Path; Path('out.txt').write_text('ok'); print(Path('out.txt').read_text())"`)
	if err != nil {
		t.Fatalf("python should run with the OS sandbox enabled: %v (output %q)", err, out)
	}
	if out != "ok\n" {
		t.Fatalf("got %q, want %q", out, "ok\n")
	}

	// The boundary still holds: it comes from the OS-call handler, not the worker.
	if _, err := runPython(t, s, dir,
		`python3 -c "from pathlib import Path; print(Path('`+outside+`/secret.txt').read_text())"`); err == nil {
		t.Fatal("reading outside the boundary succeeded with the OS sandbox enabled")
	}
}

// TestPythonNeverEscapesViaWrappers is a regression test for a real escape.
// python/python3 are on the whitelist, but the dispatch to monty only happens
// when the sandbox interpreter is the direct caller. A wrapper (xargs, env,
// timeout, find -exec) spawns its child as a native process, which resolves the
// *host* CPython from $PATH — arbitrary file access, subprocess and network,
// outside every layer of this sandbox. subCommandDenylist is what stops it.
func TestPythonNeverEscapesViaWrappers(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()

	dir := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	steal := `python3 -c "print(open('` + secret + `').read())"`

	for _, command := range []string{
		"echo x | xargs " + steal,
		"env " + steal,
		"timeout 10 " + steal,
		`find . -maxdepth 0 -exec ` + steal + ` \;`,
		"echo x | xargs python " + filepath.Join(outside, "evil.py"),
	} {
		t.Run(command, func(t *testing.T) {
			out, err := runPython(t, s, dir, command)
			if err == nil {
				t.Fatalf("a wrapper ran python outside the sandbox: %q", out)
			}
			if strings.Contains(out+err.Error(), "TOPSECRET") {
				t.Fatalf("ESCAPE: host python read a file outside the boundary: %q / %v", out, err)
			}
		})
	}
}

// TestPythonStdinWithoutInput covers `python3 -` with nothing piped in. The
// interpreter leaves Stdin nil there, and reading it panicked on the
// interpreter goroutine, which nothing recovers — taking the MCP server with it.
func TestPythonStdinWithoutInput(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	out, err := runPython(t, s, dir, "python3 -")
	if err == nil {
		t.Fatalf("expected an error, got %q", out)
	}
	if !strings.Contains(out+err.Error(), "nothing is piped in") {
		t.Fatalf("expected an explanation of the missing stdin, got %v (output %q)", err, out)
	}
}

// TestPythonExtraCommandsRunsRealPython covers the opt-out: naming python in
// extra_commands (or unsandboxed_commands) is a deliberate request for the real
// interpreter, since monty cannot import third-party packages.
func TestPythonExtraCommandsRunsRealPython(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("no python3 on PATH to run as the real interpreter")
	}
	dir := t.TempDir()

	// A program that only real CPython can run: monty has no sys.executable
	// and cannot import a third-party-style module path.
	realOnly := `python3 -c "import sys; print('real' if hasattr(sys, 'executable') else 'monty')"`

	t.Run("without an extra_commands entry it runs on monty", func(t *testing.T) {
		s := newTestSandbox()
		defer s.Close()
		out, err := runPython(t, s, dir, realOnly)
		if err == nil && strings.Contains(out, "real") {
			t.Fatalf("ran the host interpreter without being asked to: %q", out)
		}
	})

	t.Run("a bare extra_commands entry runs the real interpreter", func(t *testing.T) {
		s := NewSandbox()
		defer s.Close()
		s.UpdateConfig(&config.Config{ExtraCommands: []string{"python3"}}, dir)
		out, err := runPython(t, s, dir, realOnly)
		if err != nil {
			t.Fatalf("unexpected error: %v (output %q)", err, out)
		}
		if !strings.Contains(out, "real") {
			t.Fatalf("expected the host interpreter, got %q", out)
		}
	})

	t.Run("a subcommand-restricted entry only covers matching invocations", func(t *testing.T) {
		s := NewSandbox()
		defer s.Close()
		s.UpdateConfig(&config.Config{ExtraCommands: []string{"python3 real.py"}}, dir)

		if err := os.WriteFile(filepath.Join(dir, "real.py"),
			[]byte("import sys\nprint('real' if hasattr(sys, 'executable') else 'monty')\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := runPython(t, s, dir, "python3 real.py")
		if err != nil {
			t.Fatalf("unexpected error: %v (output %q)", err, out)
		}
		if !strings.Contains(out, "real") {
			t.Fatalf("the matching invocation should use the host interpreter, got %q", out)
		}

		// A non-matching invocation still goes to monty.
		out, err = runPython(t, s, dir, `python3 -c "print('on-monty')"`)
		if err != nil {
			t.Fatalf("unexpected error: %v (output %q)", err, out)
		}
		if !strings.Contains(out, "on-monty") {
			t.Fatalf("expected monty to run the non-matching invocation, got %q", out)
		}
	})
}

// TestPythonAllowedEntryThatIsNotADirectory covers allowed-path entries that
// are not open-able directories: a file-granular grant, and a directory that
// does not exist yet. bash handles both, so Python must not be stricter.
func TestPythonAllowedEntryThatIsNotADirectory(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()

	workDir := t.TempDir()
	other := t.TempDir()
	refFile := filepath.Join(other, "ref.txt")
	if err := os.WriteFile(refFile, []byte("REF"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("a file-granular readable entry", func(t *testing.T) {
		out, err := s.Execute(context.Background(),
			`python3 -c "from pathlib import Path; print(Path('`+refFile+`').read_text())"`,
			workDir, []string{workDir, refFile}, []string{workDir})
		if err != nil {
			t.Fatalf("reading a file-granular readable entry failed: %v (output %q)", err, out)
		}
		if out != "REF\n" {
			t.Fatalf("got %q, want %q", out, "REF\n")
		}
		// The grant is still only that one file.
		sibling := filepath.Join(other, "sibling.txt")
		if err := os.WriteFile(sibling, []byte("NOPE"), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := s.Execute(context.Background(),
			`python3 -c "from pathlib import Path; print(Path('`+sibling+`').read_text())"`,
			workDir, []string{workDir, refFile}, []string{workDir}); err == nil {
			t.Fatalf("a file-granular grant leaked its whole directory: %q", out)
		}
	})

	t.Run("a writable entry that does not exist yet", func(t *testing.T) {
		scratch := filepath.Join(t.TempDir(), "scratch") // deliberately not created
		out, err := s.Execute(context.Background(),
			`python3 -c "from pathlib import Path; Path('`+scratch+`/sub').mkdir(parents=True); print(Path('`+scratch+`/sub').is_dir())"`,
			workDir, []string{workDir, scratch}, []string{workDir, scratch})
		if err != nil {
			t.Fatalf("writing under a not-yet-created writable entry failed: %v (output %q)", err, out)
		}
		if out != "True\n" {
			t.Fatalf("got %q, want %q", out, "True\n")
		}
	})
}

// TestPythonCodeIsNotAPath checks that the -c program is exempt from the
// generic path checker. The code routinely contains "/" in a string literal,
// which was enough to get the whole program resolved as a path and rejected.
func TestPythonCodeIsNotAPath(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	out, err := runPython(t, s, dir, `python3 -c "print('../../../../etc/passwd')"`)
	if err != nil {
		t.Fatalf("a program that merely mentions a path was rejected: %v (output %q)", err, out)
	}
	if out != "../../../../etc/passwd\n" {
		t.Fatalf("got %q", out)
	}

	// Exempting the code must not exempt actually reading that path.
	if out, err := runPython(t, s, dir,
		`python3 -c "from pathlib import Path; print(Path('../../../../etc/passwd').read_text())"`); err == nil {
		t.Fatalf("reading outside the boundary succeeded: %q", out)
	}
}

// TestPythonExistsMatchesBash pins the one place Python's answer is a
// disclosure: a non-existent absolute path outside the boundary reports False
// rather than denying, because checkPathBoundary lets non-existent reads
// through. That is bash's behavior too, and the two must not drift apart.
func TestPythonExistsMatchesBash(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	missing := "/definitely/not/here/at/all.txt"
	out, err := runPython(t, s, dir, `python3 -c "from pathlib import Path; print(Path('`+missing+`').exists())"`)
	if err != nil {
		t.Fatalf("unexpected error: %v (output %q)", err, out)
	}
	if out != "False\n" {
		t.Fatalf("got %q, want %q", out, "False\n")
	}
	// bash reaches the same conclusion for the same path.
	if out, err := runPython(t, s, dir, "test -e "+missing+" && echo yes || echo no"); err != nil || out != "no\n" {
		t.Fatalf("bash disagreed: %q %v", out, err)
	}
}

// TestPythonPyCompile covers `python -m py_compile FILE...`, the idiom agents
// use to check a file's syntax. monty compiles a whole module before running
// any of it, which is what lets this be a real check rather than a run.
func TestPythonPyCompile(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()

	write := func(t *testing.T, dir, name, content string) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}

	t.Run("a file that compiles reports nothing and succeeds", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "good.py", "def f():\n    return 1\n")
		out, err := runPython(t, s, dir, "python3 -m py_compile good.py && echo OK")
		if err != nil {
			t.Fatalf("unexpected error: %v (output %q)", err, out)
		}
		if out != "OK\n" {
			t.Fatalf("py_compile should be silent on success, got %q", out)
		}
	})

	t.Run("tab-indented source is not mangled into a TabError", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "tabs.py", "def f():\n\treturn 1\n")
		if out, err := runPython(t, s, dir, "python3 -m py_compile tabs.py"); err != nil {
			t.Fatalf("tab-indented source failed to compile: %v (output %q)", err, out)
		}
	})

	t.Run("a syntax error is reported with the file's own name and line", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "bad.py", "x = 1\nif True\n    pass\n")
		out, err := runPython(t, s, dir, "python3 -m py_compile bad.py")
		if err == nil {
			t.Fatalf("expected a failure, got %q", out)
		}
		combined := out + err.Error()
		for _, want := range []string{"SyntaxError", `File "bad.py"`, "line 2"} {
			if !strings.Contains(combined, want) {
				t.Errorf("error does not mention %q:\n%s", want, combined)
			}
		}
		if strings.Contains(combined, syntaxOKMarker) {
			t.Errorf("the syntax probe leaked into the message:\n%s", combined)
		}
	})

	t.Run("the file is checked, never run", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "effect.py", "from pathlib import Path\nPath('SIDE_EFFECT.txt').write_text('x')\nprint('RAN')\n")
		out, err := runPython(t, s, dir, "python3 -m py_compile effect.py")
		if err != nil {
			t.Fatalf("unexpected error: %v (output %q)", err, out)
		}
		if strings.Contains(out, "RAN") {
			t.Fatalf("py_compile executed the file: %q", out)
		}
		if _, err := os.Stat(filepath.Join(dir, "SIDE_EFFECT.txt")); err == nil {
			t.Fatal("py_compile let the file write to disk")
		}
	})

	t.Run("an unimportable module is not a syntax error", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "np.py", "import numpy\nx = numpy\n")
		if out, err := runPython(t, s, dir, "python3 -m py_compile np.py"); err != nil {
			t.Fatalf("a runtime-only failure was reported as a compile error: %v (output %q)", err, out)
		}
	})

	t.Run("several files, the failure names the culprit", func(t *testing.T) {
		dir := t.TempDir()
		write(t, dir, "ok.py", "x = 1\n")
		write(t, dir, "broken.py", "def (((\n")
		out, err := runPython(t, s, dir, "python3 -m py_compile ok.py broken.py")
		if err == nil {
			t.Fatalf("expected a failure, got %q", out)
		}
		if !strings.Contains(out+err.Error(), `File "broken.py"`) {
			t.Errorf("the failing file is not named:\n%s", out+err.Error())
		}
	})

	t.Run("a file outside the boundary cannot be checked", func(t *testing.T) {
		dir, outside := pythonTestDir(t)
		if _, err := runPython(t, s, dir, "python3 -m py_compile "+filepath.Join(outside, "secret.txt")); err == nil {
			t.Fatal("py_compile read a file outside the boundary")
		}
	})

	t.Run("py_compile needs a file", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := runPython(t, s, dir, "python3 -m py_compile"); err == nil {
			t.Fatal("expected an error when no file is given")
		}
	})

	t.Run("other modules are still refused, and say what is served", func(t *testing.T) {
		dir := t.TempDir()
		_, err := runPython(t, s, dir, "python3 -m json.tool")
		if err == nil {
			t.Fatal("expected -m json.tool to be refused")
		}
		if !strings.Contains(err.Error(), "py_compile") {
			t.Errorf("the refusal should point at the one module that works: %v", err)
		}
	})
}
