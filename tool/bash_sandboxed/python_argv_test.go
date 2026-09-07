package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPythonArgv covers the end-to-end behaviour agents actually depend on:
// arguments reaching the program under every way of invoking it.
func TestPythonArgv(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "show.py"),
		[]byte("import sys\nprint(sys.argv)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "script with arguments",
			command: "python3 show.py --flag input.csv",
			want:    "['show.py', '--flag', 'input.csv']\n",
		},
		{
			name:    "script with no arguments still has argv[0]",
			command: "python3 show.py",
			want:    "['show.py']\n",
		},
		{
			name:    "inline code, semicolon form",
			command: `python3 -c "import sys; print(sys.argv)" a b`,
			want:    "['-c', 'a', 'b']\n",
		},
		{
			name:    "inline code, newline form",
			command: "python3 -c \"import sys\nprint(sys.argv)\" x",
			want:    "['-c', 'x']\n",
		},
		{
			name:    "from sys import argv",
			command: "python3 -c \"from sys import argv\nprint(argv)\" y",
			want:    "['-c', 'y']\n",
		},
		{
			name:    "from sys import argv as alias",
			command: "python3 -c \"from sys import argv as a\nprint(a)\" y",
			want:    "['-c', 'y']\n",
		},
		{
			name:    "import sys as alias",
			command: "python3 -c \"import sys as s\nprint(s.argv)\" z",
			want:    "['-c', 'z']\n",
		},
		{
			name:    "import inside a function",
			command: "python3 -c \"def f():\n    import sys\n    return sys.argv\nprint(f())\" q",
			want:    "['-c', 'q']\n",
		},
		{
			name:    "import with a trailing comment",
			command: "python3 -c \"import sys  # needed for argv\nprint(sys.argv)\" c",
			want:    "['-c', 'c']\n",
		},
		{
			name: "stdin program",
			command: `echo "import sys
print(sys.argv)" | python3 -`,
			want: "['-']\n",
		},
		{
			name:    "arguments that look like python flags are the program's",
			command: `python3 show.py -c -m --version`,
			want:    "['show.py', '-c', '-m', '--version']\n",
		},
		{
			name:    "shimming sys does not cost the rest of the module",
			command: `python3 -c "import sys; print(sys.argv); print(sys.platform); print(sys.version_info.major)"`,
			want:    "['-c']\nmonty\n3\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := runPython(t, s, dir, tt.command)
			if err != nil {
				t.Fatalf("unexpected error: %v (output %q)", err, out)
			}
			if out != tt.want {
				t.Fatalf("got %q, want %q", out, tt.want)
			}
		})
	}
}

// TestPythonArgvQuoting checks that an argument cannot break out of the
// generated list literal and become code. This is the one place argv values
// are interpolated into a program, so it is the one place injection could hide.
func TestPythonArgvQuoting(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "echo.py"),
		[]byte("import sys\nfor a in sys.argv[1:]:\n    print(a)\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	hostile := []string{
		`"]; print("pwned"); x = ["`,
		`'; print('pwned'); y = '`,
		`back\slash`,
		`quote" and 'single`,
		"tab\there",
		"unicode: héllo → 世界",
	}
	for _, arg := range hostile {
		t.Run(arg, func(t *testing.T) {
			// Single-quote the argument for the shell so the sandbox passes it
			// through to python verbatim; the payloads contain no single quotes
			// except the ones handled below.
			shellArg := "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
			out, err := runPython(t, s, dir, "python3 echo.py "+shellArg)
			if err != nil {
				t.Fatalf("unexpected error: %v (output %q)", err, out)
			}
			// Exact equality is the proof: the program echoes each argument
			// on its own line, so had any of these escaped the literal and
			// run as code, the output would carry its side effects too.
			if out != arg+"\n" {
				t.Fatalf("argument escaped the literal or was mangled: got %q, want %q", out, arg+"\n")
			}
		})
	}
}

// TestPythonArgvLeavesProgramTextAlone is the safety property of the rewrite:
// it must only ever touch real statements, never the contents of a string.
func TestPythonArgvLeavesProgramTextAlone(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	tests := []struct {
		name    string
		program string
		want    string
	}{
		{
			name:    "import sys inside a docstring",
			program: "import sys\ndoc = \"\"\"\nimport sys\n\"\"\"\nprint(repr(doc))",
			want:    "'\\nimport sys\\n'\n",
		},
		{
			name:    "a semicolon inside a string is not a statement separator",
			program: "import sys\nprint('a; import sys')",
			want:    "a; import sys\n",
		},
		{
			name:    "import sys inside a single-quoted string",
			program: "import sys\nprint('import sys')",
			want:    "import sys\n",
		},
		{
			name:    "the word argv in a comment does not change the program",
			program: "# argv\nprint('ok')",
			want:    "ok\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, "p.py")
			if err := os.WriteFile(path, []byte(tt.program+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := runPython(t, s, dir, "python3 p.py arg")
			if err != nil {
				t.Fatalf("unexpected error: %v (output %q)", err, out)
			}
			if out != tt.want {
				t.Fatalf("got %q, want %q", out, tt.want)
			}
		})
	}
}

// TestPythonArgvTracebackLineNumbers checks the prologue stays invisible: an
// error must be reported at the line the agent wrote, not shifted by however
// many lines the shim added.
func TestPythonArgvTracebackLineNumbers(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	// The failing statement is on line 4, after an argv reference that forces
	// the prologue in.
	program := "import sys\nx = 1\ny = 2\nraise ValueError(sys.argv[0])\n"
	if err := os.WriteFile(filepath.Join(dir, "boom.py"), []byte(program), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := runPython(t, s, dir, "python3 boom.py")
	if err == nil {
		t.Fatal("expected the program to fail")
	}
	combined := out + err.Error()
	if !strings.Contains(combined, "line 4") {
		t.Errorf("expected the error on line 4 (the agent's numbering):\n%s", combined)
	}
	if !strings.Contains(combined, `File "boom.py"`) {
		t.Errorf("traceback does not name the script:\n%s", combined)
	}
	if strings.Contains(combined, "_lite_sandbox") {
		t.Errorf("the shim leaked into the traceback:\n%s", combined)
	}
}

// TestApplySysShimIsOptIn checks a program that never mentions argv or stdin is
// handed to monty exactly as written — no prologue, no rewrite, no line shift.
func TestApplySysShimIsOptIn(t *testing.T) {
	code := "import sys\nprint(sys.version)\n"
	got, offset, inputs := applySysShim(code, []string{"x.py"})
	if got != code {
		t.Errorf("program without argv was modified:\n%q", got)
	}
	if offset != 0 {
		t.Errorf("offset = %d, want 0", offset)
	}
	if len(inputs) != 0 {
		t.Errorf("a program without the shim should need no inputs, got %v", inputs)
	}

	withArgv := "import sys\nprint(sys.argv)\n"
	got, offset, inputs = applySysShim(withArgv, []string{"x.py"})
	if offset == 0 {
		t.Error("expected a non-zero line offset once the prologue is added")
	}
	if _, ok := inputs[pythonStdinInput]; !ok {
		t.Errorf("the prologue binds sys.stdin, so the handle must be an input; got %v", inputs)
	}
	if strings.Count(got, "\n") != strings.Count(withArgv, "\n")+offset {
		t.Errorf("the rewrite changed the program's line count, so tracebacks will be wrong:\n%q", got)
	}
	if !strings.Contains(got, "import sys; sys = "+pythonShimName+"()") {
		t.Errorf("the import was not rewritten to re-apply the shim:\n%q", got)
	}
}

func TestRewriteSysBindings(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"plain import", "import sys", "import sys; sys = " + pythonShimName + "()"},
		{"indented import", "    import sys", "    import sys; sys = " + pythonShimName + "()"},
		{"aliased import", "import sys as s", "import sys as s; s = " + pythonShimName + "()"},
		{"from import", "from sys import argv", "argv = " + pythonShimName + ".argv"},
		{"from import aliased", "from sys import argv as a", "a = " + pythonShimName + ".argv"},
		{"trailing comment", "import sys  # why", "import sys; sys = " + pythonShimName + "()  # why"},
		{"semicolon statement", "import sys; print(1)", "import sys; sys = " + pythonShimName + "(); print(1)"},
		{"not a whole statement", "x = 'import sys'", "x = 'import sys'"},
		{"different module", "import os", "import os"},
		{"submodule import untouched", "import sys.path", "import sys.path"},
		{"from import of something else", "from sys import version", "from sys import version"},
		{"inside a docstring", "d = \"\"\"\nimport sys\n\"\"\"", "d = \"\"\"\nimport sys\n\"\"\""},
		{"inside a comment", "# import sys", "# import sys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rewriteSysBindings(tt.in); got != tt.want {
				t.Errorf("rewriteSysBindings(%q)\n got %q\nwant %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestPythonStringLiteral(t *testing.T) {
	tests := []struct{ in, want string }{
		{`plain`, `"plain"`},
		{`with "quotes"`, `"with \"quotes\""`},
		{`back\slash`, `"back\\slash"`},
		{"tab\tand\nnewline", `"tab\tand\nnewline"`},
		{"\x00\x1f", `"\x00\x1f"`},
		{"héllo → 世界", `"héllo → 世界"`},
		{`"]; print("x"); z = ["`, `"\"]; print(\"x\"); z = [\""`},
	}
	for _, tt := range tests {
		if got := pythonStringLiteral(tt.in); got != tt.want {
			t.Errorf("pythonStringLiteral(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestShiftTracebackLines(t *testing.T) {
	in := `Traceback (most recent call last):
  File "script.py", line 12, in <module>
    raise ValueError('x')
ValueError: x`
	got := shiftTracebackLines(in, 9)
	if !strings.Contains(got, "line 3,") {
		t.Errorf("expected line 12 to become line 3:\n%s", got)
	}
	// A frame inside the prologue has no user line to point at and is left be.
	if got := shiftTracebackLines(`File "script.py", line 2, in <module>`, 9); !strings.Contains(got, "line 2") {
		t.Errorf("a prologue frame should be left alone, got %q", got)
	}
	// No offset, no change.
	if got := shiftTracebackLines(in, 0); got != in {
		t.Errorf("offset 0 changed the traceback")
	}
}

// TestPythonArgvUnderBoundary checks the shim does not become a way around the
// path boundary: argv is just data, and a path arriving through it is checked
// like any other.
func TestPythonArgvUnderBoundary(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()

	dir, outside := pythonTestDir(t)
	if err := os.WriteFile(filepath.Join(dir, "read.py"),
		[]byte("import sys\nfrom pathlib import Path\nprint(Path(sys.argv[1]).read_text())\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := s.Execute(context.Background(), "python3 read.py in.txt", dir, []string{dir}, []string{dir})
	if err != nil {
		t.Fatalf("reading an in-boundary path via argv failed: %v (output %q)", err, out)
	}
	if out != "hello world\n" {
		t.Fatalf("got %q", out)
	}

	secret := filepath.Join(outside, "secret.txt")
	out, err = s.Execute(context.Background(), "python3 read.py "+secret, dir, []string{dir}, []string{dir})
	if err == nil {
		t.Fatalf("a path passed through argv escaped the boundary: %q", out)
	}
	if strings.Contains(out+err.Error(), "TOPSECRET") {
		t.Fatalf("argv leaked protected content: %q / %v", out, err)
	}
}

// TestRewriteImportForms covers the import shapes that bind the real sys
// module. The multi-module form is the one an agent's one-liner reaches for
// (`import sys, json`), and missing it meant the shim silently did not apply.
func TestRewriteImportForms(t *testing.T) {
	shim := pythonShimName
	tests := []struct{ name, in, want string }{
		{"plain", "import sys", "import sys; sys = " + shim + "()"},
		{"aliased", "import sys as system", "import sys as system; system = " + shim + "()"},
		{"sys first", "import sys, json", "import sys, json; sys = " + shim + "()"},
		{"sys last", "import json, sys", "import json, sys; sys = " + shim + "()"},
		{"sys middle aliased", "import json, sys as s, re", "import json, sys as s, re; s = " + shim + "()"},
		{"indented", "    import sys", "    import sys; sys = " + shim + "()"},
		{"trailing space kept", "import sys  ", "import sys; sys = " + shim + "()  "},
		// A module that merely starts with the same letters binds nothing the
		// shim owns, so it must be left exactly as written.
		{"syslog untouched", "import syslog", "import syslog"},
		{"submodule untouched", "import os.path", "import os.path"},
		{"no import", "print(sys.argv)", "print(sys.argv)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rewriteStatement(tt.in); got != tt.want {
				t.Errorf("rewriteStatement(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestRewriteFromSysImport covers the from-import forms for both shimmed
// attributes. The real sys has neither, so these become assignments rather
// than imports that would raise ImportError.
func TestRewriteFromSysImport(t *testing.T) {
	shim := pythonShimName
	tests := []struct{ in, want string }{
		{"from sys import argv", "argv = " + shim + ".argv"},
		{"from sys import stdin", "stdin = " + shim + ".stdin"},
		{"from sys import argv as a", "a = " + shim + ".argv"},
		{"from sys import stdin as inp", "inp = " + shim + ".stdin"},
	}
	for _, tt := range tests {
		if got := rewriteStatement(tt.in); got != tt.want {
			t.Errorf("rewriteStatement(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
