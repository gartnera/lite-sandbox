package bash_sandboxed

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestPythonWorkingDirectory covers the program seeing the shell's working
// directory as its own: os.getcwd(), relative paths, and os.chdir(), whose
// target answers to the same boundary as any other path question.
func TestPythonWorkingDirectory(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir, outside := pythonTestDir(t)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "f.txt"), []byte("in sub"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("getcwd is the shell's directory", func(t *testing.T) {
		out, err := runPython(t, s, dir, `python3 -c "import os; print(os.getcwd())"`)
		if err != nil {
			t.Fatalf("%v (output %q)", err, out)
		}
		if out != dir+"\n" {
			t.Fatalf("got %q, want %q", out, dir+"\n")
		}
	})

	t.Run("cd before python moves it", func(t *testing.T) {
		out, err := runPython(t, s, dir, `cd sub && python3 -c "import os; print(os.getcwd(), open('f.txt').read())"`)
		if err != nil {
			t.Fatalf("%v (output %q)", err, out)
		}
		if want := filepath.Join(dir, "sub") + " in sub\n"; out != want {
			t.Fatalf("got %q, want %q", out, want)
		}
	})

	t.Run("chdir inside the boundary", func(t *testing.T) {
		out, err := runPython(t, s, dir, `python3 -c "import os; os.chdir('sub'); print(open('f.txt').read())"`)
		if err != nil {
			t.Fatalf("%v (output %q)", err, out)
		}
		if out != "in sub\n" {
			t.Fatalf("got %q", out)
		}
	})

	t.Run("chdir onto a file is NotADirectoryError", func(t *testing.T) {
		out, err := runPython(t, s, dir, `python3 -c "
import os
try:
    os.chdir('in.txt')
except NotADirectoryError:
    print('not a dir')"`)
		if err != nil {
			t.Fatalf("%v (output %q)", err, out)
		}
		if out != "not a dir\n" {
			t.Fatalf("got %q", out)
		}
	})

	t.Run("chdir outside the boundary is denied", func(t *testing.T) {
		out, err := runPython(t, s, dir, `python3 -c "import os; os.chdir('`+outside+`')"`)
		if err == nil || !strings.Contains(err.Error()+out, "outside allowed directories") {
			t.Fatalf("expected a boundary denial, got %v (output %q)", err, out)
		}
	})
}

// TestPythonStderr covers print(file=sys.stderr) reaching the command's stderr
// rather than its stdout.
func TestPythonStderr(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()
	prog := `python3 -c "import sys; print('out'); print('err', file=sys.stderr)"`

	out, err := runPython(t, s, dir, prog+" 2>/dev/null")
	if err != nil {
		t.Fatalf("%v (output %q)", err, out)
	}
	if out != "out\n" {
		t.Fatalf("with stderr discarded got %q, want only stdout", out)
	}
	out, err = runPython(t, s, dir, prog+" 2>&1 >/dev/null")
	if err != nil {
		t.Fatalf("%v (output %q)", err, out)
	}
	if out != "err\n" {
		t.Fatalf("with stdout discarded got %q, want only stderr", out)
	}
}

// TestPythonStatResult covers Path.stat() answering with a real
// os.stat_result, whose fields read as attributes.
func TestPythonStatResult(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir, _ := pythonTestDir(t)
	// st_mode >> 12 is the file type: 0o10 a regular file, 0o4 a directory.
	out, err := runPython(t, s, dir, `python3 -c "
import os
from pathlib import Path
st = Path('in.txt').stat()
print(st.st_size, st.st_mode >> 12 == 0o10, os.stat('.').st_mode >> 12 == 0o4)"`)
	if err != nil {
		t.Fatalf("%v (output %q)", err, out)
	}
	if out != "11 True True\n" {
		t.Fatalf("got %q", out)
	}
}

// TestPythonClockAndZone covers the program reading the real clock in the
// host's local zone, not monty's default of UTC.
func TestPythonClockAndZone(t *testing.T) {
	t.Setenv("TZ", "Asia/Tokyo") // no DST, so the expectations are fixed
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()
	out, err := runPython(t, s, dir, `python3 -c "
import time
from datetime import datetime
print(time.strftime('%Z'), time.timezone, int(time.time()), datetime.now().utcoffset() is None)"`)
	if err != nil {
		t.Fatalf("%v (output %q)", err, out)
	}
	fields := strings.Fields(out)
	if len(fields) != 4 || fields[0] != "JST" || fields[1] != "-32400" || fields[3] != "True" {
		t.Fatalf("got %q, want JST -32400 <now> True", out)
	}
	now := time.Now().Unix()
	if got, err := strconv.ParseInt(fields[2], 10, 64); err != nil || got < now-60 || got > now+60 {
		t.Fatalf("time.time() = %s, want about %d", fields[2], now)
	}
}

func TestHostTimeZoneName(t *testing.T) {
	for _, tc := range []struct{ tz, want string }{
		{"Europe/London", "Europe/London"},
		{":America/New_York", "America/New_York"},
		{"UTC", "UTC"},
		{"EST5EDT,M3.2.0,M11.1.0", ""}, // a POSIX rule, not a zone name
		{"/etc/passwd", ""},
		{"Not/AZone", ""},
	} {
		t.Setenv("TZ", tc.tz)
		if got := hostTimeZoneName(); got != tc.want {
			t.Errorf("TZ=%q: got %q, want %q", tc.tz, got, tc.want)
		}
	}
}

// TestPythonSleepAndRandom covers the calls the OS policy serves: sleeps that
// really wait, random state from real entropy, and os.urandom.
func TestPythonSleepAndRandom(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()

	start := time.Now()
	out, err := runPython(t, s, dir, `python3 -c "import time; time.sleep(0.2); print('woke')"`)
	if err != nil {
		t.Fatalf("%v (output %q)", err, out)
	}
	if elapsed := time.Since(start); elapsed < 200*time.Millisecond || out != "woke\n" {
		t.Fatalf("sleep took %v, output %q", elapsed, out)
	}

	draw := `python3 -c "import random; print(random.getrandbits(64))"`
	a, err := runPython(t, s, dir, draw)
	if err != nil {
		t.Fatalf("%v (output %q)", err, a)
	}
	b, err := runPython(t, s, dir, draw)
	if err != nil {
		t.Fatalf("%v (output %q)", err, b)
	}
	if a == b {
		t.Fatalf("two runs drew the same random bits %q", a)
	}

	out, err = runPython(t, s, dir, `python3 -c "import os; print(len(os.urandom(16)), type(os.urandom(1)).__name__)"`)
	if err != nil {
		t.Fatalf("%v (output %q)", err, out)
	}
	if out != "16 bytes\n" {
		t.Fatalf("got %q", out)
	}

	// Under the heap limit (past it, monty raises MemoryError before asking)
	// but over the sandbox's own cap on one call.
	out, err = runPython(t, s, dir, `python3 -c "
import os
try:
    os.urandom(64 << 20)
except ValueError as e:
    print('refused')"`)
	if err != nil {
		t.Fatalf("%v (output %q)", err, out)
	}
	if out != "refused\n" {
		t.Fatalf("got %q", out)
	}
}

// TestPythonV1Language spot-checks language and stdlib surface that arrived
// with monty v1, so a regression in the embedded interpreter shows up here.
func TestPythonV1Language(t *testing.T) {
	s := newTestSandbox()
	defer s.Close()
	dir := t.TempDir()
	out, err := runPython(t, s, dir, `python3 - <<'PY'
import copy, itertools
z = complex(1, 2) * 1j
exec("y = 21")
print(z, eval("y * 2"), copy.deepcopy([[1]]), list(itertools.pairwise("abc")), "%05.1f" % 3.14159)
PY`)
	if err != nil {
		t.Fatalf("%v (output %q)", err, out)
	}
	if want := "(-2+1j) 42 [[1]] [('a', 'b'), ('b', 'c')] 003.1\n"; out != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}
