package bash_sandboxed

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// newTestSession starts a session in a fresh directory, which is also its
// whole read and write boundary, capturing the commands' output.
func newTestSession(t *testing.T, s *Sandbox) (*Session, string, *bytes.Buffer) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	sess, err := s.NewSession(dir, []string{dir}, []string{dir}, nil, &out, &out)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return sess, dir, &out
}

// runInSession runs command in sess, failing the test on an error, and returns what it
// printed and its status.
func runInSession(t *testing.T, sess *Session, out *bytes.Buffer, command string) (string, int) {
	t.Helper()
	out.Reset()
	status, exited, err := sess.Run(context.Background(), command)
	if err != nil {
		t.Fatalf("%q: %v", command, err)
	}
	if exited {
		t.Fatalf("%q: exited the shell", command)
	}
	return out.String(), status
}

func TestSessionKeepsShellState(t *testing.T) {
	sess, dir, out := newTestSession(t, newTestSandbox())
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	steps := []struct {
		command, want string
		status        int
	}{
		{"x=hello", "", 0},
		{`echo "$x"`, "hello\n", 0},
		{`greet() { echo "hi $1"; }`, "", 0},
		// A function an earlier command defined passes static validation.
		{"greet there", "hi there\n", 0},
		{"export Y=7", "", 0},
		{"printenv Y", "7\n", 0},
		{"false", "", 1},
		{`echo "status $?"`, "status 1\n", 0},
		{"cd sub && pwd", filepath.Join(dir, "sub") + "\n", 0},
		{"pwd", filepath.Join(dir, "sub") + "\n", 0},
		{"cd ..", "", 0},
	}
	for _, step := range steps {
		got, status := runInSession(t, sess, out, step.command)
		if got != step.want || status != step.status {
			t.Errorf("%q: got %q (status %d), want %q (status %d)", step.command, got, status, step.want, step.status)
		}
	}
	if sess.Dir() != dir {
		t.Errorf("Dir() = %q, want %q", sess.Dir(), dir)
	}
	if !slices.Contains(sess.Functions(), "greet") {
		t.Errorf("Functions() = %v, want greet among them", sess.Functions())
	}
}

func TestSessionExit(t *testing.T) {
	sess, _, _ := newTestSession(t, newTestSandbox())
	status, exited, err := sess.Run(context.Background(), "echo bye; exit 3; echo never")
	if err != nil || !exited || status != 3 {
		t.Fatalf("exit 3: status %d, exited %v, err %v; want 3, true, nil", status, exited, err)
	}
}

func TestSessionRefusalEndsOnlyTheLine(t *testing.T) {
	sess, dir, out := newTestSession(t, newTestSandbox())

	// Static: nothing of the line runs.
	out.Reset()
	status, exited, err := sess.Run(context.Background(), "echo before; cat /etc/passwd")
	if err == nil || exited || status == 0 {
		t.Fatalf("static refusal: status %d, exited %v, err %v", status, exited, err)
	}
	if out.Len() != 0 {
		t.Errorf("static refusal ran part of the line: %q", out.String())
	}

	// Runtime: the interpreter stops the line, but not the shell.
	out.Reset()
	status, exited, err = sess.Run(context.Background(), `d=/etc; cat "$d/passwd"; echo after`)
	if err == nil || exited || status == 0 {
		t.Fatalf("runtime refusal: status %d, exited %v, err %v", status, exited, err)
	}
	if strings.Contains(out.String(), "after") {
		t.Errorf("runtime refusal ran the rest of the line: %q", out.String())
	}

	if got, _ := runInSession(t, sess, out, "echo still here"); got != "still here\n" {
		t.Errorf("after refusals: got %q", got)
	}
	if sess.Dir() != dir {
		t.Errorf("Dir() = %q, want %q", sess.Dir(), dir)
	}
}

func TestSessionCdStaysInBoundary(t *testing.T) {
	// A home outside the boundary; the interpreter reads HOME when it starts.
	t.Setenv("HOME", t.TempDir())
	sess, dir, _ := newTestSession(t, newTestSandbox())

	for _, command := range []string{"cd /etc", "cd ..", "cd", "cd ~"} {
		if _, _, err := sess.Run(context.Background(), command); err == nil {
			t.Errorf("%q: want a boundary error", command)
		}
		if sess.Dir() != dir {
			t.Fatalf("%q moved the session to %q", command, sess.Dir())
		}
	}
}

func TestSessionInterrupt(t *testing.T) {
	sess, _, _ := newTestSession(t, newTestSandbox())
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	status, exited, _ := sess.Run(ctx, "sleep 30")
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("cancelled command took %v", elapsed)
	}
	if exited || status != 130 {
		t.Errorf("cancelled command: status %d, exited %v; want 130, false", status, exited)
	}
}

func TestCommandNames(t *testing.T) {
	names := newTestSandbox().CommandNames()
	for _, want := range []string{"ls", "cd", "grep"} {
		if !slices.Contains(names, want) {
			t.Errorf("CommandNames() lacks %q", want)
		}
	}
	if slices.Contains(names, "eval") {
		t.Error("CommandNames() offers eval, which is not allowed")
	}
	if !slices.IsSorted(names) {
		t.Error("CommandNames() is not sorted")
	}
}

// A bare cd names no path, but goes to $HOME: outside the boundary, it is
// refused like cd to that directory by name.
func TestExecuteBareCdOutsideBoundary(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	out, err := newTestSandbox().Execute(context.Background(), "cd; ls", dir, []string{dir}, []string{dir})
	if err == nil {
		t.Fatalf("bare cd out of the boundary ran: %q", out)
	}
}
