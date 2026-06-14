package bash_sandboxed

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
)

// waitForStatus polls a background process until it reaches one of the wanted
// statuses or the deadline elapses.
func waitForStatus(t *testing.T, p *BackgroundProcess, deadline time.Duration, want ...string) string {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		st := p.Status()
		for _, w := range want {
			if st == w {
				return st
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	return p.Status()
}

func TestBackgroundExecuteAndOutput(t *testing.T) {
	s := newTestSandbox()
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("echo hello && echo world", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	if proc.ID == "" {
		t.Fatal("expected a non-empty process id")
	}

	if st := waitForStatus(t, proc, 2*time.Second, "completed", "failed"); st != "completed" {
		t.Fatalf("expected completed status, got %q", st)
	}

	res, err := s.BackgroundOutput(proc.ID, "")
	if err != nil {
		t.Fatalf("BackgroundOutput failed: %v", err)
	}
	if res.Status != "completed" {
		t.Fatalf("expected completed status, got %q", res.Status)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}
	if !strings.Contains(res.Output, "hello") || !strings.Contains(res.Output, "world") {
		t.Fatalf("expected output to contain hello and world, got %q", res.Output)
	}
}

func TestBackgroundOutputIncremental(t *testing.T) {
	s := newTestSandbox()
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("echo first; sleep 0.3; echo second", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}

	// Give the first echo time to land but not the second.
	time.Sleep(100 * time.Millisecond)
	res1, err := s.BackgroundOutput(proc.ID, "")
	if err != nil {
		t.Fatalf("BackgroundOutput failed: %v", err)
	}
	if !strings.Contains(res1.Output, "first") {
		t.Fatalf("expected first read to contain 'first', got %q", res1.Output)
	}
	if strings.Contains(res1.Output, "second") {
		t.Fatalf("did not expect 'second' yet, got %q", res1.Output)
	}

	waitForStatus(t, proc, 2*time.Second, "completed", "failed")

	res2, err := s.BackgroundOutput(proc.ID, "")
	if err != nil {
		t.Fatalf("BackgroundOutput failed: %v", err)
	}
	// Second read should only contain new output.
	if strings.Contains(res2.Output, "first") {
		t.Fatalf("second read should not repeat 'first', got %q", res2.Output)
	}
	if !strings.Contains(res2.Output, "second") {
		t.Fatalf("expected second read to contain 'second', got %q", res2.Output)
	}
}

func TestBackgroundOutputFilter(t *testing.T) {
	s := newTestSandbox()
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("echo apple; echo banana; echo apricot", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	waitForStatus(t, proc, 2*time.Second, "completed", "failed")

	res, err := s.BackgroundOutput(proc.ID, "^ap")
	if err != nil {
		t.Fatalf("BackgroundOutput failed: %v", err)
	}
	if strings.Contains(res.Output, "banana") {
		t.Fatalf("filter should have excluded banana, got %q", res.Output)
	}
	if !strings.Contains(res.Output, "apple") || !strings.Contains(res.Output, "apricot") {
		t.Fatalf("filter should have kept apple and apricot, got %q", res.Output)
	}
}

func TestBackgroundOutputInvalidFilter(t *testing.T) {
	s := newTestSandbox()
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("echo hi", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	waitForStatus(t, proc, 2*time.Second, "completed", "failed")

	if _, err := s.BackgroundOutput(proc.ID, "("); err == nil {
		t.Fatal("expected error for invalid filter regex")
	}
}

func TestBackgroundKill(t *testing.T) {
	s := newTestSandbox()
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("sleep 30", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	if proc.Status() != "running" {
		t.Fatalf("expected running status, got %q", proc.Status())
	}

	if err := s.KillBackground(proc.ID); err != nil {
		t.Fatalf("KillBackground failed: %v", err)
	}

	if st := waitForStatus(t, proc, 5*time.Second, "killed"); st != "killed" {
		t.Fatalf("expected killed status, got %q", st)
	}

	// Killing an already-exited process should error.
	if err := s.KillBackground(proc.ID); err == nil {
		t.Fatal("expected error killing already-exited process")
	}
}

func TestBackgroundValidationError(t *testing.T) {
	s := newTestSandbox()
	cwd := t.TempDir()

	// python is not in the allowlist; validation should fail synchronously.
	if _, err := s.ExecuteBackground("python evil.py", cwd, []string{cwd}, []string{cwd}); err == nil {
		t.Fatal("expected validation error for disallowed command")
	}
}

func TestBackgroundUnknownID(t *testing.T) {
	s := newTestSandbox()

	if _, err := s.BackgroundOutput("bash_999", ""); err == nil {
		t.Fatal("expected error for unknown bash_output id")
	}
	if err := s.KillBackground("bash_999"); err == nil {
		t.Fatal("expected error for unknown kill id")
	}
}

func TestListBackground(t *testing.T) {
	s := newTestSandbox()
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("echo listed", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	waitForStatus(t, proc, 2*time.Second, "completed", "failed")

	list := s.ListBackground()
	found := false
	for _, st := range list {
		if st.ID == proc.ID {
			found = true
			if st.Status != "completed" {
				t.Fatalf("expected completed status in list, got %q", st.Status)
			}
		}
	}
	if !found {
		t.Fatalf("expected process %q in list", proc.ID)
	}
}

// TestBackgroundKillReapsForkedChildren verifies that killing a background bare
// extra_commands invocation tears down the whole process group, including a
// grandchild the command forked — not just the direct process.
func TestBackgroundKillReapsForkedChildren(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process groups not supported on windows")
	}
	s := NewSandbox()
	cwd := t.TempDir()
	// "bash" as a bare extra command routes through the executeRaw path, which
	// runs the background command in its own process group.
	s.UpdateConfig(&config.Config{ExtraCommands: []string{"bash"}}, cwd)

	pidFile := filepath.Join(cwd, "child.pid")
	// Fork a long-lived grandchild, record its pid, then wait so the command
	// stays running until we kill it.
	command := "bash -c 'sleep 300 & echo $! > " + pidFile + "; wait'"
	proc, err := s.ExecuteBackground(command, cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}

	// Wait for the grandchild pid to be recorded.
	var childPid int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(pidFile); err == nil {
			if p, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && p > 0 {
				childPid = p
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if childPid == 0 {
		t.Fatal("forked child pid was never recorded")
	}
	// Sanity: the grandchild is alive (signal 0 probes existence).
	if err := syscall.Kill(childPid, 0); err != nil {
		t.Fatalf("expected forked child %d alive before kill, got %v", childPid, err)
	}

	if err := s.KillBackground(proc.ID); err != nil {
		t.Fatalf("KillBackground failed: %v", err)
	}
	waitForStatus(t, proc, 5*time.Second, "killed")

	// The grandchild must be reaped along with the group.
	reaped := false
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(childPid, 0); err != nil {
			reaped = true // ESRCH: no such process
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reaped {
		t.Fatalf("forked child %d survived the kill (process group not reaped)", childPid)
	}
}

func TestBackgroundKilledExitCode(t *testing.T) {
	s := newTestSandbox()
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("sleep 30", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	if err := s.KillBackground(proc.ID); err != nil {
		t.Fatalf("KillBackground failed: %v", err)
	}
	waitForStatus(t, proc, 5*time.Second, "killed")

	res, err := s.BackgroundOutput(proc.ID, "")
	if err != nil {
		t.Fatalf("BackgroundOutput failed: %v", err)
	}
	if res.Status != "killed" {
		t.Fatalf("expected killed status, got %q", res.Status)
	}
	// A killed process must report the SIGKILL code, never 0, so status and
	// exit code stay consistent.
	if res.ExitCode != 137 {
		t.Fatalf("expected exit code 137 for killed process, got %d", res.ExitCode)
	}
}

// TestStreamBufferLineAlignedRead verifies the filter never sees a line split
// across two reads: a partial line is held back until its newline arrives.
func TestStreamBufferLineAlignedRead(t *testing.T) {
	b := newStreamBuffer(1 << 20)

	b.Write([]byte("ERR"))
	if got := b.read(true); got != "" {
		t.Fatalf("expected empty read while line is incomplete, got %q", got)
	}
	b.Write([]byte("OR: boom\nnext"))
	if got := b.read(true); got != "ERROR: boom\n" {
		t.Fatalf("expected the completed line, got %q", got)
	}
	// "next" has no newline yet -> still held back.
	if got := b.read(true); got != "" {
		t.Fatalf("expected partial line to be held, got %q", got)
	}
	// Process done: flush everything including the unterminated tail.
	if got := b.read(false); got != "next" {
		t.Fatalf("expected final flush of partial line, got %q", got)
	}
}

func TestStreamBufferCapTruncation(t *testing.T) {
	b := newStreamBuffer(10)
	b.Write([]byte("0123456789"))
	b.Write([]byte("ABCDE")) // exceeds cap; oldest dropped

	got := b.readNew()
	if got != "56789ABCDE" {
		t.Fatalf("expected trailing 10 bytes, got %q", got)
	}
	// Subsequent read with no new writes returns empty.
	if more := b.readNew(); more != "" {
		t.Fatalf("expected empty incremental read, got %q", more)
	}
}
