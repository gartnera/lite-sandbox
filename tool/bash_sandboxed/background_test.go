package bash_sandboxed

import (
	"fmt"
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

// readOutput returns the current content of a background process's output file.
func readOutput(t *testing.T, p *BackgroundProcess) string {
	t.Helper()
	data, err := os.ReadFile(p.OutputPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	return string(data)
}

// newBackgroundTestSandbox returns a test sandbox whose background output files
// live under a per-test directory, closed (killing its processes and removing
// the output directory) when the test ends.
func newBackgroundTestSandbox(t *testing.T) *Sandbox {
	t.Helper()
	s := newTestSandbox()
	s.bg.outputRoot = filepath.Join(t.TempDir(), "bg-root")
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBackgroundExecuteAndOutput(t *testing.T) {
	s := newBackgroundTestSandbox(t)
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

	if out := readOutput(t, proc); out != "hello\nworld\n" {
		t.Fatalf("expected output file to hold hello and world, got %q", out)
	}
	list := s.ListBackground()
	if len(list) != 1 || list[0].ExitCode != 0 || list[0].OutputPath != proc.OutputPath {
		t.Fatalf("unexpected list entry: %+v", list)
	}
}

// TestBackgroundOutputStreams verifies output reaches the file while the
// process is still running, not only once it exits.
func TestBackgroundOutputStreams(t *testing.T) {
	s := newBackgroundTestSandbox(t)
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("echo first; sleep 30", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(readOutput(t, proc), "first") {
		time.Sleep(10 * time.Millisecond)
	}
	if out := readOutput(t, proc); out != "first\n" {
		t.Fatalf("expected streamed output, got %q", out)
	}
	if st := proc.Status(); st != "running" {
		t.Fatalf("expected running status, got %q", st)
	}
}

// TestBackgroundOutputStderr verifies stderr lands in the same file.
func TestBackgroundOutputStderr(t *testing.T) {
	s := newBackgroundTestSandbox(t)
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("echo oops >&2; exit 3", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	if st := waitForStatus(t, proc, 2*time.Second, "completed", "failed"); st != "failed" {
		t.Fatalf("expected failed status, got %q", st)
	}
	if out := readOutput(t, proc); out != "oops\n" {
		t.Fatalf("expected stderr in output file, got %q", out)
	}
	if list := s.ListBackground(); list[0].ExitCode != 3 {
		t.Fatalf("expected exit code 3, got %d", list[0].ExitCode)
	}
}

// TestBackgroundOutputDirRemovedOnClose verifies shutdown deletes the output
// files, and that the root is created private to the user.
func TestBackgroundOutputDirRemovedOnClose(t *testing.T) {
	s := newTestSandbox()
	root := filepath.Join(t.TempDir(), "bg-root")
	s.bg.outputRoot = root
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("echo hi", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	waitForStatus(t, proc, 2*time.Second, "completed", "failed")
	if filepath.Dir(filepath.Dir(proc.OutputPath)) != root {
		t.Fatalf("output file %q not under root %q", proc.OutputPath, root)
	}
	fi, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("expected root mode 0700, got %v", fi.Mode().Perm())
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(proc.OutputPath)); !os.IsNotExist(err) {
		t.Fatalf("expected output dir removed on Close, got %v", err)
	}
}

// TestBackgroundOutputRootRejectsSymlink verifies a root planted as a symlink
// (another user in a shared /tmp) is refused rather than followed.
func TestBackgroundOutputRootRejectsSymlink(t *testing.T) {
	s := newTestSandbox()
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(dir, "bg-root")
	if err := os.Symlink(target, root); err != nil {
		t.Fatal(err)
	}
	s.bg.outputRoot = root
	t.Cleanup(func() { s.Close() })

	if _, err := s.ExecuteBackground("echo hi", dir, []string{dir}, []string{dir}); err == nil {
		t.Fatal("expected a symlinked output root to be refused")
	}
}

// TestSweepStaleOutputDirs verifies directories of dead servers are removed
// and live ones (this process) kept.
func TestSweepStaleOutputDirs(t *testing.T) {
	root := t.TempDir()
	// A pid far above any pid_max is never running.
	stale := filepath.Join(root, "bg-2147483000-abc")
	live := filepath.Join(root, fmt.Sprintf("bg-%d-abc", os.Getpid()))
	other := filepath.Join(root, "unrelated")
	for _, d := range []string{stale, live, other} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sweepStaleOutputDirs(root)
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("expected stale dir removed, got %v", err)
	}
	for _, d := range []string{live, other} {
		if _, err := os.Stat(d); err != nil {
			t.Fatalf("expected %s kept, got %v", d, err)
		}
	}
}

func TestBackgroundKill(t *testing.T) {
	s := newBackgroundTestSandbox(t)
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
	s := newBackgroundTestSandbox(t)
	cwd := t.TempDir()

	// perl is not in the allowlist; validation should fail synchronously.
	if _, err := s.ExecuteBackground("perl evil.py", cwd, []string{cwd}, []string{cwd}); err == nil {
		t.Fatal("expected validation error for disallowed command")
	}
}

func TestBackgroundUnknownID(t *testing.T) {
	s := newTestSandbox()

	if err := s.KillBackground("bash_999"); err == nil {
		t.Fatal("expected error for unknown kill id")
	}
}

func TestListBackground(t *testing.T) {
	s := newBackgroundTestSandbox(t)
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
	s.updateConfig(&config.Config{ExtraCommands: []string{"bash"}}, cwd)

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

// TestCloseShutsDownBackgroundProcesses verifies that closing the sandbox (as
// happens when the top-level MCP server shuts down) tears down a running
// background process and its forked grandchild, and blocks until the teardown
// has actually completed rather than returning while the process is still alive.
func TestCloseShutsDownBackgroundProcesses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process groups not supported on windows")
	}
	s := NewSandbox()
	cwd := t.TempDir()
	s.updateConfig(&config.Config{ExtraCommands: []string{"bash"}}, cwd)

	pidFile := filepath.Join(cwd, "child.pid")
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
	if err := syscall.Kill(childPid, 0); err != nil {
		t.Fatalf("expected forked child %d alive before close, got %v", childPid, err)
	}

	// Close must block until the runner goroutine has finished its teardown, so
	// bound it well under how long the child would otherwise sleep (300s).
	closed := make(chan error, 1)
	go func() { closed <- s.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close returned error: %v", err)
		}
	case <-time.After(shutdownGracePeriod + 3*time.Second):
		t.Fatal("Close did not return within the shutdown grace period")
	}

	// Once Close has returned, the background process is recorded as killed.
	if st := proc.Status(); st != "killed" {
		t.Fatalf("expected killed status after Close, got %q", st)
	}

	// The forked grandchild must be torn down along with the group (rather than
	// left orphaned running its 300s sleep). Poll for reaping, since the process
	// dying and being reaped by init lags slightly behind Close returning.
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
		t.Fatalf("forked child %d survived Close (process group not reaped)", childPid)
	}
}

// TestBackgroundKillIsGraceful verifies kill sends SIGTERM first, giving the
// process a chance to clean up, before escalating to SIGKILL. A command that
// traps SIGTERM and writes a marker proves the signal was delivered (an
// immediate SIGKILL could not be trapped, so no marker would appear).
func TestBackgroundKillIsGraceful(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("signals not supported on windows")
	}
	s := NewSandbox()
	cwd := t.TempDir()
	s.updateConfig(&config.Config{ExtraCommands: []string{"bash"}}, cwd)

	marker := filepath.Join(cwd, "termed")
	ready := filepath.Join(cwd, "ready")
	command := "bash -c 'trap \"echo yes > " + marker + "; exit 0\" TERM; touch " + ready + "; while true; do sleep 0.05; done'"
	proc, err := s.ExecuteBackground(command, cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}

	// Wait until the trap is installed before killing.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	if err := s.KillBackground(proc.ID); err != nil {
		t.Fatalf("KillBackground failed: %v", err)
	}
	waitForStatus(t, proc, 5*time.Second, "killed")

	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("expected SIGTERM handler to run (marker file), got %v", err)
	}
}

func TestBackgroundKilledExitCode(t *testing.T) {
	s := newBackgroundTestSandbox(t)
	cwd := t.TempDir()

	proc, err := s.ExecuteBackground("sleep 30", cwd, []string{cwd}, []string{cwd})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	if err := s.KillBackground(proc.ID); err != nil {
		t.Fatalf("KillBackground failed: %v", err)
	}
	waitForStatus(t, proc, 5*time.Second, "killed")

	res := s.ListBackground()[0]
	if res.Status != "killed" {
		t.Fatalf("expected killed status, got %q", res.Status)
	}
	// A killed process must report the SIGKILL code, never 0, so status and
	// exit code stay consistent.
	if res.ExitCode != 137 {
		t.Fatalf("expected exit code 137 for killed process, got %d", res.ExitCode)
	}
}

// TestOutputFileCapCompaction verifies that exceeding the cap keeps the most
// recent output behind a truncation marker.
func TestOutputFileCapCompaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "out.log")
	o, err := createOutputFile(path, 20)
	if err != nil {
		t.Fatal(err)
	}
	o.Write([]byte("0123456789"))
	o.Write([]byte("ABCDEFGHIJ")) // exactly at the cap: no compaction
	o.Write([]byte("xyz"))        // exceeds it: keep the last 10 bytes
	got, _ := os.ReadFile(path)
	if want := outputTruncatedMarker + "DEFGHIJxyz"; string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// A single write larger than half the cap keeps its own tail.
	o.Write([]byte("abcdefghijklmnopqrstuvwxyz"))
	got, _ = os.ReadFile(path)
	if want := outputTruncatedMarker + "qrstuvwxyz"; string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}

	// Writes after Close are dropped, not errors.
	o.Close()
	if n, err := o.Write([]byte("late")); err != nil || n != 4 {
		t.Fatalf("write after close: n=%d err=%v", n, err)
	}
}
