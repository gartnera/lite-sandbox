package os_sandbox

import (
	"bufio"
	"bytes"
	"context"
	"encoding/gob"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startBareWorker starts the sandbox-worker subprocess directly (no bwrap) and
// wires a *Worker around it, exactly as StartWorker does after the sandbox cmd
// is running. This exercises the real host-side Worker API (Exec, cancellation,
// the dispatcher, Close) without needing bwrap, which is unavailable on some
// platforms/CI legs.
func startBareWorker(t *testing.T) *Worker {
	t.Helper()
	binary := "../lite-sandbox"
	if _, err := os.Stat(binary); err != nil {
		t.Skipf("lite-sandbox binary not found at %s (run 'go build -o lite-sandbox')", binary)
	}

	cmd := exec.Command(binary, "sandbox-worker")
	cmd.Stderr = os.Stderr
	// Mirror StartWorker: the worker leads its own group so Close can reap it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start worker: %v", err)
	}

	w := &Worker{
		cmd:     cmd,
		stdin:   stdin,
		stdout:  stdout,
		enc:     newHostLockedEncoder(stdin),
		dec:     gob.NewDecoder(bufio.NewReader(stdout)),
		pending: make(map[uint64]chan WorkerMsg),
	}

	var ready WorkerMsg
	if err := w.dec.Decode(&ready); err != nil {
		t.Fatalf("read ready signal: %v", err)
	}
	if ready.Type != WorkerMsgReady {
		t.Fatalf("expected ready signal, got type %d", ready.Type)
	}
	go w.runDispatcher()
	t.Cleanup(func() { w.Close() })
	return w
}

// execResult is the outcome of a Worker.Exec call run in a goroutine.
type execResult struct {
	exitCode int
	err      error
}

// runExecAsync runs w.Exec in a goroutine and returns a channel for its result
// plus the buffer capturing combined stdout/stderr.
func runExecAsync(w *Worker, ctx context.Context, args []string, dir string) (<-chan execResult, *bytes.Buffer) {
	var buf bytes.Buffer
	ch := make(chan execResult, 1)
	go func() {
		code, err := w.Exec(ctx, args, dir, nil, nil, &buf, &buf)
		ch <- execResult{code, err}
	}()
	return ch, &buf
}

func TestWorkerExecBasic(t *testing.T) {
	w := startBareWorker(t)
	ch, buf := runExecAsync(w, context.Background(), []string{"echo", "hi"}, t.TempDir())
	select {
	case r := <-ch:
		if r.err != nil || r.exitCode != 0 {
			t.Fatalf("expected clean exit, got code=%d err=%v", r.exitCode, r.err)
		}
		if got := buf.String(); got != "hi\n" {
			t.Fatalf("unexpected output %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Exec did not return")
	}
}

// TestWorkerExecCancel verifies that cancelling the context stops a running
// worker command (round-tripping HostMsgCancel to the worker, which kills it).
func TestWorkerExecCancel(t *testing.T) {
	w := startBareWorker(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := runExecAsync(w, ctx, []string{"sleep", "60"}, t.TempDir())

	time.Sleep(300 * time.Millisecond) // let the command get going
	start := time.Now()
	cancel()

	select {
	case r := <-ch:
		if r.exitCode == 0 && r.err == nil {
			t.Fatalf("expected non-zero/err for cancelled command, got code=%d err=%v", r.exitCode, r.err)
		}
		if elapsed := time.Since(start); elapsed > gracefulKillTimeout+5*time.Second {
			t.Fatalf("Exec took too long to return after cancel: %v", elapsed)
		}
	case <-time.After(gracefulKillTimeout + 8*time.Second):
		t.Fatal("Exec did not return after cancel")
	}
}

// TestWorkerExecCancelGraceful verifies cancellation sends SIGTERM first: a
// command that traps SIGTERM gets to run its handler before being killed.
func TestWorkerExecCancelGraceful(t *testing.T) {
	w := startBareWorker(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "termed")
	ready := filepath.Join(dir, "ready")
	script := "trap 'echo yes > " + marker + "; exit 0' TERM; touch " + ready +
		"; while true; do sleep 0.05; done"

	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := runExecAsync(w, ctx, []string{"bash", "-c", script}, dir)

	waitForFile(t, ready, 5*time.Second)
	cancel()

	select {
	case <-ch:
	case <-time.After(gracefulKillTimeout + 8*time.Second):
		t.Fatal("Exec did not return after cancel")
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("expected SIGTERM trap to run (marker missing): %v", err)
	}
}

// TestWorkerExecCancelReapsForkedChild verifies that cancelling a worker command
// tears down its whole process group, including a child it forked.
func TestWorkerExecCancelReapsForkedChild(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("worker process-group reaping is linux-only (macOS sandbox signal confinement)")
	}
	w := startBareWorker(t)
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	script := "sleep 300 & echo $! > " + pidFile + "; wait"

	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := runExecAsync(w, ctx, []string{"bash", "-c", script}, dir)

	childPid := readPidFile(t, pidFile, 5*time.Second)
	cancel()
	select {
	case <-ch:
	case <-time.After(gracefulKillTimeout + 8*time.Second):
		t.Fatal("Exec did not return after cancel")
	}
	assertReaped(t, childPid, 5*time.Second)
}

// TestProcRegistryKillReapsGroup unit-tests the registry's graceful group kill
// directly, without the worker binary (only needs bash).
func TestProcRegistryKillReapsGroup(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("process-group reaping is linux-only here")
	}
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "child.pid")
	cmd := exec.Command("bash", "-c", "sleep 300 & echo $! > "+pidFile+"; wait")
	setProcGroup(cmd)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	reg := newProcRegistry()
	reg.add(1, cmd)
	// Mirror streamCommand: deregister once the process exits.
	go func() {
		_ = cmd.Wait()
		reg.remove(1)
	}()

	childPid := readPidFile(t, pidFile, 5*time.Second)
	reg.kill(1)
	assertReaped(t, childPid, 5*time.Second)
}

// TestProcRegistryKillUnknownID ensures killing an unregistered id is a no-op.
func TestProcRegistryKillUnknownID(t *testing.T) {
	reg := newProcRegistry()
	reg.kill(999) // must not panic
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("file %s never appeared", path)
}

func readPidFile(t *testing.T, path string, timeout time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			if p, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && p > 0 {
				return p
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("pid file %s never populated", path)
	return 0
}

func assertReaped(t *testing.T, pid int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			return // ESRCH: gone
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("process %d was not reaped within %v", pid, timeout)
}
