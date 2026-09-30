package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
)

// newOSSandboxForTest returns a Sandbox with the real OS sandbox (bwrap on
// Linux, sandbox-exec on macOS) enabled for workDir. Requires the platform
// sandbox to be available — these tests run in CI, which installs bubblewrap.
func newOSSandboxForTest(t *testing.T, workDir string) *Sandbox {
	t.Helper()
	s := NewSandbox()
	enabled := true
	s.updateConfig(&config.Config{OSSandbox: &enabled}, workDir)
	t.Cleanup(func() { s.Close() })
	return s
}

// TestOSSandboxBackgroundExecuteAndOutput runs a background command through the
// real OS sandbox worker and reads its output and exit code back.
func TestOSSandboxBackgroundExecuteAndOutput(t *testing.T) {
	requireOSSandbox(t)
	tmpDir := t.TempDir()
	s := newOSSandboxForTest(t, tmpDir)

	// `cat` is a real binary (not an interpreter builtin), so its output flows
	// back from a process actually spawned inside the sandbox worker.
	marker := filepath.Join(tmpDir, "marker.txt")
	if err := os.WriteFile(marker, []byte("sandbox-bg\n"), 0644); err != nil {
		t.Fatalf("write marker: %v", err)
	}

	proc, err := s.ExecuteBackground("cat "+marker, tmpDir, []string{tmpDir}, []string{tmpDir})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}

	if st := waitForStatus(t, proc, 15*time.Second, "completed", "failed"); st != "completed" {
		t.Fatalf("expected completed status, got %q", st)
	}

	data, err := os.ReadFile(proc.OutputPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if !strings.Contains(string(data), "sandbox-bg") {
		t.Fatalf("expected output to contain greeting, got %q", data)
	}
	if code := s.ListBackground()[0].ExitCode; code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}

	// The agent reads the output file through the sandbox itself: the worker
	// sees the host's file (on Linux, through a bind over its private /tmp)
	// and the read passes validation with the output root granted.
	readPaths := []string{tmpDir, BackgroundOutputReadPath()}
	out, err := s.Execute(context.Background(), "cat "+proc.OutputPath, tmpDir, readPaths, []string{tmpDir})
	if err != nil {
		t.Fatalf("reading output file through the sandbox: %v", err)
	}
	if !strings.Contains(out, "sandbox-bg") {
		t.Fatalf("expected sandboxed cat of output file to show greeting, got %q", out)
	}
}

// TestOSSandboxBackgroundKill verifies that killing a background process running
// in the OS sandbox actually stops it: the kill round-trips through the worker
// (HostMsgCancel), and output stops flowing afterward. The loop spawns `sleep`
// in the sandbox each iteration, so the worker's kill path is exercised.
func TestOSSandboxBackgroundKill(t *testing.T) {
	requireOSSandbox(t)
	tmpDir := t.TempDir()
	s := newOSSandboxForTest(t, tmpDir)

	proc, err := s.ExecuteBackground("while true; do echo tick; sleep 0.2; done", tmpDir, []string{tmpDir}, []string{tmpDir})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}

	// Wait until it is actually producing output through the sandbox.
	readOut := func() string {
		data, err := os.ReadFile(proc.OutputPath)
		if err != nil {
			t.Fatalf("read output file: %v", err)
		}
		return string(data)
	}
	sawTick := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(readOut(), "tick") {
			sawTick = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !sawTick {
		t.Fatal("background command never produced output through the OS sandbox")
	}

	if err := s.KillBackground(proc.ID); err != nil {
		t.Fatalf("KillBackground failed: %v", err)
	}
	if st := waitForStatus(t, proc, 15*time.Second, "killed"); st != "killed" {
		t.Fatalf("expected killed status, got %q", st)
	}

	// After the kill settles, output must stop growing — the sandboxed process
	// (and the sleep it spawns) is gone.
	before := readOut()
	time.Sleep(1500 * time.Millisecond)
	if after := readOut(); after != before {
		t.Fatalf("expected no new output after kill, got %q", after[len(before):])
	}
}
