package bash_sandboxed

import (
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
	s.UpdateConfig(&config.Config{OSSandbox: &enabled}, workDir)
	t.Cleanup(func() { s.Close() })
	return s
}

// TestOSSandboxBackgroundExecuteAndOutput runs a background command through the
// real OS sandbox worker and reads its output and exit code back.
func TestOSSandboxBackgroundExecuteAndOutput(t *testing.T) {
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

	res, err := s.BackgroundOutput(proc.ID, "")
	if err != nil {
		t.Fatalf("BackgroundOutput failed: %v", err)
	}
	if !strings.Contains(res.Output, "sandbox-bg") {
		t.Fatalf("expected output to contain greeting, got %q", res.Output)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}
}

// TestOSSandboxBackgroundKill verifies that killing a background process running
// in the OS sandbox actually stops it: the kill round-trips through the worker
// (HostMsgCancel), and output stops flowing afterward. The loop spawns `sleep`
// in the sandbox each iteration, so the worker's kill path is exercised.
func TestOSSandboxBackgroundKill(t *testing.T) {
	tmpDir := t.TempDir()
	s := newOSSandboxForTest(t, tmpDir)

	proc, err := s.ExecuteBackground("while true; do echo tick; sleep 0.2; done", tmpDir, []string{tmpDir}, []string{tmpDir})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}

	// Wait until it is actually producing output through the sandbox.
	sawTick := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		res, err := s.BackgroundOutput(proc.ID, "")
		if err != nil {
			t.Fatalf("BackgroundOutput failed: %v", err)
		}
		if strings.Contains(res.Output, "tick") {
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
	_, _ = s.BackgroundOutput(proc.ID, "") // drain anything buffered
	time.Sleep(1500 * time.Millisecond)
	res, err := s.BackgroundOutput(proc.ID, "")
	if err != nil {
		t.Fatalf("BackgroundOutput failed: %v", err)
	}
	if strings.TrimSpace(res.Output) != "" {
		t.Fatalf("expected no new output after kill, got %q", res.Output)
	}
}
