package os_sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetWorkerBinary drops the process-wide pinned worker binary so a test can
// pin a different one, and restores the default afterwards.
func resetWorkerBinary(t *testing.T) {
	t.Helper()
	reset := func() {
		if workerBinaryVal.file != nil {
			workerBinaryVal.file.Close()
		}
		workerBinaryOnce = sync.Once{}
		workerBinaryVal, workerBinaryErr = workerBinary{}, nil
	}
	reset()
	t.Cleanup(reset)
}

// TestPinnedWorkerBinarySurvivesReplacement replaces the lite-sandbox binary
// after the first worker started — what a rebuild or `lite-sandbox update`
// does under a running server — and checks a later worker still runs the
// build that was pinned rather than the file now at that path.
func TestPinnedWorkerBinarySurvivesReplacement(t *testing.T) {
	requireLinux(t)
	if os.Getenv("OS_SANDBOX_TESTS") == "" {
		t.Skip("requires OS sandbox runtime; set OS_SANDBOX_TESTS=1 to run (enabled in CI)")
	}
	built, err := os.ReadFile(filepath.Join("..", "lite-sandbox"))
	if err != nil {
		t.Skipf("lite-sandbox binary not built at the repo root: %v", err)
	}

	dir := t.TempDir()
	bin := filepath.Join(dir, "lite-sandbox")
	if err := os.WriteFile(bin, built, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	resetWorkerBinary(t)

	run := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		w, err := StartWorker(ctx, WorkerOptions{WorkDir: dir})
		if err != nil {
			t.Fatalf("StartWorker: %v", err)
		}
		defer w.Close()
		var stdout, stderr bytes.Buffer
		code, err := w.Exec(ctx, args, dir, nil, nil, &stdout, &stderr)
		if err != nil || code != 0 {
			t.Fatalf("Exec %v: code %d, err %v, stderr %q", args, code, err, stderr.String())
		}
		return stdout.String()
	}

	if got := run("echo", "first"); got != "first\n" {
		t.Fatalf("first worker: got %q", got)
	}

	// Replace the binary the way a build does: a new file at the same path.
	if err := os.Remove(bin); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 97\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := run("echo", "second"); got != "second\n" {
		t.Fatalf("worker after replacement: got %q", got)
	}

	// The worker closes the descriptor it was exec'd through, so the commands
	// it runs do not inherit a handle on the binary.
	out := run("ls", "-l", "/proc/self/fd/")
	if strings.Contains(out, "lite-sandbox") {
		t.Fatalf("pinned binary descriptor leaked into the worker's commands:\n%s", out)
	}
}

func TestCheckWorkerBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lite-sandbox")
	if err := os.WriteFile(path, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	saved := startupExecutable
	startupExecutable = fi
	t.Cleanup(func() { startupExecutable = saved })

	b := workerBinary{path: path}
	if err := checkWorkerBinary(b); err != nil {
		t.Fatalf("unchanged binary: %v", err)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("v2, longer"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkWorkerBinary(b); err == nil || !strings.Contains(err.Error(), "restart the server") {
		t.Fatalf("replaced binary: got %v, want a restart error", err)
	}

	// A pinned handle needs no check: the worker runs the handle's file.
	b.file = os.Stdin
	if err := checkWorkerBinary(b); err != nil {
		t.Fatalf("pinned binary: %v", err)
	}
}
