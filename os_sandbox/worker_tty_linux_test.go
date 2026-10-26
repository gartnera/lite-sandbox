package os_sandbox

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// ttyHelperEnv marks the re-executed test process that holds a controlling
// terminal (see TestWorkerHasNoControllingTerminal).
const ttyHelperEnv = "LITE_SANDBOX_TEST_TTY_HELPER"

// TestWorkerHasNoControllingTerminal: an agent's MCP server shares the agent's
// terminal as its controlling terminal, and a worker command that could open
// /dev/tty would prompt on it (ssh's host-key and password prompts) and hang,
// or write to the agent's screen. The test re-executes itself with a pty as
// its controlling terminal, the way the agent runs the server, and checks that
// a command in the worker cannot open /dev/tty.
func TestWorkerHasNoControllingTerminal(t *testing.T) {
	if os.Getenv(ttyHelperEnv) == "1" {
		f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			t.Fatalf("helper has no controlling terminal to start with: %v", err)
		}
		f.Close()
		w := startBareWorker(t)
		var out bytes.Buffer
		code, err := w.Exec(context.Background(), []string{"sh", "-c", ": </dev/tty"}, t.TempDir(), nil, nil, &out, &out)
		if err != nil || code == 0 {
			t.Fatalf("a worker command opened /dev/tty: code=%d err=%v out=%q", code, err, out.String())
		}
		return
	}

	binary, err := filepath.Abs("../lite-sandbox")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(binary); err != nil {
		t.Skipf("lite-sandbox binary not found at %s (run 'go build -o lite-sandbox')", binary)
	}
	ptmx, pts, err := openPty()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer ptmx.Close()
	defer pts.Close()
	go io.Copy(io.Discard, ptmx) //nolint:errcheck // keep the terminal drained

	var out bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestWorkerHasNoControllingTerminal$", "-test.v")
	cmd.Env = append(os.Environ(), ttyHelperEnv+"=1")
	cmd.Stdin = pts
	cmd.Stdout = &out
	cmd.Stderr = &out
	cmd.SysProcAttr = &unix.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Run(); err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out.String())
	}
}

// openPty opens a pseudo-terminal pair (Linux).
func openPty() (ptmx, pts *os.File, err error) {
	ptmx, err = os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		ptmx.Close()
		return nil, nil, fmt.Errorf("unlockpt: %w", err)
	}
	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		ptmx.Close()
		return nil, nil, fmt.Errorf("ptsname: %w", err)
	}
	pts, err = os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		ptmx.Close()
		return nil, nil, err
	}
	return ptmx, pts, nil
}
