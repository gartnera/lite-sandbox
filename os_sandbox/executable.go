package os_sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

// pinnedExecFD is the descriptor a Linux worker's binary is handed to bwrap
// on: the first of exec.Cmd.ExtraFiles.
const pinnedExecFD = 3

// pinnedExecFDPath is what bwrap execs for a pinned worker binary. bwrap
// inherits the descriptor and exec through the /proc magic link reaches the
// file it was opened on, even after the path has been replaced or deleted.
var pinnedExecFDPath = "/proc/self/fd/" + strconv.Itoa(pinnedExecFD)

// workerBinary is the lite-sandbox executable a worker runs.
type workerBinary struct {
	// path is where the binary was found, for logs and for exec where no
	// handle is pinned.
	path string
	// file, on Linux, is an open handle on the binary, so every worker the
	// process starts runs that same build even if a rebuild or `lite-sandbox
	// update` replaces the file at path in the meantime.
	file *os.File
}

var (
	workerBinaryOnce sync.Once
	workerBinaryVal  workerBinary
	workerBinaryErr  error
)

// pinnedWorkerBinary returns the binary workers run, resolved once per
// process. Normally that is this process's own executable: on Linux it is
// opened through /proc/self/exe, which names the running image whatever
// has since happened to its path; elsewhere it is the path, checked against
// startupExecutable before each worker starts (checkWorkerBinary). A test
// binary instead runs a lite-sandbox built next to the test.
func pinnedWorkerBinary() (workerBinary, error) {
	workerBinaryOnce.Do(func() {
		workerBinaryVal, workerBinaryErr = resolveWorkerBinary()
	})
	return workerBinaryVal, workerBinaryErr
}

func resolveWorkerBinary() (workerBinary, error) {
	self, err := os.Executable()
	if err != nil {
		return workerBinary{}, fmt.Errorf("failed to get executable path: %w", err)
	}
	open := "/proc/self/exe"

	// If running from a test binary, try to find the actual binary
	if isTestBinary(self) {
		// Look for lite-sandbox next to the test's working directory, then two
		// levels up (for tests in tool/bash_sandboxed).
		found := ""
		if cwd, err := os.Getwd(); err == nil {
			for _, candidate := range []string{
				filepath.Join(cwd, "lite-sandbox"),
				filepath.Join(cwd, "../..", "lite-sandbox"),
			} {
				if _, err := os.Stat(candidate); err == nil {
					found = candidate
					break
				}
			}
		}
		if found == "" {
			return workerBinary{}, fmt.Errorf("lite-sandbox binary not found (required for OS sandbox tests, run 'go build -o lite-sandbox' first)")
		}
		self, open = found, found
	}

	b := workerBinary{path: self}
	if runtime.GOOS == "linux" {
		f, err := os.Open(open)
		if err != nil {
			return workerBinary{}, fmt.Errorf("failed to open executable %s: %w", open, err)
		}
		b.file = f
	}
	return b, nil
}

func isTestBinary(self string) bool {
	baseName := filepath.Base(self)
	return baseName != "lite-sandbox" && (filepath.Ext(self) == ".test" || filepath.Ext(baseName) == ".test")
}

// startupExecutable is this process's executable as it was at process start.
// It is only recorded where a worker binary cannot be pinned by handle (not
// Linux), so checkWorkerBinary can refuse to start a worker from a file that
// has since been replaced rather than silently run a different build.
var startupExecutable = statStartupExecutable()

func statStartupExecutable() os.FileInfo {
	if runtime.GOOS == "linux" {
		return nil
	}
	self, err := os.Executable()
	if err != nil || isTestBinary(self) {
		return nil
	}
	fi, err := os.Stat(self)
	if err != nil {
		return nil
	}
	return fi
}

// checkWorkerBinary reports an error when the unpinned worker binary is no
// longer the file this process started from.
func checkWorkerBinary(b workerBinary) error {
	if b.file != nil || startupExecutable == nil {
		return nil
	}
	fi, err := os.Stat(b.path)
	if err == nil && sameBinary(startupExecutable, fi) {
		return nil
	}
	return fmt.Errorf("the lite-sandbox binary at %s changed after this server started (rebuilt or updated); restart the server so its sandbox workers run the same build", b.path)
}

func sameBinary(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

// closePinnedExecFD closes the descriptor a worker was exec'd through (see
// pinnedExecFDPath). It is inherited without close-on-exec, so left open it
// would pass on to every command the worker runs.
func closePinnedExecFD() {
	rest, ok := strings.CutPrefix(os.Args[0], "/proc/self/fd/")
	if !ok {
		return
	}
	if fd, err := strconv.Atoi(rest); err == nil && fd > 2 {
		syscall.Close(fd)
	}
}
