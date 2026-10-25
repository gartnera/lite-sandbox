package os_sandbox

import (
	"bufio"
	"encoding/gob"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// workerTestResult accumulates stdout/stderr from a streamed worker response.
type workerTestResult struct {
	stdout   []byte
	stderr   []byte
	exitCode int
	err      string
}

// readWorkerResult reads WorkerMsg messages from dec until WorkerMsgDone for the given ID.
// Messages for other IDs are skipped (for sequential tests where only one exec is in flight).
func readWorkerResult(dec *gob.Decoder, id uint64) (workerTestResult, error) {
	var res workerTestResult
	for {
		var msg WorkerMsg
		if err := dec.Decode(&msg); err != nil {
			return res, err
		}
		if msg.ID != id {
			continue
		}
		switch msg.Type {
		case WorkerMsgStdout:
			res.stdout = append(res.stdout, msg.Data...)
		case WorkerMsgStderr:
			res.stderr = append(res.stderr, msg.Data...)
		case WorkerMsgDone:
			res.exitCode = msg.ExitCode
			res.err = msg.Error
			return res, nil
		}
	}
}

// sendExec sends a HostMsgExec followed by HostMsgStdinEOF (no stdin data).
func sendExec(enc *gob.Encoder, buf *bufio.Writer, id uint64, args []string, dir string) error {
	if err := enc.Encode(HostMsg{ID: id, Type: HostMsgExec, Args: args, Dir: dir, Env: map[string]string{}}); err != nil {
		return err
	}
	if err := buf.Flush(); err != nil {
		return err
	}
	if err := enc.Encode(HostMsg{ID: id, Type: HostMsgStdinEOF}); err != nil {
		return err
	}
	return buf.Flush()
}

// TestWorkerIPCWithoutBwrap tests the gob IPC mechanism without bwrap.
func TestWorkerIPCWithoutBwrap(t *testing.T) {
	// Use the lite-sandbox binary (not the test binary)
	// Look in project root (two directories up from this test file)
	binary := "../lite-sandbox"
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		t.Skipf("lite-sandbox binary not found at %s, skipping test (run 'go build' first)", binary)
	}

	// Start worker directly (no bwrap)
	cmd := exec.Command(binary, "sandbox-worker")
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start worker: %v", err)
	}
	defer cmd.Process.Kill()

	// Set up gob encoder/decoder with buffering
	bufStdin := bufio.NewWriter(stdin)
	bufStdout := bufio.NewReader(stdout)
	enc := gob.NewEncoder(bufStdin)
	dec := gob.NewDecoder(bufStdout)

	// Wait for ready signal
	t.Log("waiting for ready signal")
	var ready WorkerMsg
	if err := dec.Decode(&ready); err != nil {
		t.Fatalf("failed to receive ready signal: %v", err)
	}
	if ready.Type != WorkerMsgReady {
		t.Fatalf("expected WorkerMsgReady, got type %d", ready.Type)
	}
	t.Log("received ready signal")

	// Send a simple command
	t.Log("sending command")
	if err := sendExec(enc, bufStdin, 1, []string{"echo", "hello"}, t.TempDir()); err != nil {
		t.Fatalf("failed to send exec: %v", err)
	}

	// Read response with timeout
	t.Log("waiting for response")
	type resultOrErr struct {
		res workerTestResult
		err error
	}
	ch := make(chan resultOrErr, 1)
	go func() {
		res, err := readWorkerResult(dec, 1)
		ch <- resultOrErr{res, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("failed to read worker result: %v", r.err)
		}
		t.Logf("received response: stdout=%q, stderr=%q, exit_code=%d", r.res.stdout, r.res.stderr, r.res.exitCode)
		if r.res.err != "" {
			t.Fatalf("command failed: %s", r.res.err)
		}
		if r.res.exitCode != 0 {
			t.Fatalf("command exited with code %d", r.res.exitCode)
		}
		if string(r.res.stdout) != "hello\n" {
			t.Errorf("unexpected output: got %q, want %q", r.res.stdout, "hello\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestWorkerIPCMultipleCommands tests sending multiple commands to the same worker.
func TestWorkerIPCMultipleCommands(t *testing.T) {
	binary := "../lite-sandbox"
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		t.Skipf("lite-sandbox binary not found at %s, skipping test (run 'go build' first)", binary)
	}

	cmd := exec.Command(binary, "sandbox-worker")
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start worker: %v", err)
	}
	defer cmd.Process.Kill()

	bufStdin := bufio.NewWriter(stdin)
	bufStdout := bufio.NewReader(stdout)
	enc := gob.NewEncoder(bufStdin)
	dec := gob.NewDecoder(bufStdout)

	// Wait for ready signal
	var ready WorkerMsg
	if err := dec.Decode(&ready); err != nil {
		t.Fatalf("failed to receive ready signal: %v", err)
	}
	if ready.Type != WorkerMsgReady {
		t.Fatalf("expected WorkerMsgReady, got type %d", ready.Type)
	}

	tmpDir := t.TempDir()

	// Send multiple commands sequentially
	testCases := []struct {
		id       uint64
		args     []string
		expected string
	}{
		{1, []string{"echo", "first"}, "first\n"},
		{2, []string{"echo", "second"}, "second\n"},
		{3, []string{"echo", "third"}, "third\n"},
	}

	for i, tc := range testCases {
		if err := sendExec(enc, bufStdin, tc.id, tc.args, tmpDir); err != nil {
			t.Fatalf("failed to send exec %d: %v", i, err)
		}

		res, err := readWorkerResult(dec, tc.id)
		if err != nil {
			t.Fatalf("failed to read result %d: %v", i, err)
		}

		if res.err != "" {
			t.Fatalf("command %d failed: %s", i, res.err)
		}
		if res.exitCode != 0 {
			t.Fatalf("command %d exited with code %d", i, res.exitCode)
		}
		if string(res.stdout) != tc.expected {
			t.Errorf("command %d: got %q, want %q", i, res.stdout, tc.expected)
		}
	}
}

// TestWorkerIPCWithStdin tests streaming stdin data to a worker command.
func TestWorkerIPCWithStdin(t *testing.T) {
	binary := "../lite-sandbox"
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		t.Skipf("lite-sandbox binary not found at %s, skipping test (run 'go build' first)", binary)
	}

	cmd := exec.Command(binary, "sandbox-worker")
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start worker: %v", err)
	}
	defer cmd.Process.Kill()

	bufStdin := bufio.NewWriter(stdin)
	bufStdout := bufio.NewReader(stdout)
	enc := gob.NewEncoder(bufStdin)
	dec := gob.NewDecoder(bufStdout)

	// Wait for ready signal
	var ready WorkerMsg
	if err := dec.Decode(&ready); err != nil {
		t.Fatalf("failed to receive ready signal: %v", err)
	}
	if ready.Type != WorkerMsgReady {
		t.Fatalf("expected WorkerMsgReady, got type %d", ready.Type)
	}

	tmpDir := t.TempDir()
	const execID uint64 = 1

	// Send exec for "cat" which reads stdin and writes to stdout
	if err := enc.Encode(HostMsg{ID: execID, Type: HostMsgExec, Args: []string{"cat"}, Dir: tmpDir, Env: map[string]string{}}); err != nil {
		t.Fatalf("failed to encode exec: %v", err)
	}
	if err := bufStdin.Flush(); err != nil {
		t.Fatalf("failed to flush exec: %v", err)
	}

	// Stream stdin data in chunks
	for _, line := range []string{"hello\n", "world\n"} {
		if err := enc.Encode(HostMsg{ID: execID, Type: HostMsgStdin, Data: []byte(line)}); err != nil {
			t.Fatalf("failed to encode stdin chunk: %v", err)
		}
		if err := bufStdin.Flush(); err != nil {
			t.Fatalf("failed to flush stdin chunk: %v", err)
		}
	}

	// Send stdin EOF
	if err := enc.Encode(HostMsg{ID: execID, Type: HostMsgStdinEOF}); err != nil {
		t.Fatalf("failed to encode stdin EOF: %v", err)
	}
	if err := bufStdin.Flush(); err != nil {
		t.Fatalf("failed to flush stdin EOF: %v", err)
	}

	// Read response with timeout
	type resultOrErr struct {
		res workerTestResult
		err error
	}
	ch := make(chan resultOrErr, 1)
	go func() {
		res, err := readWorkerResult(dec, execID)
		ch <- resultOrErr{res, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("failed to read worker result: %v", r.err)
		}
		if r.res.exitCode != 0 {
			t.Fatalf("command exited with code %d", r.res.exitCode)
		}
		if string(r.res.stdout) != "hello\nworld\n" {
			t.Errorf("unexpected output: got %q, want %q", r.res.stdout, "hello\nworld\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for response")
	}
}

// TestWorkerIPCDoneBeforeStdinEOF checks a command's done message does not
// wait for the end of its stdin: a host terminal ends only when the host stops
// pumping it, which it does on that message.
func TestWorkerIPCDoneBeforeStdinEOF(t *testing.T) {
	binary := "../lite-sandbox"
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		t.Skipf("lite-sandbox binary not found at %s, skipping test (run 'go build' first)", binary)
	}

	cmd := exec.Command(binary, "sandbox-worker")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start worker: %v", err)
	}
	defer cmd.Process.Kill()

	bufStdin := bufio.NewWriter(stdin)
	enc := gob.NewEncoder(bufStdin)
	dec := gob.NewDecoder(bufio.NewReader(stdout))
	var ready WorkerMsg
	if err := dec.Decode(&ready); err != nil || ready.Type != WorkerMsgReady {
		t.Fatalf("no ready signal: %v (type %d)", err, ready.Type)
	}

	// Exec without ever sending HostMsgStdinEOF.
	const execID uint64 = 1
	if err := enc.Encode(HostMsg{ID: execID, Type: HostMsgExec, Args: []string{"echo", "done"}, Dir: t.TempDir(), Env: map[string]string{}}); err != nil {
		t.Fatalf("failed to encode exec: %v", err)
	}
	if err := bufStdin.Flush(); err != nil {
		t.Fatalf("failed to flush exec: %v", err)
	}

	ch := make(chan workerTestResult, 1)
	go func() {
		res, _ := readWorkerResult(dec, execID)
		ch <- res
	}()
	select {
	case res := <-ch:
		if res.exitCode != 0 || string(res.stdout) != "done\n" {
			t.Errorf("got exit %d, stdout %q; want 0, %q", res.exitCode, res.stdout, "done\n")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("done waited for the end of stdin")
	}
}

// TestWorkerIPCConcurrent tests that multiple executions can run concurrently on a single worker.
func TestWorkerIPCConcurrent(t *testing.T) {
	binary := "../lite-sandbox"
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		t.Skipf("lite-sandbox binary not found at %s, skipping test (run 'go build' first)", binary)
	}

	cmd := exec.Command(binary, "sandbox-worker")
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("failed to create stdin pipe: %v", err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("failed to start worker: %v", err)
	}
	defer cmd.Process.Kill()

	bufStdin := bufio.NewWriter(stdin)
	bufStdout := bufio.NewReader(stdout)
	enc := gob.NewEncoder(bufStdin)
	dec := gob.NewDecoder(bufStdout)

	// Wait for ready signal
	var ready WorkerMsg
	if err := dec.Decode(&ready); err != nil {
		t.Fatalf("failed to receive ready signal: %v", err)
	}
	if ready.Type != WorkerMsgReady {
		t.Fatalf("expected WorkerMsgReady, got type %d", ready.Type)
	}

	tmpDir := t.TempDir()

	// Send 3 execs without waiting for any results.
	execIDs := []uint64{10, 20, 30}
	for _, id := range execIDs {
		if err := sendExec(enc, bufStdin, id, []string{"echo", "hello"}, tmpDir); err != nil {
			t.Fatalf("failed to send exec %d: %v", id, err)
		}
	}

	// Collect results for all IDs concurrently by reading in a demuxing goroutine.
	type resultOrErr struct {
		res workerTestResult
		err error
	}
	resultChans := make(map[uint64]chan resultOrErr)
	for _, id := range execIDs {
		resultChans[id] = make(chan resultOrErr, 1)
	}

	// Demux: read all messages and route by ID.
	var demuxWg sync.WaitGroup
	demuxWg.Add(1)
	go func() {
		defer demuxWg.Done()
		pending := make(map[uint64]workerTestResult)
		remaining := len(execIDs)
		for remaining > 0 {
			var msg WorkerMsg
			if err := dec.Decode(&msg); err != nil {
				// Send error to all remaining channels
				for _, id := range execIDs {
					if _, done := pending[id]; !done {
						resultChans[id] <- resultOrErr{err: err}
					}
				}
				return
			}
			r := pending[msg.ID]
			switch msg.Type {
			case WorkerMsgStdout:
				r.stdout = append(r.stdout, msg.Data...)
			case WorkerMsgStderr:
				r.stderr = append(r.stderr, msg.Data...)
			case WorkerMsgDone:
				r.exitCode = msg.ExitCode
				r.err = msg.Error
				resultChans[msg.ID] <- resultOrErr{res: r}
				remaining--
				continue
			}
			pending[msg.ID] = r
		}
	}()

	// Verify results for each exec.
	for _, id := range execIDs {
		select {
		case r := <-resultChans[id]:
			if r.err != nil {
				t.Errorf("exec %d: error: %v", id, r.err)
				continue
			}
			if r.res.err != "" {
				t.Errorf("exec %d: command error: %s", id, r.res.err)
			}
			if r.res.exitCode != 0 {
				t.Errorf("exec %d: unexpected exit code %d", id, r.res.exitCode)
			}
			if string(r.res.stdout) != "hello\n" {
				t.Errorf("exec %d: got %q, want %q", id, r.res.stdout, "hello\n")
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timeout waiting for result of exec %d", id)
		}
	}

	demuxWg.Wait()
}
