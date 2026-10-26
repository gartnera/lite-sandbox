package os_sandbox

import (
	"context"
	"io"
	"testing"
	"time"
)

// endlessReader is a stdin that never runs out.
type endlessReader struct{}

func (endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'y'
	}
	return len(p), nil
}

// TestWorkerUnreadStdinDoesNotBlock is the regression test for one command
// bricking the worker: a command that never reads its stdin, fed without end
// (`yes | sleep 100`), used to block the worker's message loop on a pipe
// write, so every later command — and the hung one's own cancellation —
// waited forever.
func TestWorkerUnreadStdinDoesNotBlock(t *testing.T) {
	w := startBareWorker(t)
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hung := make(chan execResult, 1)
	go func() {
		code, err := w.Exec(ctx, []string{"sleep", "60"}, dir, nil, endlessReader{}, io.Discard, io.Discard)
		hung <- execResult{code, err}
	}()
	time.Sleep(500 * time.Millisecond) // let stdin fill the pipe and the window

	ch, buf := runExecAsync(w, context.Background(), []string{"echo", "hi"}, dir)
	select {
	case r := <-ch:
		if r.err != nil || r.exitCode != 0 || buf.String() != "hi\n" {
			t.Fatalf("second command: code=%d err=%v out=%q", r.exitCode, r.err, buf.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a command that does not read its stdin blocked the next command")
	}

	cancel()
	select {
	case <-hung:
	case <-time.After(gracefulKillTimeout + 8*time.Second):
		t.Fatal("cancel did not reach a command that does not read its stdin")
	}
}

// blockingWriter blocks every Write until release is closed, like a pipeline
// stage that is not reading.
type blockingWriter struct{ release chan struct{} }

func (b blockingWriter) Write(p []byte) (int, error) {
	<-b.release
	return 0, io.ErrClosedPipe
}

// TestWorkerStalledOutputDoesNotBlock covers the host side of the same bug:
// an execution whose output is not being taken used to fill its channel and
// block the dispatcher that delivers every execution's messages.
func TestWorkerStalledOutputDoesNotBlock(t *testing.T) {
	w := startBareWorker(t)
	dir := t.TempDir()

	release := make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stalled := make(chan execResult, 1)
	go func() {
		out := blockingWriter{release}
		code, err := w.Exec(ctx, []string{"yes"}, dir, nil, nil, out, out)
		stalled <- execResult{code, err}
	}()
	time.Sleep(500 * time.Millisecond)

	ch, buf := runExecAsync(w, context.Background(), []string{"echo", "hi"}, dir)
	select {
	case r := <-ch:
		if r.err != nil || r.exitCode != 0 || buf.String() != "hi\n" {
			t.Fatalf("second command: code=%d err=%v out=%q", r.exitCode, r.err, buf.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a command whose output is not taken blocked the next command")
	}

	// Cancelling must reach the worker even while Exec is stuck writing.
	cancel()
	time.Sleep(gracefulKillTimeout + time.Second)
	close(release)
	select {
	case <-stalled:
	case <-time.After(10 * time.Second):
		t.Fatal("stalled command did not finish after cancel")
	}
}

// TestWorkerBrokenPipeStopsCommand: once the writer its output goes to fails
// (`yes | head -1` after head exits), the command is stopped, as SIGPIPE would
// stop it, instead of running until the timeout.
func TestWorkerBrokenPipeStopsCommand(t *testing.T) {
	w := startBareWorker(t)
	pr, pw := io.Pipe()
	go func() {
		buf := make([]byte, 1)
		pr.Read(buf) //nolint:errcheck
		pr.Close()
	}()
	done := make(chan execResult, 1)
	go func() {
		code, err := w.Exec(context.Background(), []string{"yes"}, t.TempDir(), nil, nil, pw, io.Discard)
		done <- execResult{code, err}
	}()
	select {
	case r := <-done:
		if r.exitCode == 0 {
			t.Fatalf("expected yes to be stopped, got exit 0")
		}
	case <-time.After(gracefulKillTimeout + 8*time.Second):
		t.Fatal("command kept running after its reader went away")
	}
}

// deadlineOnlyCtx has a deadline but is never cancelled, standing in for a
// host whose cancel never reaches the worker.
type deadlineOnlyCtx struct {
	context.Context
	deadline time.Time
}

func (c deadlineOnlyCtx) Deadline() (time.Time, bool) { return c.deadline, true }

// TestWorkerEnforcesDeadline: the worker kills a command at the deadline the
// host sent with it, without waiting for the host's cancel.
func TestWorkerEnforcesDeadline(t *testing.T) {
	w := startBareWorker(t)
	ctx := deadlineOnlyCtx{context.Background(), time.Now().Add(500 * time.Millisecond)}
	start := time.Now()
	ch, _ := runExecAsync(w, ctx, []string{"sleep", "60"}, t.TempDir())
	select {
	case r := <-ch:
		if r.exitCode == 0 && r.err == nil {
			t.Fatalf("expected the command to be killed, got a clean exit")
		}
		if elapsed := time.Since(start); elapsed > gracefulKillTimeout+5*time.Second {
			t.Fatalf("worker took %v to enforce the deadline", elapsed)
		}
	case <-time.After(gracefulKillTimeout + 8*time.Second):
		t.Fatal("worker did not enforce the deadline")
	}
}
