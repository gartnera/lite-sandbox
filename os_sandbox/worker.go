package os_sandbox

import (
	"encoding/gob"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
)

// procRegistry tracks the currently running commands by execution ID so a
// HostMsgCancel can terminate the matching process.
type procRegistry struct {
	mu sync.Mutex
	m  map[uint64]*exec.Cmd
}

func newProcRegistry() *procRegistry {
	return &procRegistry{m: make(map[uint64]*exec.Cmd)}
}

func (r *procRegistry) add(id uint64, cmd *exec.Cmd) {
	r.mu.Lock()
	r.m[id] = cmd
	r.mu.Unlock()
}

func (r *procRegistry) remove(id uint64) {
	r.mu.Lock()
	delete(r.m, id)
	r.mu.Unlock()
}

// kill terminates the command registered for id, if any. It first asks the
// process subtree to exit with SIGTERM, then SIGKILLs whatever is left after a
// grace period. The set of target pids is snapshotted once, up front: on macOS
// the subtree is enumerated from the live process table (see killTargets), and
// once the command leader exits its children reparent to launchd, so
// re-deriving the tree at force-kill time would miss them. Any survivors are
// reaped when the worker is torn down (see Worker.Close).
func (r *procRegistry) kill(id uint64) {
	r.mu.Lock()
	cmd, ok := r.m[id]
	r.mu.Unlock()
	if !ok || cmd.Process == nil {
		return
	}
	targets := killTargets(cmd.Process.Pid)
	signalPids(targets, syscall.SIGTERM)

	time.AfterFunc(gracefulKillTimeout, func() {
		// Skip the force-kill if the command already exited (and was
		// deregistered), so we don't signal recycled pids.
		r.mu.Lock()
		_, stillRunning := r.m[id]
		r.mu.Unlock()
		if !stillRunning {
			return
		}
		signalPids(targets, syscall.SIGKILL)
	})
}

// signalPids sends sig to each target, ignoring errors (a target may have
// already exited). A negative target signals the process group led by its
// absolute value (used on Linux); a positive target signals that one process
// (used for each member of an enumerated subtree on macOS).
func signalPids(targets []int, sig syscall.Signal) {
	for _, pid := range targets {
		_ = syscall.Kill(pid, sig)
	}
}

// execFlow is the worker's flow-control state for one execution. RunWorker's
// message loop is shared by every execution — their stdin, their cancellation
// and new commands all arrive through it — so it must never wait on any one of
// them: a command that does not read its stdin (`yes | sleep 100`) used to
// block the loop on a pipe write, and with it every later command and every
// cancel. Each direction is bounded by a window of flowWindow chunks instead:
// the host sends a stdin chunk only against a credit the worker returns
// (WorkerMsgStdinAck) once the chunk is written to the command, so the stdin
// queue never fills; and the worker sends an output chunk only against a
// credit the host returns (HostMsgOutputAck) once it has written the chunk out.
type execFlow struct {
	stdin       chan []byte   // stdin chunks, closed at the host's EOF
	stdinClosed bool          // guarded by flowRegistry.mu
	credits     chan struct{} // output chunks the host has room for
	cancelled   chan struct{} // closed when the execution is cancelled
	cancelOnce  sync.Once
}

// acquire waits for an output credit. It returns false once the execution is
// cancelled: the host may have stopped reading (its writer blocked on a
// pipeline stage that never reads), and the command's remaining output is
// dropped so that it can be reaped and its done message sent.
func (f *execFlow) acquire() bool {
	select {
	case <-f.credits:
		return true
	default:
	}
	select {
	case <-f.credits:
		return true
	case <-f.cancelled:
		return false
	}
}

func (f *execFlow) cancel() {
	f.cancelOnce.Do(func() { close(f.cancelled) })
}

// flowRegistry holds the execFlow of each running execution. Every method
// returns without blocking, so RunWorker's loop can call them.
type flowRegistry struct {
	mu sync.Mutex
	m  map[uint64]*execFlow
}

func newFlowRegistry() *flowRegistry {
	return &flowRegistry{m: make(map[uint64]*execFlow)}
}

func (r *flowRegistry) add(id uint64) *execFlow {
	f := &execFlow{
		stdin:     make(chan []byte, flowWindow),
		credits:   make(chan struct{}, flowWindow),
		cancelled: make(chan struct{}),
	}
	for range flowWindow {
		f.credits <- struct{}{}
	}
	r.mu.Lock()
	r.m[id] = f
	r.mu.Unlock()
	return f
}

// remove forgets the execution, ending its stdin.
func (r *flowRegistry) remove(id uint64) {
	r.closeStdin(id)
	r.mu.Lock()
	delete(r.m, id)
	r.mu.Unlock()
}

// pushStdin queues a stdin chunk. The host never has more than flowWindow
// chunks unacknowledged, so the queue has room; a chunk past that is a
// protocol error, dropped rather than allowed to block the loop.
func (r *flowRegistry) pushStdin(id uint64, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	f, ok := r.m[id]
	if !ok || f.stdinClosed {
		return
	}
	select {
	case f.stdin <- data:
	default:
		slog.Error("stdin chunk beyond the flow window, dropped", "id", id)
	}
}

func (r *flowRegistry) closeStdin(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.m[id]; ok && !f.stdinClosed {
		f.stdinClosed = true
		close(f.stdin)
	}
}

// credit returns one output credit to the execution.
func (r *flowRegistry) credit(id uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if f, ok := r.m[id]; ok {
		select {
		case f.credits <- struct{}{}:
		default:
		}
	}
}

func (r *flowRegistry) cancel(id uint64) {
	r.mu.Lock()
	f, ok := r.m[id]
	r.mu.Unlock()
	if ok {
		f.cancel()
	}
}

// setProcGroup makes cmd lead its own process group so its whole subtree can be
// signaled at once. On macOS the sandbox profile denies signaling processes
// outside the worker's own process group ("(deny signal (target others))"), so
// placing a command in a separate group would make even a direct kill fail;
// there we leave it in the worker's group and reap its subtree by enumerating
// descendants instead (see killTargets on darwin).
func setProcGroup(cmd *exec.Cmd) {
	if runtime.GOOS != "linux" {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// RunWorker is the main loop for a sandbox worker process (runs inside bwrap/sandbox-exec).
// It reads HostMsg messages from stdin and dispatches them to concurrent executions.
// Multiple executions may be in flight simultaneously, identified by their ID.
// This is called by the "sandbox-worker" CLI command.
func RunWorker() error {
	var level slog.Level
	if err := level.UnmarshalText([]byte(os.Getenv(workerLogLevelEnv))); err != nil {
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	slog.Info("sandbox worker started")

	enc := newLockedEncoder[WorkerMsg](os.Stdout)
	dec := gob.NewDecoder(os.Stdin)

	// Send ready signal
	slog.Info("sending ready signal")
	if err := enc.send(WorkerMsg{Type: WorkerMsgReady}); err != nil {
		return fmt.Errorf("failed to send ready signal: %w", err)
	}

	// flows holds each execution's stdin queue and output credits; procs
	// tracks running commands so HostMsgCancel can kill them.
	flows := newFlowRegistry()
	procs := newProcRegistry()

	// Nothing in this loop may block on one execution: see execFlow.
	for {
		var msg HostMsg
		if err := dec.Decode(&msg); err != nil {
			if err == io.EOF {
				return nil // host closed connection — clean shutdown
			}
			slog.Error("failed to decode host message", "error", err)
			return fmt.Errorf("failed to decode host message: %w", err)
		}

		switch msg.Type {
		case HostMsgExec:
			slog.Info("executing command", "args", msg.Args, "dir", msg.Dir, "id", msg.ID)
			flow := flows.add(msg.ID)
			go func(m HostMsg) {
				if err := streamCommand(enc, m.ID, m, flow, procs); err != nil {
					slog.Error("streamCommand error", "id", m.ID, "error", err)
				}
				flows.remove(m.ID)
			}(msg)

		case HostMsgCancel:
			slog.Info("cancelling command", "id", msg.ID)
			flows.cancel(msg.ID)
			procs.kill(msg.ID)
			flows.closeStdin(msg.ID)

		case HostMsgStdin:
			if len(msg.Data) > 0 {
				flows.pushStdin(msg.ID, msg.Data)
			}

		case HostMsgStdinEOF:
			flows.closeStdin(msg.ID)

		case HostMsgOutputAck:
			flows.credit(msg.ID)

		default:
			slog.Error("unexpected message type", "type", msg.Type)
			return fmt.Errorf("unexpected message type %d", msg.Type)
		}
	}
}

// streamCommand starts the command described by req, feeds it the stdin chunks
// queued on flow, and streams stdout/stderr back via the encoder against
// flow's output credits. Sends WorkerMsgDone when finished. The id parameter
// is included in all outgoing WorkerMsg messages for multiplexing.
func streamCommand(enc *lockedEncoder[WorkerMsg], id uint64, req HostMsg, flow *execFlow, procs *procRegistry) error {
	if len(req.Args) == 0 {
		return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: 1, Error: "no command specified"})
	}

	cmd := exec.Command(req.Args[0], req.Args[1:]...)
	cmd.Dir = req.Dir
	setProcGroup(cmd)

	if len(req.Env) > 0 {
		env := make([]string, 0, len(req.Env))
		for k, v := range req.Env {
			env = append(env, k+"="+v)
		}
		cmd.Env = env
	}

	// The command reads an OS pipe fed from flow's stdin queue. Each chunk is
	// acknowledged once written, which is what lets the host send the next;
	// a command that never reads its stdin holds up only its own feed. Once
	// the pipe is gone (the command closed it, or exited and the write end was
	// closed below) the rest is acknowledged unwritten.
	stdinRead, stdinWrite, err := os.Pipe()
	if err != nil {
		return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: 1, Error: "failed to create stdin pipe: " + err.Error()})
	}
	cmd.Stdin = stdinRead
	go func() {
		live := true
		for data := range flow.stdin {
			if live {
				if _, err := stdinWrite.Write(data); err != nil {
					live = false
				}
			}
			_ = enc.send(WorkerMsg{ID: id, Type: WorkerMsgStdinAck})
		}
		stdinWrite.Close()
	}()
	// The child holds its own copy of the read end from Start on. Once the
	// command is done, closing the write end too unblocks a write a
	// backgrounded grandchild holding stdin would otherwise never take.
	defer stdinRead.Close()
	defer stdinWrite.Close()

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: 1, Error: "failed to create stdout pipe: " + err.Error()})
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: 1, Error: "failed to create stderr pipe: " + err.Error()})
	}

	if err := cmd.Start(); err != nil {
		return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: 1, Error: "failed to start command: " + err.Error()})
	}

	// Register so a HostMsgCancel can kill this process; deregister on exit.
	procs.add(id, cmd)
	defer procs.remove(id)
	// A cancel that arrived before the command was registered found nothing
	// to kill.
	select {
	case <-flow.cancelled:
		procs.kill(id)
	default:
	}

	// The host's deadline is enforced here too, so a command is killed on time
	// even if the host's cancel never arrives (the host gave up on the call,
	// or its connection is wedged).
	if !req.Deadline.IsZero() {
		timer := time.AfterFunc(time.Until(req.Deadline), func() {
			slog.Info("command deadline reached", "id", id)
			flow.cancel()
			procs.kill(id)
		})
		defer timer.Stop()
	}

	// Stream stdout and stderr chunks to the host, each against an output
	// credit; after cancellation, output the host has no room for is dropped.
	pump := func(r io.Reader, typ WorkerMsgType) {
		buf := make([]byte, streamChunkSize)
		for {
			n, err := r.Read(buf)
			if n > 0 && flow.acquire() {
				if encErr := enc.send(WorkerMsg{ID: id, Type: typ, Data: buf[:n]}); encErr != nil {
					slog.Error("failed to send output chunk", "error", encErr)
					return
				}
			}
			if err != nil {
				return
			}
		}
	}
	var wg sync.WaitGroup
	wg.Go(func() { pump(stdoutPipe, WorkerMsgStdout) })
	wg.Go(func() { pump(stderrPipe, WorkerMsgStderr) })

	// Wait for all I/O goroutines to complete, then collect the exit status.
	wg.Wait()

	exitCode := 0
	errStr := ""
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
			errStr = err.Error()
		}
	}

	return enc.send(WorkerMsg{ID: id, Type: WorkerMsgDone, ExitCode: exitCode, Error: errStr})
}
