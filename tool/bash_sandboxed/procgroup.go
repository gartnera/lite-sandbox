package bash_sandboxed

import (
	"os/exec"
	"syscall"
	"time"
)

// gracefulKillTimeout is how long a background process is given to exit after a
// SIGTERM before its whole process group is forcibly SIGKILLed.
const gracefulKillTimeout = 3 * time.Second

// setProcessGroup makes cmd lead its own process group so its entire subtree
// (including processes it forks) can be signaled at once via the group.
//
// Unlike the OS-sandbox worker, the host has no seatbelt signal restriction, so
// this is safe on every supported (unix) platform.
func setProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// terminateProcessGroup sends SIGTERM to the process group led by cmd (and to
// the process directly as a fallback), asking it to shut down cleanly.
func terminateProcessGroup(cmd *exec.Cmd) {
	signalProcessGroup(cmd, syscall.SIGTERM)
}

// killProcessGroup SIGKILLs the process group led by cmd, force-terminating any
// survivors of an earlier SIGTERM.
func killProcessGroup(cmd *exec.Cmd) {
	signalProcessGroup(cmd, syscall.SIGKILL)
}

// signalProcessGroup sends sig to the group led by cmd (negative pid) and to the
// direct process. Safe to call when the process has not started or has exited.
func signalProcessGroup(cmd *exec.Cmd, sig syscall.Signal) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, sig)
	_ = cmd.Process.Signal(sig)
}
