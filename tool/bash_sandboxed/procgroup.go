package bash_sandboxed

import (
	"os/exec"
	"syscall"
)

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

// killProcessGroup SIGKILLs the process group led by cmd (negative pid), then
// the direct process as a fallback. Safe to call when the process has not
// started or has already exited.
func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	return cmd.Process.Kill()
}
