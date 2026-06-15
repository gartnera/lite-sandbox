//go:build linux

package os_sandbox

// killTargets returns the targets to signal to tear down the command led by
// pid. On Linux each command leads its own process group (see setProcGroup), so
// signaling the group (the negative pid) reaches every process the command
// forked in one call; the leader pid itself is included as a fallback in case
// the group setup did not take effect.
func killTargets(pid int) []int {
	return []int{-pid, pid}
}
