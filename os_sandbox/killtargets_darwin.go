//go:build darwin

package os_sandbox

import "golang.org/x/sys/unix"

// killTargets returns pid followed by all of its transitive children. On macOS
// every sandboxed command shares the worker's process group (setProcGroup is a
// no-op there, because the seatbelt profile forbids signaling a separate
// group), so a process-group kill cannot single out one command's subtree.
// Instead we snapshot the process table and collect the descendants of pid;
// each shares the worker's group, which the seatbelt allows us to signal
// individually.
//
// The tree is captured while the leader is still alive — once it exits, its
// children reparent to launchd and would no longer trace back to pid — so the
// caller reuses this snapshot for the later force-kill rather than re-deriving
// it (see procRegistry.kill).
func killTargets(pid int) []int {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return []int{pid}
	}

	// Build a parent -> children adjacency map from the process table.
	children := make(map[int][]int, len(procs))
	for i := range procs {
		cpid := int(procs[i].Proc.P_pid)
		ppid := int(procs[i].Eproc.Ppid)
		if cpid > 0 {
			children[ppid] = append(children[ppid], cpid)
		}
	}

	// Breadth-first walk from pid, collecting every descendant. The process
	// table is a tree (each process has one parent), so this terminates.
	targets := []int{pid}
	for i := 0; i < len(targets); i++ {
		targets = append(targets, children[targets[i]]...)
	}
	return targets
}
