package os_sandbox

import (
	"strings"
	"testing"
)

// bindTargetIndex returns the index into args of the target operand of a mount
// flag that binds/masks path. For --bind/--ro-bind the target is the operand
// after the source (e.g. `--bind <path> <path>` → the second <path>); for
// --tmpfs it is the single operand. Returns -1 if not found. When path appears
// more than once (a writable bind that is later masked), the LAST occurrence is
// returned, which is the one bwrap actually resolves.
func bindTargetIndex(t *testing.T, args []string, path string) int {
	t.Helper()
	idx := -1
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--bind", "--ro-bind":
			// flag src dst — the target is dst (i+2).
			if i+2 < len(args) && args[i+2] == path {
				idx = i + 2
			}
			i += 2
		case "--tmpfs":
			if i+1 < len(args) && args[i+1] == path {
				idx = i + 1
			}
			i++
		}
	}
	return idx
}

// TestBuildBwrapArgs_MasksAfterBinds is the regression test for the ordering
// bug: credential/socket masks must be emitted after every writable bind so a
// bind that overlaps a masked path (workDir under $HOME, writable_paths: ["~"])
// cannot re-expose the secret. bwrap applies mounts in order and the last
// overlapping mount wins, so "mask index > bind index" is exactly the property
// that keeps the secret hidden.
func TestBuildBwrapArgs_MasksAfterBinds(t *testing.T) {
	home := "/home/user"
	workDir := home // worst case: workDir IS $HOME, overlapping every mask
	sshKey := home + "/.ssh/id_rsa"
	awsDir := home + "/.aws"
	dockerSock := "/var/run/docker.sock"

	args := buildBwrapArgs(
		"/usr/bin/lite-sandbox",
		workDir,
		[]string{home}, // writable_paths: ["~"] binds $HOME writable
		[]string{home}, // internal_readable_paths: ["~"] also overlaps every mask
		[]string{sshKey},
		[]string{dockerSock},
		awsDir,
	)

	workDirIdx := bindTargetIndex(t, args, workDir)
	if workDirIdx < 0 {
		t.Fatalf("workDir bind not found in args: %v", args)
	}

	for _, mask := range []string{sshKey, awsDir, dockerSock} {
		maskIdx := bindTargetIndex(t, args, mask)
		if maskIdx < 0 {
			t.Fatalf("mask %q not found in args: %v", mask, args)
		}
		if maskIdx < workDirIdx {
			t.Errorf("mask %q (index %d) must come AFTER the workDir/$HOME bind (index %d); an earlier mask is overridden by the later bind, re-exposing the secret\nargs: %v",
				mask, maskIdx, workDirIdx, args)
		}
	}
}

// TestBuildBwrapArgs_Structure checks the invariant flags and terminal layout
// are present and correctly ordered.
func TestBuildBwrapArgs_Structure(t *testing.T) {
	self := "/usr/bin/lite-sandbox"
	args := buildBwrapArgs(self, "/work", nil, []string{"/data/cache"}, nil, nil, "")

	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--ro-bind / /",
		"--tmpfs /tmp",
		"--ro-bind /data/cache /data/cache",
		"--bind /work /work",
		"--dev /dev",
		"--proc /proc",
		"--unshare-all",
		"--share-net",
		"--die-with-parent",
		"--chdir /work",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected args to contain %q\nargs: %v", want, args)
		}
	}

	// The command to run must be the final two operands, after the "--".
	if n := len(args); n < 3 || args[n-2] != self || args[n-1] != "sandbox-worker" {
		t.Fatalf("expected args to end with %q sandbox-worker after --, got tail %v", self, args)
	}
	dashIdx := -1
	for i, a := range args {
		if a == "--" {
			dashIdx = i
		}
	}
	if dashIdx < 0 || dashIdx != len(args)-3 {
		t.Fatalf("expected `--` immediately before the worker command, args: %v", args)
	}
}

// TestBuildBwrapArgs_NoAWSWhenEmpty verifies an empty awsTmpfsDir emits no
// ~/.aws tmpfs (the caller passes "" when blocking is off or the dir is absent).
func TestBuildBwrapArgs_NoAWSWhenEmpty(t *testing.T) {
	args := buildBwrapArgs("/usr/bin/lite-sandbox", "/work", nil, nil, nil, nil, "")
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--tmpfs" && strings.HasSuffix(args[i+1], "/.aws") {
			t.Fatalf("did not expect a ~/.aws tmpfs with empty awsTmpfsDir, args: %v", args)
		}
	}
}
