package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// newFakeHome creates a throwaway home directory under the REAL home and points
// $HOME at it. A t.TempDir() home would not do: on Linux the worker overlays
// /tmp with a tmpfs, and on macOS the profile always allows writes under
// /var/folders, so writes there would "succeed" without exercising the home
// bind — and on macOS they would reach the host regardless of mode.
func newFakeHome(t *testing.T) string {
	t.Helper()
	real, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory: %v", err)
	}
	home, err := os.MkdirTemp(real, "ls-denylist-test-")
	if err != nil {
		t.Skipf("cannot create a directory under %s: %v", real, err)
	}
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("HOME", home)
	return home
}

// osDenied reports whether a child process's error text is an OS-sandbox
// denial on either backend: EACCES/EROFS/ENOENT under bubblewrap's masks,
// EPERM ("Operation not permitted") under sandbox-exec.
func osDenied(out string) bool {
	for _, s := range []string{"Permission denied", "Read-only", "No such file", "Operation not permitted"} {
		if strings.Contains(out, s) {
			return true
		}
	}
	return false
}

// TestOSSandboxDenylistPosture exercises the denylist-mode worker layout end to
// end: a child process (perl, not on the whitelist, so only denylist mode lets
// it run) can write anywhere in $HOME except the write-denied paths, cannot
// read the read-denied paths, and still cannot write outside $HOME.
//
// $HOME is pointed at a temp dir so the built-in deny lists resolve there.
func TestOSSandboxDenylistPosture(t *testing.T) {
	requireOSSandbox(t)
	home := newFakeHome(t)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(home, ".config", "lite-sandbox", "config.yaml"))

	// Fixtures the deny lists cover: a read-denied directory, a read-denied
	// file, a write-denied file, plus an unrelated file to prove reads work.
	mustWrite := func(rel, content string) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(".aws/config", "[default]\nregion=us-east-1\n")
	mustWrite(".netrc", "machine x login y password z\n")
	mustWrite(".bashrc", "export X=1\n")
	mustWrite("notes.txt", "hello\n")
	workDir := filepath.Join(home, "proj")
	if err := os.Mkdir(workDir, 0o755); err != nil {
		t.Fatal(err)
	}

	s := NewSandbox()
	on := true
	s.UpdateConfig(&config.Config{Mode: "denylist", OSSandbox: &on}, workDir)
	defer s.Close()
	paths := []string{workDir}

	// perl runs an arbitrary program inside the worker; it is deliberately not
	// whitelisted so this only works because of denylist mode.
	run := func(prog string) (string, error) {
		return s.Execute(context.Background(), "perl -e '"+prog+"'", workDir, paths, paths)
	}
	// Reads elsewhere in $HOME work.
	out, err := run(`open(F,"<$ENV{HOME}/notes.txt") or die "denied: $!"; print <F>`)
	if err != nil || !strings.Contains(out, "hello") {
		t.Fatalf("plain read in home: out=%q err=%v", out, err)
	}

	// Writes in $HOME work (the point of denylist mode). The file must show up
	// on the host, which only happens through the writable home bind.
	out, err = run(`open(F,">$ENV{HOME}/.cache-of-some-tool") or die "denied: $!"; print F "x"; close F; print "wrote"`)
	if err != nil || !strings.Contains(out, "wrote") {
		t.Fatalf("write in home should succeed: out=%q err=%v", out, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".cache-of-some-tool")); err != nil {
		t.Errorf("write in home did not reach the host (landed in the /tmp tmpfs instead): %v", err)
	}

	// Read-denied directory and file are hidden (EACCES for a normal user, an
	// empty/missing view for root).
	out, _ = run(`if (open(F,"<$ENV{HOME}/.aws/config")) { local $/; my $c=<F>; print "content=[$c]" } else { print "denied: $!" }`)
	if !osDenied(out) && !strings.Contains(out, "content=[]") {
		t.Errorf("~/.aws/config should be hidden, got %q", out)
	}
	if strings.Contains(out, "region=") {
		t.Errorf("~/.aws/config content leaked: %q", out)
	}
	out, _ = run(`if (open(F,"<$ENV{HOME}/.netrc")) { local $/; my $c=<F>; print "content=[$c]" } else { print "denied: $!" }`)
	if strings.Contains(out, "password") {
		t.Errorf("~/.netrc content leaked: %q", out)
	}

	// Write-denied file stays readable but not writable.
	out, err = run(`open(F,"<$ENV{HOME}/.bashrc") or die "denied: $!"; print <F>`)
	if err != nil || !strings.Contains(out, "export X=1") {
		t.Fatalf("~/.bashrc should be readable: out=%q err=%v", out, err)
	}
	out, _ = run(`open(F,">>$ENV{HOME}/.bashrc") or die "denied: $!"; print F "evil"; close F; print "wrote"`)
	if !osDenied(out) || strings.Contains(out, "wrote") {
		t.Errorf("~/.bashrc should not be writable, got %q", out)
	}
	if data, _ := os.ReadFile(filepath.Join(home, ".bashrc")); strings.Contains(string(data), "evil") {
		t.Error("~/.bashrc was modified through the sandbox")
	}

	// Outside $HOME the root stays read-only.
	out, _ = run(`open(F,">/usr/lite-sandbox-test") or die "denied: $!"; print "wrote"`)
	if !osDenied(out) || strings.Contains(out, "wrote") {
		t.Errorf("/usr should be read-only, got %q", out)
	}
}

// TestOSSandboxAllowlistPostureUnchanged pins the allowlist-mode worker layout:
// $HOME is not writable even though the deny lists exist.
func TestOSSandboxAllowlistPostureUnchanged(t *testing.T) {
	requireOSSandbox(t)
	home := newFakeHome(t)
	workDir := filepath.Join(home, "proj")
	if err := os.Mkdir(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	s := NewSandbox()
	on := true
	s.UpdateConfig(&config.Config{Mode: "allowlist", OSSandbox: &on}, workDir)
	defer s.Close()

	// touch is whitelisted; the path is inside $HOME but outside workDir, so
	// widen the validator's write set to isolate the OS layer's decision. What
	// matters is that nothing reaches the host, which only a writable home
	// bind would allow.
	target := filepath.Join(home, "x")
	_, _ = s.Execute(context.Background(), "touch "+target, workDir, []string{home}, []string{home})
	if _, err := os.Stat(target); err == nil {
		t.Errorf("allowlist worker must not bind $HOME writable: %s was created on the host", target)
	}
}
