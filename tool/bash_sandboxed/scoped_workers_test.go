package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/os_sandbox"
)

func denyHas(entries []os_sandbox.DenyPath, p string) bool {
	for _, e := range entries {
		if e.Path == p {
			return true
		}
	}
	return false
}

// TestWorkerOptions_ScopedGrant: the shared worker hides a scoped path in
// allowlist mode too (where the built-in deny lists are unused), and the
// scope's worker binds it instead.
func TestWorkerOptions_ScopedGrant(t *testing.T) {
	creds := t.TempDir()
	yes := true
	s := NewSandbox()
	s.updateConfig(&config.Config{
		OSSandbox: &yes,
		Paths:     []config.PathEntry{{Path: creds, Read: &yes, Internal: true, Commands: []string{"gh"}}},
	}, t.TempDir())
	cfg := s.getConfig()

	shared := s.workerOptions(cfg)
	if !denyHas(shared.DeniedReadPaths, creds) {
		t.Errorf("shared worker does not hide %s: %v", creds, shared.DeniedReadPaths)
	}
	if slices.Contains(shared.ROBinds, creds) {
		t.Errorf("shared worker binds %s", creds)
	}

	scope, _, ok := s.commandScope("gh")
	if !ok {
		t.Fatal("no scope for gh")
	}
	own := s.workerOptions(cfg.ForScope(scope))
	if denyHas(own.DeniedReadPaths, creds) {
		t.Errorf("gh's worker hides %s", creds)
	}
	if !slices.Contains(own.ROBinds, creds) {
		t.Errorf("gh's worker does not bind %s: %v", creds, own.ROBinds)
	}
	for _, name := range []string{"/usr/bin/gh", "./gh", "git"} {
		if s.isScopedCommand(name) {
			t.Errorf("commandScope(%q) matched", name)
		}
	}
}

func TestAgentWritableDir(t *testing.T) {
	// Synthetic paths, outside the temp roots: macOS leaves /var/folders
	// (where t.TempDir lives) writable, which would mask what is tested.
	work := "/ls-test/work"
	bind := "/ls-test/bind"
	opts := os_sandbox.WorkerOptions{WorkDir: work, ExtraBinds: []string{bind}}
	cases := map[string]bool{
		filepath.Join(work, "bin", "gh"): true,
		filepath.Join(bind, "gh"):        true,
		work + "-sibling/gh":             false,
		"/usr/bin/gh":                    false,
	}
	for p, want := range cases {
		if got := agentWritableDir(p, opts) != ""; got != want {
			t.Errorf("agentWritableDir(%q) writable = %v, want %v", p, got, want)
		}
	}

	home := "/ls-test/home"
	t.Setenv("HOME", home)
	opts = os_sandbox.WorkerOptions{WorkDir: work, HomeWritable: true,
		DeniedWritePaths: []os_sandbox.DenyPath{{Path: filepath.Join(home, ".local", "bin"), Dir: true}}}
	if agentWritableDir(filepath.Join(home, "go", "bin", "gh"), opts) == "" {
		t.Error("denylist mode: a binary under the writable home was not reported")
	}
	if dir := agentWritableDir(filepath.Join(home, ".local", "bin", "gh"), opts); dir != "" {
		t.Errorf("denylist mode: a binary under a write-denied path reported writable through %s", dir)
	}
	if runtime.GOOS == "darwin" {
		if agentWritableDir("/private/var/folders/x/T/gh", os_sandbox.WorkerOptions{WorkDir: work}) == "" {
			t.Error("macOS: a binary under /private/var/folders was not reported")
		}
	}
}

// TestScopedBinary_RefusesAgentWritable: the scoped command resolves on the
// server's PATH, a binary the agent could have written is refused, and the
// unresolved path is what runs (a shim keeps the name it was invoked by).
func TestScopedBinary_RefusesAgentWritable(t *testing.T) {
	work := t.TempDir()
	safe := t.TempDir()
	target := t.TempDir()
	for _, dir := range []string{work, target} {
		if err := os.WriteFile(filepath.Join(dir, "credtool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(target, "credtool"), filepath.Join(safe, "credtool")); err != nil {
		t.Fatal(err)
	}
	writableUnder := func(dirs ...string) func(string) string {
		return func(p string) string {
			for _, d := range dirs {
				if underAny(p, d) {
					return d
				}
			}
			return ""
		}
	}

	t.Setenv("PATH", work+string(os.PathListSeparator)+safe)
	if _, err := scopedBinary("credtool", writableUnder(work)); err == nil || !strings.Contains(err.Error(), "can write") {
		t.Errorf("binary in the working directory: err = %v, want a refusal", err)
	}

	t.Setenv("PATH", safe)
	if _, err := scopedBinary("credtool", writableUnder(target)); err == nil {
		t.Error("a link to a writable target was accepted")
	}
	got, err := scopedBinary("credtool", writableUnder(work))
	if err != nil {
		t.Fatalf("binary outside the writable paths: %v", err)
	}
	if want := filepath.Join(safe, "credtool"); got != want {
		t.Errorf("scopedBinary = %q, want the unresolved %q", got, want)
	}
}

func TestSafePath(t *testing.T) {
	work := t.TempDir()
	writable := func(p string) string {
		if underAny(p, work) {
			return work
		}
		return ""
	}
	sep := string(os.PathListSeparator)
	in := strings.Join([]string{filepath.Join(work, "bin"), "/usr/bin", "relative/bin", "", "/bin"}, sep)
	if got, want := safePath(in, writable), "/usr/bin"+sep+"/bin"; got != want {
		t.Errorf("safePath = %q, want %q", got, want)
	}
}

// TestOSSandboxScopedGrant runs a credential-reading CLI end to end: it reads
// its credential in its own worker, while the shared worker hides it — from
// a program the agent runs, and from the same CLI launched by that program.
func TestOSSandboxScopedGrant(t *testing.T) {
	requireOSSandbox(t)
	work := t.TempDir()

	// The credential and the CLI live under the real home: outside the
	// working directory and the writable paths (so the binary passes
	// scopedBinary), and outside /tmp, which the Linux worker overlays.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, "ls-scoped-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	creds := filepath.Join(root, "creds")
	bin := filepath.Join(root, "bin")
	for _, d := range []string{creds, bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	secret := filepath.Join(creds, "token")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// credtool prints the token, whatever AGENT_VAR it was given, and its
	// PATH.
	script := "#!/bin/sh\ncat " + secret + "\necho \"agent_var=$AGENT_VAR\"\necho \"path=$PATH\"\n"
	if err := os.WriteFile(filepath.Join(bin, "credtool"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	// The working directory on the server's PATH: the CLI must not get it.
	t.Setenv("PATH", bin+string(os.PathListSeparator)+work+string(os.PathListSeparator)+os.Getenv("PATH"))

	yes := true
	s := NewSandbox()
	s.updateConfig(&config.Config{
		OSSandbox: &yes,
		Commands: []config.CommandEntry{
			{Command: "credtool show", Allow: &yes}, // validated: goes through the exec handler
			{Command: "bash", Allow: &yes},          // raw: stands in for a program the agent wrote
		},
		Paths: []config.PathEntry{{Path: creds, Read: &yes, Internal: true, Commands: []string{"credtool"}}},
	}, work)
	defer s.Close()
	paths := []string{work}
	run := func(cmd string) (string, error) {
		return s.Execute(context.Background(), cmd, work, paths, paths)
	}

	out, err := run("export AGENT_VAR=leak; credtool show")
	if err != nil {
		t.Fatalf("credtool in its own worker: %v\n%s", err, out)
	}
	if !strings.Contains(out, "s3cret") {
		t.Errorf("credtool did not read its credential: %q", out)
	}
	if strings.Contains(out, "leak") {
		t.Errorf("credtool was given the agent's variable: %q", out)
	}
	if strings.Contains(out, work) {
		t.Errorf("credtool's PATH kept the working directory: %q", out)
	}

	for _, cmd := range []string{
		"bash -c 'cat " + secret + "'", // a program the agent runs
		"bash -c 'credtool show'",      // the CLI, launched by that program
		"bash -c 'ls " + creds + "'",   // the directory itself
	} {
		// Masked: EACCES for a regular user, an empty directory for root.
		if out, _ := run(cmd); strings.Contains(out, "s3cret") {
			t.Errorf("%s: shared worker did not hide the credential: %q", cmd, out)
		}
	}
}

// TestOSSandboxScopedWorkerIdleTTL: a scoped worker closes once idle for the
// TTL, and the next command starts a new one.
func TestOSSandboxScopedWorkerIdleTTL(t *testing.T) {
	requireOSSandbox(t)
	old := scopedWorkerIdleTTL
	scopedWorkerIdleTTL = 200 * time.Millisecond
	t.Cleanup(func() { scopedWorkerIdleTTL = old })

	work := t.TempDir()
	yes := true
	s := NewSandbox()
	s.updateConfig(&config.Config{
		OSSandbox: &yes,
		Paths:     []config.PathEntry{{Path: work + "-creds", Read: &yes, Internal: true, Commands: []string{"cat"}}},
	}, work)
	defer s.Close()
	if err := os.WriteFile(filepath.Join(work, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	live := func() int {
		s.mu.RLock()
		defer s.mu.RUnlock()
		return len(s.scopedWorkers)
	}
	for round := 0; round < 2; round++ {
		if out, err := s.Execute(context.Background(), "cat f", work, []string{work}, []string{work}); err != nil || out != "x" {
			t.Fatalf("round %d: cat f = %q, %v", round, out, err)
		}
		if n := live(); n != 1 {
			t.Fatalf("round %d: %d scoped workers after a command, want 1", round, n)
		}
		deadline := time.Now().Add(5 * time.Second)
		for live() != 0 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if n := live(); n != 0 {
			t.Fatalf("round %d: scoped worker still up after the idle TTL", round)
		}
	}
}
