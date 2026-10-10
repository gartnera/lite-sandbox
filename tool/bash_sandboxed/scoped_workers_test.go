package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
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

	scope, ok := s.commandScope("gh")
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
		if _, ok := s.commandScope(name); ok {
			t.Errorf("commandScope(%q) matched", name)
		}
	}
}

func TestAgentWritableDir(t *testing.T) {
	work := t.TempDir()
	bind := t.TempDir()
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

	home := t.TempDir()
	t.Setenv("HOME", home)
	opts = os_sandbox.WorkerOptions{WorkDir: work, HomeWritable: true,
		DeniedWritePaths: []os_sandbox.DenyPath{{Path: filepath.Join(home, ".local", "bin"), Dir: true}}}
	if agentWritableDir(filepath.Join(home, "go", "bin", "gh"), opts) == "" {
		t.Error("denylist mode: a binary under the writable home was not reported")
	}
	if dir := agentWritableDir(filepath.Join(home, ".local", "bin", "gh"), opts); dir != "" {
		t.Errorf("denylist mode: a binary under a write-denied path reported writable through %s", dir)
	}
}

// TestScopedBinary_RefusesAgentWritable: the scoped command resolves on the
// server's PATH, and a binary the agent could have written is refused.
func TestScopedBinary_RefusesAgentWritable(t *testing.T) {
	work := t.TempDir()
	safe := t.TempDir()
	for _, dir := range []string{work, safe} {
		if err := os.WriteFile(filepath.Join(dir, "credtool"), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	yes := true
	s := NewSandbox()
	s.updateConfig(&config.Config{
		OSSandbox: &yes,
		Paths:     []config.PathEntry{{Path: "/creds", Read: &yes, Internal: true, Commands: []string{"credtool"}}},
	}, work)

	t.Setenv("PATH", work+string(os.PathListSeparator)+safe)
	if _, err := s.scopedBinary("credtool"); err == nil || !strings.Contains(err.Error(), "can write") {
		t.Errorf("binary in the working directory: err = %v, want a refusal", err)
	}

	t.Setenv("PATH", safe)
	got, err := s.scopedBinary("credtool")
	if err != nil {
		t.Fatalf("binary outside the writable paths: %v", err)
	}
	want, _ := filepath.EvalSymlinks(filepath.Join(safe, "credtool"))
	if got != want {
		t.Errorf("scopedBinary = %q, want %q", got, want)
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
	// credtool prints the token and whatever AGENT_VAR it was given.
	script := "#!/bin/sh\ncat " + secret + "\necho \"agent_var=$AGENT_VAR\"\n"
	if err := os.WriteFile(filepath.Join(bin, "credtool"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

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
