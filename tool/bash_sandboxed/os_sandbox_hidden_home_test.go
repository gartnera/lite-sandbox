package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// newFakeRuntimeDir creates a runtime directory beside the fake home (outside
// it, and outside /tmp, which the worker overlays anyway), so it is hidden on
// its own account, and points $XDG_RUNTIME_DIR at it.
func newFakeRuntimeDir(t *testing.T, fakeHome string) string {
	t.Helper()
	dir, err := os.MkdirTemp(filepath.Dir(fakeHome), "ls-runtime-test-")
	if err != nil {
		t.Skipf("cannot create a runtime dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("XDG_RUNTIME_DIR", dir)
	return dir
}

// TestOSSandboxHidesHome exercises the hidden home end to end: code the
// worker runs (perl, through a bare allow, so no static check sees what it
// opens) cannot read what is in $HOME or the runtime directory, but still
// reads the project, a paths grant, git's config, and a toolchain installed
// under $HOME on the PATH. git's credential store stays hidden though its
// directory is shown, and os_sandbox_hide_home: false turns it all off.
func TestOSSandboxHidesHome(t *testing.T) {
	requireOSSandbox(t)
	home := newFakeHome(t)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(home, ".config", "lite-sandbox", "config.yaml"))

	runtimeDir := newFakeRuntimeDir(t, home)

	mustWrite := func(p, content string, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(filepath.Join(home, ".config/sometool/token"), "SECRET-TOKEN\n", 0o644)
	mustWrite(filepath.Join(home, ".config/git/config"), "[user]\n\tname = Tester\n", 0o644)
	mustWrite(filepath.Join(home, ".config/git/credentials"), "https://u:GIT-SECRET@example.com\n", 0o600)
	mustWrite(filepath.Join(home, "granted/data.txt"), "granted-data\n", 0o644)
	mustWrite(filepath.Join(runtimeDir, "keyring/control"), "RUNTIME-SECRET\n", 0o644)
	// A toolchain installed under $HOME: its bin/ is on PATH, and the program
	// reads its own installation beside it.
	tool := filepath.Join(home, ".mytool")
	mustWrite(filepath.Join(tool, "share/msg"), "tool-data\n", 0o644)
	mustWrite(filepath.Join(tool, "bin/mytool"), "#!/bin/sh\ncat \""+tool+"/share/msg\"\n", 0o755)
	t.Setenv("PATH", filepath.Join(tool, "bin")+string(os.PathListSeparator)+os.Getenv("PATH"))

	workDir := filepath.Join(home, "proj")
	mustWrite(filepath.Join(workDir, "README"), "project-file\n", 0o644)

	yes := true
	newSandbox := func(hide *bool) *Sandbox {
		s := NewSandbox()
		s.updateConfig(&config.Config{
			OSSandbox:         &yes,
			OSSandboxHideHome: hide,
			Commands: []config.CommandEntry{
				{Command: "perl", Allow: &yes},
				{Command: "mytool", Allow: &yes},
			},
			Paths: []config.PathEntry{{Path: filepath.Join(home, "granted"), Read: &yes, Internal: true}},
		}, workDir)
		t.Cleanup(func() { s.Close() })
		return s
	}
	read := func(s *Sandbox, path string) string {
		t.Helper()
		prog := `if (open(F,"<` + path + `")) { local $/; print "content=[".<F>."]" } else { print "denied: $!" }`
		out, _ := s.Execute(context.Background(), "perl -e '"+prog+"'", workDir, []string{workDir}, []string{workDir})
		return out
	}

	s := newSandbox(nil)
	for path, want := range map[string]string{
		filepath.Join(workDir, "README"):          "project-file",
		filepath.Join(home, "granted/data.txt"):   "granted-data",
		filepath.Join(home, ".config/git/config"): "name = Tester",
	} {
		if out := read(s, path); !strings.Contains(out, want) {
			t.Errorf("%s should be readable: %q", path, out)
		}
	}
	for path, secret := range map[string]string{
		filepath.Join(home, ".config/sometool/token"):  "SECRET-TOKEN",
		filepath.Join(home, ".config/git/credentials"): "GIT-SECRET",
		filepath.Join(runtimeDir, "keyring/control"):   "RUNTIME-SECRET",
	} {
		out := read(s, path)
		if strings.Contains(out, secret) {
			t.Errorf("%s leaked: %q", path, out)
		}
		if !osDenied(out) && !strings.Contains(out, "content=[]") {
			t.Errorf("%s should be denied, got %q", path, out)
		}
	}
	if out, err := s.Execute(context.Background(), "mytool", workDir, []string{workDir}, []string{workDir}); err != nil || !strings.Contains(out, "tool-data") {
		t.Errorf("a toolchain on PATH under $HOME should run: out=%q err=%v", out, err)
	}
	// $HOME stays read-only: nothing is created beside the grants.
	out, _ := s.Execute(context.Background(), `perl -e 'open(F,">`+home+`/planted") or die "denied: $!"; print "wrote"'`, workDir, []string{workDir}, []string{workDir})
	if strings.Contains(out, "wrote") {
		t.Errorf("hidden home should be read-only, got %q", out)
	}
	if _, err := os.Stat(filepath.Join(home, "planted")); err == nil {
		t.Error("a write in the hidden home reached the host")
	}

	off := false
	s = newSandbox(&off)
	if out := read(s, filepath.Join(home, ".config/sometool/token")); !strings.Contains(out, "SECRET-TOKEN") {
		t.Errorf("with os_sandbox_hide_home: false, $HOME should be readable: %q", out)
	}
}

// TestOSSandboxDenylistHidesRuntimeDir checks that denylist mode, whose home
// is writable and governed by its deny lists, still hides the runtime
// directory with its keyring and agent sockets.
func TestOSSandboxDenylistHidesRuntimeDir(t *testing.T) {
	requireOSSandbox(t)
	home := newFakeHome(t)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(home, ".cache"))
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(home, ".config", "lite-sandbox", "config.yaml"))
	runtimeDir := newFakeRuntimeDir(t, home)
	if err := os.WriteFile(filepath.Join(runtimeDir, "bus"), []byte("RUNTIME-SECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "notes.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	workDir := filepath.Join(home, "proj")
	if err := os.Mkdir(workDir, 0o755); err != nil {
		t.Fatal(err)
	}

	s := NewSandbox()
	on := true
	s.updateConfig(&config.Config{Mode: "denylist", OSSandbox: &on}, workDir)
	defer s.Close()
	run := func(path string) string {
		out, _ := s.Execute(context.Background(), `perl -e 'if (open(F,"<`+path+`")) { print "content=[".<F>."]" } else { print "denied: $!" }'`, workDir, []string{workDir}, []string{workDir})
		return out
	}
	if out := run(filepath.Join(home, "notes.txt")); !strings.Contains(out, "hello") {
		t.Errorf("denylist mode keeps $HOME readable: %q", out)
	}
	if out := run(filepath.Join(runtimeDir, "bus")); strings.Contains(out, "RUNTIME-SECRET") {
		t.Errorf("runtime dir leaked in denylist mode: %q", out)
	}
}
