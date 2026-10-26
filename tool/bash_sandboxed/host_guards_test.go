package bash_sandboxed

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/os_sandbox"
)

// TestHostProgramDenies checks that a PATH directory up to lite-sandbox's
// inside a writable bind (GOPATH/bin inside the go profile's GOPATH grant) is
// write-denied, that one after lite-sandbox's (fvm's SDK bin), outside every
// bind, or in the working directory is left alone, and that the server's own
// binary is denied wherever the worker could write it.
func TestHostProgramDenies(t *testing.T) {
	root := t.TempDir()
	gopath := filepath.Join(root, "go")
	fvm := filepath.Join(root, "fvm")
	work := filepath.Join(root, "work")
	fvmBin := filepath.Join(fvm, "default", "bin")
	for _, d := range []string{filepath.Join(gopath, "bin"), filepath.Join(work, "bin"), fvmBin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(gopath, "bin", "lite-sandbox"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", strings.Join([]string{filepath.Join(work, "bin"), filepath.Join(gopath, "bin"), fvmBin, "/usr/bin"}, string(filepath.ListSeparator)))

	opts := os_sandbox.WorkerOptions{WorkDir: work, ExtraBinds: []string{gopath, fvm}}
	got := hostProgramDenies(&config.Config{}, opts)
	if !slices.Contains(got, os_sandbox.DenyPath{Path: filepath.Join(gopath, "bin"), Dir: true}) {
		t.Errorf("GOPATH/bin is not write-denied: %v", got)
	}
	for _, d := range got {
		if d.Path == "/usr/bin" || d.Path == filepath.Join(work, "bin") || d.Path == fvmBin {
			t.Errorf("unexpected denial of %s", d.Path)
		}
	}

	// The test binary stands in for the server's: bind its directory.
	exe, err := os.Executable()
	if err != nil {
		t.Skip(err)
	}
	opts.ExtraBinds = append(opts.ExtraBinds, filepath.Dir(exe))
	got = hostProgramDenies(&config.Config{}, opts)
	if !slices.Contains(got, os_sandbox.DenyPath{Path: exe}) {
		t.Errorf("server binary is not write-denied: %v", got)
	}
}

// TestGuardHostEnv checks that the worker's environment leaves out the
// agent's token when the OS sandbox is on.
func TestGuardHostEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "sk-secret")
	on := true
	var opts os_sandbox.WorkerOptions
	guardHost(&config.Config{OSSandbox: &on}, &opts)
	if opts.Env == nil {
		t.Fatal("worker env not set")
	}
	for _, kv := range opts.Env {
		if kv == "ANTHROPIC_AUTH_TOKEN=sk-secret" {
			t.Error("worker env carries ANTHROPIC_AUTH_TOKEN")
		}
	}
}
