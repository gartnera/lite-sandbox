package bash_sandboxed

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/os_sandbox"
)

// TestHostProgramDenies checks that a PATH directory inside a writable bind
// (GOPATH/bin inside the go profile's GOPATH grant) is write-denied, that one
// outside every bind or in the working directory is left alone, and that the
// server's own binary is denied wherever the worker could write it.
func TestHostProgramDenies(t *testing.T) {
	root := t.TempDir()
	gopath := filepath.Join(root, "go")
	work := filepath.Join(root, "work")
	for _, d := range []string{filepath.Join(gopath, "bin"), filepath.Join(work, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", filepath.Join(gopath, "bin")+string(filepath.ListSeparator)+filepath.Join(work, "bin")+string(filepath.ListSeparator)+"/usr/bin")

	opts := os_sandbox.WorkerOptions{WorkDir: work, ExtraBinds: []string{gopath}}
	got := hostProgramDenies(&config.Config{}, opts)
	if !slices.Contains(got, os_sandbox.DenyPath{Path: filepath.Join(gopath, "bin"), Dir: true}) {
		t.Errorf("GOPATH/bin is not write-denied: %v", got)
	}
	for _, d := range got {
		if d.Path == "/usr/bin" || d.Path == filepath.Join(work, "bin") {
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
