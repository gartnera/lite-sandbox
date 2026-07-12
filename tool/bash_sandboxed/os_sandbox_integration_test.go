package bash_sandboxed

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
)

// TestOSSandboxBasicExecution tests that OS sandbox can execute basic commands.
func TestOSSandboxBasicExecution(t *testing.T) {
	requireOSSandbox(t)
	// Create a temporary directory for testing
	tmpDir := t.TempDir()

	s := NewSandbox()

	// Enable OS sandbox
	enabled := true
	cfg := &config.Config{
		OSSandbox: &enabled,
	}
	s.UpdateConfig(cfg, tmpDir)
	defer s.Close()

	// Run a real external command (cat) so the execution actually routes through
	// the sandbox worker. A shell builtin like echo would never reach it.
	srcFile := filepath.Join(tmpDir, "hello.txt")
	if err := os.WriteFile(srcFile, []byte("hello\n"), 0644); err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}

	output, err := s.Execute(context.Background(), "cat "+srcFile, tmpDir, []string{tmpDir}, []string{tmpDir})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if output != "hello\n" {
		t.Errorf("unexpected output: got %q, want %q", output, "hello\n")
	}
}

// TestOSSandboxFileIsolation tests that OS sandbox provides read-only root.
func TestOSSandboxFileIsolation(t *testing.T) {
	requireOSSandbox(t)
	tmpDir := t.TempDir()

	s := NewSandbox()

	enabled := true
	cfg := &config.Config{
		OSSandbox: &enabled,
	}
	s.UpdateConfig(cfg, tmpDir)
	defer s.Close()

	// Try to write outside workdir - should fail
	// Use /usr/testfile on macOS, /root/testfile on Linux
	restrictedPath := "/root/testfile"
	if runtime.GOOS == "darwin" {
		restrictedPath = "/usr/testfile"
	}
	output, err := s.Execute(context.Background(), "touch "+restrictedPath, tmpDir, []string{tmpDir}, []string{tmpDir})
	if err == nil {
		t.Errorf("expected error when writing to %s, got success. output: %s", restrictedPath, output)
	}

	// Try to write inside workdir - should succeed
	testFile := filepath.Join(tmpDir, "testfile")
	_, err = s.Execute(context.Background(), "touch "+testFile, tmpDir, []string{tmpDir}, []string{tmpDir})
	if err != nil {
		t.Errorf("expected success when writing to workdir, got error: %v", err)
	}

	// Verify file was created
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Error("expected file to exist in workdir")
	}
}

// TestOSSandboxWorkerPool tests that multiple workers can execute concurrently.
func TestOSSandboxWorkerPool(t *testing.T) {
	requireOSSandbox(t)
	tmpDir := t.TempDir()

	s := NewSandbox()

	enabled := true
	cfg := &config.Config{
		OSSandbox: &enabled,
	}
	s.UpdateConfig(cfg, tmpDir)
	defer s.Close()

	// Run a real external command (cat) concurrently so each execution actually
	// routes through the sandbox worker pool.
	srcFile := filepath.Join(tmpDir, "test.txt")
	if err := os.WriteFile(srcFile, []byte("test\n"), 0644); err != nil {
		t.Fatalf("failed to write source file: %v", err)
	}

	// Execute multiple commands concurrently
	type result struct {
		output string
		err    error
	}
	results := make(chan result, 5)

	for i := 0; i < 5; i++ {
		go func(n int) {
			output, err := s.Execute(context.Background(), "cat "+srcFile, tmpDir, []string{tmpDir}, []string{tmpDir})
			results <- result{output, err}
		}(i)
	}

	// Collect results
	for i := 0; i < 5; i++ {
		r := <-results
		if r.err != nil {
			t.Errorf("concurrent execute %d failed: %v", i, r.err)
		}
		if r.output != "test\n" {
			t.Errorf("concurrent execute %d unexpected output: got %q, want %q", i, r.output, "test\n")
		}
	}
}

// TestOSSandboxBareExtraCommandConfined verifies that a bare extra_commands
// entry — which bypasses AST parsing and validation entirely — still executes
// inside the OS sandbox worker when the OS sandbox is enabled: the real bash
// runs (accepting syntax the AST validator would reject), writes inside the
// working directory succeed, and writes outside it are blocked.
func TestOSSandboxBareExtraCommandConfined(t *testing.T) {
	requireOSSandbox(t)
	tmpDir := t.TempDir()

	s := NewSandbox()
	enabled := true
	cfg := &config.Config{
		OSSandbox:     &enabled,
		ExtraCommands: []string{"bash"},
	}
	s.UpdateConfig(cfg, tmpDir)
	defer s.Close()

	// Process substitution would be rejected by the AST validator; it only
	// works because the bare entry routes the whole string to the real bash.
	output, err := s.Execute(context.Background(), `bash -c 'cat <(echo raw-ok)'`, tmpDir, []string{tmpDir}, []string{tmpDir})
	if err != nil {
		t.Fatalf("bare extra command failed: %v, output: %s", err, output)
	}
	if !strings.Contains(output, "raw-ok") {
		t.Errorf("unexpected output: got %q, want it to contain %q", output, "raw-ok")
	}

	// Writes inside the working directory succeed and are visible on the host.
	insideFile := filepath.Join(tmpDir, "inside.txt")
	if _, err := s.Execute(context.Background(), "bash -c 'touch "+insideFile+"'", tmpDir, []string{tmpDir}, []string{tmpDir}); err != nil {
		t.Errorf("expected write inside workdir to succeed, got error: %v", err)
	}
	if _, err := os.Stat(insideFile); os.IsNotExist(err) {
		t.Error("expected file to exist in workdir")
	}

	// Writes outside the working directory are blocked by the OS sandbox even
	// though no validation ran.
	restrictedPath := "/root/testfile"
	if runtime.GOOS == "darwin" {
		restrictedPath = "/usr/testfile"
	}
	output, err = s.Execute(context.Background(), "bash -c 'touch "+restrictedPath+"'", tmpDir, []string{tmpDir}, []string{tmpDir})
	if err == nil {
		t.Errorf("expected error when writing to %s, got success. output: %s", restrictedPath, output)
	}
}

// TestOSSandboxUnsandboxedCommandEscapes verifies that an unsandboxed_commands
// entry runs directly on the host even when the OS sandbox is enabled: a write
// outside the working directory (into the user's home, which the sandbox mounts
// read-only) succeeds, whereas the same command allowed via extra_commands is
// confined and fails. This is the defining difference between the two lists.
func TestOSSandboxUnsandboxedCommandEscapes(t *testing.T) {
	requireOSSandbox(t)
	tmpDir := t.TempDir()

	// A host-writable location outside the working directory and outside the
	// temp roots the sandbox profile permits (/tmp, /var/folders). The user's
	// home is writable on the host but read-only inside the OS sandbox.
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("failed to get home dir: %v", err)
	}
	outsideDir, err := os.MkdirTemp(home, "ls-unsandboxed-test-")
	if err != nil {
		t.Fatalf("failed to create outside dir: %v", err)
	}
	defer os.RemoveAll(outsideDir)
	outsideFile := filepath.Join(outsideDir, "escaped.txt")

	enabled := true

	// Control: as a bare extra_commands entry the write is confined and fails.
	confined := NewSandbox()
	confined.UpdateConfig(&config.Config{OSSandbox: &enabled, ExtraCommands: []string{"bash"}}, tmpDir)
	defer confined.Close()
	if output, err := confined.Execute(context.Background(), "bash -c 'touch "+outsideFile+"'", tmpDir, []string{tmpDir}, []string{tmpDir}); err == nil {
		t.Errorf("expected confined write outside workdir to fail, got success. output: %s", output)
	}
	if _, err := os.Stat(outsideFile); err == nil {
		t.Fatalf("confined command unexpectedly created %s", outsideFile)
	}

	// Unsandboxed: the same command runs on the host and the write succeeds.
	s := NewSandbox()
	s.UpdateConfig(&config.Config{OSSandbox: &enabled, UnsandboxedCommands: []string{"bash"}}, tmpDir)
	defer s.Close()
	if output, err := s.Execute(context.Background(), "bash -c 'touch "+outsideFile+"'", tmpDir, []string{tmpDir}, []string{tmpDir}); err != nil {
		t.Fatalf("expected unsandboxed write outside workdir to succeed, got error: %v, output: %s", err, output)
	}
	if _, err := os.Stat(outsideFile); err != nil {
		t.Errorf("expected unsandboxed command to create %s on the host, stat error: %v", outsideFile, err)
	}
}

// TestOSSandboxBackgroundBareExtraCommandConfined verifies the background raw
// path for bare extra_commands is likewise confined by the OS sandbox.
func TestOSSandboxBackgroundBareExtraCommandConfined(t *testing.T) {
	requireOSSandbox(t)
	tmpDir := t.TempDir()

	s := NewSandbox()
	enabled := true
	cfg := &config.Config{
		OSSandbox:     &enabled,
		ExtraCommands: []string{"bash"},
	}
	s.UpdateConfig(cfg, tmpDir)
	defer s.Close()

	restrictedPath := "/root/testfile"
	if runtime.GOOS == "darwin" {
		restrictedPath = "/usr/testfile"
	}

	proc, err := s.ExecuteBackground("bash -c 'touch "+restrictedPath+"'", tmpDir, []string{tmpDir}, []string{tmpDir})
	if err != nil {
		t.Fatalf("ExecuteBackground failed: %v", err)
	}
	if st := waitForStatus(t, proc, 15*time.Second, "completed", "failed"); st != "failed" {
		t.Fatalf("expected background write outside workdir to fail, got status %q", st)
	}
}

// TestOSSandboxGoRuntime tests that Go build, test, and install work in OS sandbox.
func TestOSSandboxGoRuntime(t *testing.T) {
	requireOSSandbox(t)
	tmpDir := t.TempDir()

	s := NewSandbox()

	// Enable OS sandbox and Go runtime
	enabled := true
	goEnabled := true
	cfg := &config.Config{
		OSSandbox: &enabled,
		Runtimes: &config.RuntimesConfig{
			Go: &config.GoConfig{
				Enabled: &goEnabled,
			},
		},
	}
	s.UpdateConfig(cfg, tmpDir)
	defer s.Close()

	// Create a simple Go module
	mainGo := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(mainGo, []byte(`package main

import "fmt"

func main() {
	fmt.Println("hello from sandbox")
}

func Add(a, b int) int {
	return a + b
}
`), 0644); err != nil {
		t.Fatalf("failed to write main.go: %v", err)
	}

	// Create a test file
	mainTestGo := filepath.Join(tmpDir, "main_test.go")
	if err := os.WriteFile(mainTestGo, []byte(`package main

import "testing"

func TestAdd(t *testing.T) {
	result := Add(2, 3)
	if result != 5 {
		t.Errorf("Add(2, 3) = %d, want 5", result)
	}
}
`), 0644); err != nil {
		t.Fatalf("failed to write main_test.go: %v", err)
	}

	// Initialize go module
	goMod := filepath.Join(tmpDir, "go.mod")
	if err := os.WriteFile(goMod, []byte(`module example.com/test

go 1.21
`), 0644); err != nil {
		t.Fatalf("failed to write go.mod: %v", err)
	}

	// Test go build
	t.Run("go build", func(t *testing.T) {
		output, err := s.Execute(context.Background(), "go build -o testbin", tmpDir, []string{tmpDir}, []string{tmpDir})
		if err != nil {
			t.Fatalf("go build failed: %v, output: %s", err, output)
		}

		// Verify binary was created
		binPath := filepath.Join(tmpDir, "testbin")
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			t.Error("expected binary to exist after go build")
		}
	})

	// Test go test
	t.Run("go test", func(t *testing.T) {
		output, err := s.Execute(context.Background(), "go test -v", tmpDir, []string{tmpDir}, []string{tmpDir})
		if err != nil {
			t.Fatalf("go test failed: %v, output: %s", err, output)
		}

		// Check that test passed
		if !contains(output, "PASS") {
			t.Errorf("expected PASS in test output, got: %s", output)
		}
	})

	// Test go install to custom GOBIN within tmpDir
	t.Run("go install with custom GOBIN", func(t *testing.T) {
		binDir := filepath.Join(tmpDir, "bin")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			t.Fatalf("failed to create bin dir: %v", err)
		}

		cmd := "GOBIN=" + binDir + " go install"
		output, err := s.Execute(context.Background(), cmd, tmpDir, []string{tmpDir}, []string{tmpDir})
		if err != nil {
			t.Fatalf("go install failed: %v, output: %s", err, output)
		}

		// Verify binary was installed
		installedBin := filepath.Join(binDir, "test")
		if _, err := os.Stat(installedBin); os.IsNotExist(err) {
			t.Error("expected binary to exist after go install")
		}
	})

	// Test go install to default GOPATH/bin (tests that GOPATH is writable)
	t.Run("go install to default GOPATH", func(t *testing.T) {
		// Get GOPATH from go env
		cmd := exec.Command("go", "env", "GOPATH")
		output, err := cmd.Output()
		if err != nil {
			t.Skipf("failed to get GOPATH: %v", err)
		}
		gopath := strings.TrimSpace(string(output))
		if gopath == "" {
			t.Skip("GOPATH is not set")
		}

		defaultBinPath := filepath.Join(gopath, "bin", "test")

		// Remove the binary if it exists from a previous run
		os.Remove(defaultBinPath)

		// Install without specifying GOBIN (should use default GOPATH/bin)
		output2, err := s.Execute(context.Background(), "go install", tmpDir, []string{tmpDir}, []string{tmpDir})
		if err != nil {
			t.Fatalf("go install to default GOPATH failed: %v, output: %s", err, output2)
		}

		// Verify binary was installed to GOPATH/bin
		if _, err := os.Stat(defaultBinPath); os.IsNotExist(err) {
			t.Errorf("expected binary to exist at %s after go install", defaultBinPath)
		}

		// Clean up
		os.Remove(defaultBinPath)
	})
}

// TestOSSandboxUvRuntime verifies the uv runtime works end-to-end under the OS
// sandbox: uv's detected paths (cache, python, tool dirs) are bound writable, so
// creating a venv and running code that populates the cache both succeed even
// though those paths live outside the working directory.
func TestOSSandboxUvRuntime(t *testing.T) {
	requireOSSandbox(t)
	if _, err := exec.LookPath("uv"); err != nil {
		t.Skip("uv not installed")
	}
	tmpDir := t.TempDir()

	s := NewSandbox()

	enabled := true
	uvEnabled := true
	cfg := &config.Config{
		OSSandbox: &enabled,
		Runtimes: &config.RuntimesConfig{
			Uv: &config.UvConfig{
				Enabled: &uvEnabled,
			},
		},
	}
	s.UpdateConfig(cfg, tmpDir)
	defer s.Close()

	// uv venv writes the virtual environment into the working directory and
	// exercises uv executing under the sandbox. Pin to the host python so no
	// interpreter download is attempted.
	t.Run("uv venv", func(t *testing.T) {
		output, err := s.Execute(context.Background(), "uv venv --python python3", tmpDir, []string{tmpDir}, []string{tmpDir})
		if err != nil {
			t.Fatalf("uv venv failed: %v, output: %s", err, output)
		}
		if _, err := os.Stat(filepath.Join(tmpDir, ".venv")); os.IsNotExist(err) {
			t.Error("expected .venv to exist after uv venv")
		}
	})

	// uv run populates uv's cache (outside the working directory). If the cache
	// dir were not bound writable, uv would fail with a permission error, so a
	// successful run proves the runtime path binding works.
	t.Run("uv run populates cache", func(t *testing.T) {
		cmd := `uv run --no-project --python python3 python -c "print('hello from uv')"`
		output, err := s.Execute(context.Background(), cmd, tmpDir, []string{tmpDir}, []string{tmpDir})
		if err != nil {
			t.Fatalf("uv run failed: %v, output: %s", err, output)
		}
		if !contains(output, "hello from uv") {
			t.Errorf("expected greeting in output, got: %s", output)
		}
	})

	// uv tool install places a launcher on the user's PATH (`uv tool dir --bin`,
	// default ~/.local/bin), which is deliberately NOT bound writable: installing
	// executables that persist and run outside the sandbox is exactly what the
	// boundary must prevent. The install must therefore fail and leave no
	// launcher behind. Build a trivial local package so the failure is the bin
	// write, not a missing build backend.
	t.Run("uv tool install cannot escape to PATH", func(t *testing.T) {
		binOut, err := exec.Command("uv", "tool", "dir", "--bin").Output()
		if err != nil {
			t.Skipf("failed to resolve uv tool bin dir: %v", err)
		}
		launcher := filepath.Join(strings.TrimSpace(string(binOut)), "greeter")
		os.Remove(launcher)

		pkgDir := filepath.Join(tmpDir, "greeter")
		if err := os.MkdirAll(filepath.Join(pkgDir, "src", "greeter"), 0755); err != nil {
			t.Fatalf("failed to create package dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "pyproject.toml"), []byte(`[project]
name = "greeter"
version = "0.1.0"

[project.scripts]
greeter = "greeter:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
`), 0644); err != nil {
			t.Fatalf("failed to write pyproject.toml: %v", err)
		}
		if err := os.WriteFile(filepath.Join(pkgDir, "src", "greeter", "__init__.py"), []byte(`def main():
    print("greeter installed")
`), 0644); err != nil {
			t.Fatalf("failed to write __init__.py: %v", err)
		}

		cmd := "uv tool install --python python3 " + pkgDir
		output, execErr := s.Execute(context.Background(), cmd, tmpDir, []string{tmpDir}, []string{tmpDir})
		if execErr == nil {
			t.Fatalf("expected uv tool install to fail (bin dir not writable), got success. output: %s", output)
		}
		if _, statErr := os.Stat(launcher); statErr == nil {
			os.Remove(launcher)
			t.Errorf("launcher escaped the sandbox to %s", launcher)
		}
	})
}
