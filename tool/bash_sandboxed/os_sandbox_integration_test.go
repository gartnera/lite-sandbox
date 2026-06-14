package bash_sandboxed

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

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
