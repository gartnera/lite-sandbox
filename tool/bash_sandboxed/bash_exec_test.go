package bash_sandboxed

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// executeInDirWithSandbox runs command using a specific sandbox instance.
func executeInDirWithSandbox(t *testing.T, s *Sandbox, dir, command string) (string, error) {
	t.Helper()
	paths := []string{dir}
	return s.Execute(context.Background(), command, dir, paths, paths)
}

func TestValidateBashArgs_Allowed(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"bash -c echo", `bash -c 'echo hello'`},
		{"sh -c echo", `sh -c 'echo hello'`},
		{"bash -c pipe", `bash -c 'echo hello | grep hello'`},
		{"bash -ex -c", `bash -ex -c 'echo hello'`},
		{"bash script.sh", `bash script.sh`},
		{"bash --norc -c", `bash --norc -c 'ls'`},
		{"bash --noprofile -c", `bash --noprofile -c 'echo hi'`},
		{"bash -e -c", `bash -e -c 'echo hello'`},
		{"bash -u -c", `bash -u -c 'echo hello'`},
		{"bash -n -c", `bash -n -c 'echo hello'`},
		{"bash -o pipefail -c", `bash -o pipefail -c 'echo hello'`},
		{"sh script.sh", `sh script.sh`},
		{"bash script with args", `bash script.sh arg1 arg2`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidateBashArgs_Blocked(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"bash -i", `bash -i`, `flag "-i" is not allowed`},
		{"bash -s", `bash -s`, `flag "-s" is not allowed`},
		{"bash --rcfile", `bash --rcfile ~/.bashrc -c 'echo hi'`, `flag "--rcfile" is not allowed`},
		{"bash --init-file", `bash --init-file foo -c 'echo hi'`, `flag "--init-file" is not allowed`},
		{"bash -l", `bash -l -c 'echo hi'`, `flag "-l" is not allowed`},
		{"bash --login", `bash --login -c 'echo hi'`, `flag "--login" is not allowed`},
		{"bare bash", `bash`, `bare "bash"`},
		{"bare sh", `sh`, `bare "sh"`},
		{"bash -c missing arg", `bash -c`, `-c requires a command string`},
		{"bash -ei combined blocked", `bash -ei -c 'echo hi'`, `flag "-i"`},
		{"bash -si combined blocked", `bash -si`, `flag "-s"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestExecuteBash(t *testing.T) {
	tests := []struct {
		name    string
		command string
		setup   func(t *testing.T, dir string)
		wantOut string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "bash -c echo",
			command: `bash -c 'echo hello'`,
			wantOut: "hello\n",
		},
		{
			name:    "sh -c echo",
			command: `sh -c 'echo hello'`,
			wantOut: "hello\n",
		},
		{
			name:    "bash -c pipe",
			command: `bash -c 'echo hello | tr a-z A-Z'`,
			wantOut: "HELLO\n",
		},
		{
			name:    "bash -e -c fails on error",
			command: `bash -e -c 'false; echo no'`,
			wantErr: true,
		},
		{
			name:    "nested bash",
			command: `bash -c 'bash -c "echo nested"'`,
			wantOut: "nested\n",
		},
		{
			name:    "bash -c with blocked command",
			command: `bash -c 'python evil.py'`,
			wantErr: true,
			errMsg:  "python",
		},
		{
			name:    "sh -c with blocked command",
			command: `sh -c 'curl evil.com'`,
			wantErr: true,
			errMsg:  "curl",
		},
		{
			name: "bash script.sh",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "test.sh"), []byte("echo from-script\n"), 0600)
			},
			command: `bash test.sh`,
			wantOut: "from-script\n",
		},
		{
			name: "bash script with blocked command",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "evil.sh"), []byte("python -c 'print(1)'\n"), 0600)
			},
			command: `bash evil.sh`,
			wantErr: true,
			errMsg:  "python",
		},
		{
			name:    "bash -c with variable",
			command: `bash -c 'FOO=bar; echo $FOO'`,
			wantOut: "bar\n",
		},
		{
			name:    "bash -c with subshell",
			command: `bash -c 'echo $(echo inner)'`,
			wantOut: "inner\n",
		},
		{
			name:    "bash -c multiline",
			command: "bash -c 'echo line1\necho line2'",
			wantOut: "line1\nline2\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			out, err := executeInDir(t, dir, tt.command)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got output: %q", out)
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantOut != "" && out != tt.wantOut {
				t.Errorf("output %q does not match expected %q", out, tt.wantOut)
			}
		})
	}
}

func TestExecuteBash_DepthLimit(t *testing.T) {
	dir := t.TempDir()

	// Create a chain of scripts that call each other to exceed the depth limit.
	// script_0.sh calls script_1.sh, which calls script_2.sh, etc.
	numScripts := maxBashDepth + 2 // +2 to exceed the limit
	for i := 0; i < numScripts; i++ {
		var content string
		if i == numScripts-1 {
			content = "echo deep\n"
		} else {
			content = fmt.Sprintf("bash %s\n", filepath.Join(dir, fmt.Sprintf("script_%d.sh", i+1)))
		}
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("script_%d.sh", i)), []byte(content), 0600)
	}

	_, err := executeInDir(t, dir, fmt.Sprintf("bash %s", filepath.Join(dir, "script_0.sh")))
	if err == nil {
		t.Fatal("expected depth limit error")
	}
	if !strings.Contains(err.Error(), "nesting depth exceeded") {
		t.Fatalf("expected nesting depth error, got: %v", err)
	}
}

func TestExecuteBash_DepthWithinLimit(t *testing.T) {
	// 3 levels of nesting should be fine
	cmd := `bash -c 'bash -c "bash -c \"echo deep\""'`
	dir := t.TempDir()
	out, err := executeInDir(t, dir, cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(out) != "deep" {
		t.Errorf("expected 'deep', got %q", out)
	}
}

func TestExecuteBash_InheritsWorkDir(t *testing.T) {
	dir := t.TempDir()
	// Create a file in the temp dir
	os.WriteFile(filepath.Join(dir, "marker.txt"), []byte("found"), 0600)

	out, err := executeInDir(t, dir, `bash -c 'cat marker.txt'`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(out) != "found" {
		t.Errorf("expected 'found', got %q", out)
	}
}

func TestExecuteBash_ShellFlagsApplied(t *testing.T) {
	dir := t.TempDir()

	// -x flag should produce trace output on stderr (merged with stdout in our setup)
	out, err := executeInDir(t, dir, `bash -x -c 'echo traced'`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should contain the trace output (+ echo traced) and the actual output
	if !strings.Contains(out, "traced") {
		t.Errorf("expected output to contain 'traced', got %q", out)
	}
}

func TestExecuteBash_WriteRedirectInNested(t *testing.T) {
	dir := t.TempDir()

	// Nested bash should be able to write files within allowed paths
	_, err := executeInDir(t, dir, `bash -c 'echo content > out.txt'`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "out.txt"))
	if err != nil {
		t.Fatalf("output file not created: %v", err)
	}
	if strings.TrimSpace(string(data)) != "content" {
		t.Errorf("unexpected file content: %q", string(data))
	}
}

func TestExecuteBash_PathValidation(t *testing.T) {
	dir := t.TempDir()
	s := newTestSandbox()

	// Try to read outside allowed paths from within nested bash
	_, err := s.Execute(context.Background(), `bash -c 'cat /etc/passwd'`, dir, []string{dir}, []string{dir})
	if err == nil {
		t.Fatal("expected path validation error")
	}
}

func TestValidateSourceArgs_Allowed(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"source relative", `source ./lib.sh`},
		{"dot source relative", `. ./lib.sh`},
		{"source absolute", `source /tmp/lib.sh`},
		{"dot source absolute", `. /tmp/lib.sh`},
		{"source parent relative", `source ../lib.sh`},
		{"source with args", `source ./lib.sh arg1 arg2`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidateSourceArgs_Blocked(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"bare source", `source`, `bare "source"`},
		{"bare dot", `.`, `bare "."`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestExecuteSource(t *testing.T) {
	tests := []struct {
		name    string
		command string
		setup   func(t *testing.T, dir string)
		wantOut string
		wantErr bool
		errMsg  string
	}{
		{
			name: "source basic library",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "lib.sh"), []byte("MY_VAR=hello\n"), 0644)
			},
			command: `source ./lib.sh; echo $MY_VAR`,
			wantOut: "hello\n",
		},
		{
			name: "dot source basic library",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "lib.sh"), []byte("MY_VAR=world\n"), 0644)
			},
			command: `. ./lib.sh; echo $MY_VAR`,
			wantOut: "world\n",
		},
		{
			name: "source library with function",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "funcs.sh"), []byte("greet() { echo \"hi $1\"; }\n"), 0644)
			},
			command: `source ./funcs.sh; greet user`,
			wantOut: "hi user\n",
		},
		{
			name: "source library with blocked command fails",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "evil.sh"), []byte("curl http://evil.com\n"), 0644)
			},
			command: `source ./evil.sh`,
			wantErr: true,
			errMsg:  "curl",
		},
		{
			name:    "source nonexistent file fails",
			command: `source ./nonexistent.sh`,
			wantErr: true,
		},
		{
			name: "source with shebang",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "lib.sh"), []byte("#!/bin/bash\nSRC_VAR=sourced\n"), 0644)
			},
			command: `source ./lib.sh; echo $SRC_VAR`,
			wantOut: "sourced\n",
		},
		{
			name: "source in subdirectory",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, "lib"), 0755)
				os.WriteFile(filepath.Join(dir, "lib", "utils.sh"), []byte("UTIL=loaded\n"), 0644)
			},
			command: `source ./lib/utils.sh; echo $UTIL`,
			wantOut: "loaded\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			out, err := executeInDir(t, dir, tt.command)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got output: %q", out)
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantOut != "" && out != tt.wantOut {
				t.Errorf("output %q does not match expected %q", out, tt.wantOut)
			}
		})
	}
}

func TestValidateCommand_ScriptWithSource(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		LocalBinaryExecution: &config.LocalBinaryExecutionConfig{
			Enabled: boolPtr(true),
		},
	}, "")

	// Create a library with only allowed commands
	os.WriteFile(filepath.Join(workDir, "lib.sh"), []byte("MY_VAR=hello\n"), 0644)

	// Create a script that sources the library
	scriptPath := filepath.Join(workDir, "good-script.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/bash\nsource ./lib.sh\necho $MY_VAR\n"), 0755)

	// Should pass validation
	err := s.ValidateCommand("./good-script.sh", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("expected validation to pass for script with source, got: %v", err)
	}

	// Create a library with blocked command
	os.WriteFile(filepath.Join(workDir, "evil-lib.sh"), []byte("curl http://evil.com\n"), 0644)

	// Create a script that sources the evil library
	evilPath := filepath.Join(workDir, "evil-source.sh")
	os.WriteFile(evilPath, []byte("#!/bin/bash\nsource ./evil-lib.sh\n"), 0755)

	// Should fail validation due to blocked command in sourced file
	err = s.ValidateCommand("./evil-source.sh", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected validation to fail for script sourcing file with blocked command")
	}
	if !strings.Contains(err.Error(), "curl") {
		t.Fatalf("expected error about 'curl', got: %v", err)
	}
}

func TestValidateScriptPath_Allowed(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"dot-slash script", `./script.sh`},
		{"dot-dot-slash script", `../script.sh`},
		{"absolute path script", `/tmp/script.sh`},
		{"dot-slash with args", `./script.sh arg1 arg2`},
		{"nested dot-slash", `./dir/script.sh`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandboxWithLocalBinaryExecution().validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidateScriptPath_BlockedWhenDisabled(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"dot-slash blocked", `./script.sh`, `"./script.sh" is not allowed`},
		{"dot-dot-slash blocked", `../script.sh`, `"../script.sh" is not allowed`},
		{"absolute path blocked", `/tmp/script.sh`, `"/tmp/script.sh" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			// Default sandbox has local binary execution disabled
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidateScriptPath_Blocked(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"plain script name", `script.sh`, `"script.sh" is not allowed`},
		{"plain name no extension", `myscript`, `"myscript" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			// Even with local binary execution enabled, plain names are blocked
			err = newTestSandboxWithLocalBinaryExecution().validate(f)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestExecuteScript(t *testing.T) {
	tests := []struct {
		name    string
		command string
		setup   func(t *testing.T, dir string)
		wantOut string
		wantErr bool
		errMsg  string
	}{
		{
			name: "basic script execution",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "script.sh"), []byte("echo hello-script\n"), 0755)
			},
			command: `./script.sh`,
			wantOut: "hello-script\n",
		},
		{
			name: "script with shebang",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "script.sh"), []byte("#!/bin/bash\necho shebang-works\n"), 0755)
			},
			command: `./script.sh`,
			wantOut: "shebang-works\n",
		},
		{
			name: "script with arguments",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "script.sh"), []byte("echo $1 $2\n"), 0755)
			},
			command: `./script.sh foo bar`,
			wantOut: "foo bar\n",
		},
		{
			name: "script with blocked command",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "evil.sh"), []byte("python -c 'print(1)'\n"), 0755)
			},
			command: `./evil.sh`,
			wantErr: true,
			errMsg:  "python",
		},
		{
			name:    "script file does not exist",
			command: `./nonexistent.sh`,
			wantErr: true,
			errMsg:  "cannot read script",
		},
		{
			name: "script in subdirectory",
			setup: func(t *testing.T, dir string) {
				os.MkdirAll(filepath.Join(dir, "sub"), 0755)
				os.WriteFile(filepath.Join(dir, "sub", "script.sh"), []byte("echo from-sub\n"), 0755)
			},
			command: `./sub/script.sh`,
			wantOut: "from-sub\n",
		},
		{
			name: "absolute path script",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "abs.sh"), []byte("echo absolute\n"), 0755)
			},
			// command is set dynamically in setup since we need the temp dir path
			wantOut: "absolute\n",
		},
		{
			name: "script with multiple commands",
			setup: func(t *testing.T, dir string) {
				os.WriteFile(filepath.Join(dir, "multi.sh"), []byte("echo line1\necho line2\n"), 0755)
			},
			command: `./multi.sh`,
			wantOut: "line1\nline2\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			cmd := tt.command
			// Handle absolute path test case
			if tt.name == "absolute path script" {
				cmd = filepath.Join(dir, "abs.sh")
			}
			s := newTestSandboxWithLocalBinaryExecution()
			out, err := executeInDirWithSandbox(t, s, dir, cmd)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got output: %q", out)
				}
				if tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantOut != "" && out != tt.wantOut {
				t.Errorf("output %q does not match expected %q", out, tt.wantOut)
			}
		})
	}
}

func TestExecuteScript_BlockedWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "script.sh"), []byte("echo hello\n"), 0755)

	// Default sandbox (local binary execution disabled)
	s := newTestSandbox()
	_, err := executeInDirWithSandbox(t, s, dir, `./script.sh`)
	if err == nil {
		t.Fatal("expected error when local binary execution is disabled")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected 'not allowed' error, got: %v", err)
	}
}

func TestExecuteScript_DepthLimit(t *testing.T) {
	dir := t.TempDir()

	// Create a chain of scripts that call each other via ./script_N.sh
	numScripts := maxBashDepth + 2
	for i := 0; i < numScripts; i++ {
		var content string
		if i == numScripts-1 {
			content = "echo deep\n"
		} else {
			content = fmt.Sprintf("./script_%d.sh\n", i+1)
		}
		os.WriteFile(filepath.Join(dir, fmt.Sprintf("script_%d.sh", i)), []byte(content), 0755)
	}

	s := newTestSandboxWithLocalBinaryExecution()
	_, err := executeInDirWithSandbox(t, s, dir, `./script_0.sh`)
	if err == nil {
		t.Fatal("expected depth limit error")
	}
	if !strings.Contains(err.Error(), "nesting depth exceeded") {
		t.Fatalf("expected nesting depth error, got: %v", err)
	}
}

func TestExecuteBinary(t *testing.T) {
	// Check that Go compiler is available
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go compiler not available")
	}

	dir := t.TempDir()

	// Write a small Go program
	src := filepath.Join(dir, "hello.go")
	os.WriteFile(src, []byte(`package main

import "fmt"

func main() {
	fmt.Println("hello-from-binary")
}
`), 0644)

	// Compile it
	binPath := filepath.Join(dir, "hello")
	cmd := exec.Command("go", "build", "-o", binPath, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile test binary: %v\n%s", err, out)
	}

	// Execute via ./hello with local binary execution enabled
	s := newTestSandboxWithLocalBinaryExecution()
	out, err := executeInDirWithSandbox(t, s, dir, `./hello`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.TrimSpace(out) != "hello-from-binary" {
		t.Errorf("expected 'hello-from-binary', got %q", out)
	}
}

func TestExecuteBinary_BlockedWhenDisabled(t *testing.T) {
	// Check that Go compiler is available
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go compiler not available")
	}

	dir := t.TempDir()

	// Write and compile a small Go program
	src := filepath.Join(dir, "hello.go")
	os.WriteFile(src, []byte(`package main

import "fmt"

func main() {
	fmt.Println("should-not-run")
}
`), 0644)

	binPath := filepath.Join(dir, "hello")
	cmd := exec.Command("go", "build", "-o", binPath, src)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile test binary: %v\n%s", err, out)
	}

	// Default sandbox (local binary execution disabled)
	s := newTestSandbox()
	_, err := executeInDirWithSandbox(t, s, dir, `./hello`)
	if err == nil {
		t.Fatal("expected error when local binary execution is disabled")
	}
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected 'not allowed' error, got: %v", err)
	}
}

func TestIsBinaryExecutable(t *testing.T) {
	dir := t.TempDir()

	// Shell script should not be detected as binary
	scriptPath := filepath.Join(dir, "script.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/bash\necho hello\n"), 0755)
	if isBinaryExecutable(scriptPath) {
		t.Error("shell script should not be detected as binary")
	}

	// Non-existent file should return false
	if isBinaryExecutable(filepath.Join(dir, "nonexistent")) {
		t.Error("non-existent file should not be detected as binary")
	}

	// Empty file should return false
	emptyPath := filepath.Join(dir, "empty")
	os.WriteFile(emptyPath, []byte{}, 0755)
	if isBinaryExecutable(emptyPath) {
		t.Error("empty file should not be detected as binary")
	}

	// Fake ELF file
	elfPath := filepath.Join(dir, "fake-elf")
	os.WriteFile(elfPath, []byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0}, 0755)
	if !isBinaryExecutable(elfPath) {
		t.Error("ELF magic should be detected as binary")
	}

	// Fake Mach-O 64-bit
	machoPath := filepath.Join(dir, "fake-macho64")
	os.WriteFile(machoPath, []byte{0xfe, 0xed, 0xfa, 0xcf, 0, 0, 0, 0}, 0755)
	if !isBinaryExecutable(machoPath) {
		t.Error("Mach-O 64-bit magic should be detected as binary")
	}

	// Fake Mach-O 32-bit
	macho32Path := filepath.Join(dir, "fake-macho32")
	os.WriteFile(macho32Path, []byte{0xfe, 0xed, 0xfa, 0xce, 0, 0, 0, 0}, 0755)
	if !isBinaryExecutable(macho32Path) {
		t.Error("Mach-O 32-bit magic should be detected as binary")
	}

	// Fake Mach-O 64-bit little-endian
	macho64LEPath := filepath.Join(dir, "fake-macho64le")
	os.WriteFile(macho64LEPath, []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}, 0755)
	if !isBinaryExecutable(macho64LEPath) {
		t.Error("Mach-O 64-bit little-endian magic should be detected as binary")
	}

	// Fake Mach-O 32-bit little-endian
	macho32LEPath := filepath.Join(dir, "fake-macho32le")
	os.WriteFile(macho32LEPath, []byte{0xce, 0xfa, 0xed, 0xfe, 0, 0, 0, 0}, 0755)
	if !isBinaryExecutable(macho32LEPath) {
		t.Error("Mach-O 32-bit little-endian magic should be detected as binary")
	}

	// Fake fat/universal binary
	fatPath := filepath.Join(dir, "fake-fat")
	os.WriteFile(fatPath, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0}, 0755)
	if !isBinaryExecutable(fatPath) {
		t.Error("fat/universal binary magic should be detected as binary")
	}
}

func TestLocalBinaryExecutionConfig_YAML(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", configPath)

	data := []byte("local_binary_execution:\n  enabled: true\n")
	if err := os.WriteFile(configPath, data, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.LocalBinaryExecution.IsEnabled() {
		t.Fatal("expected local binary execution to be enabled")
	}
}

// TestExecuteScript_BareExtraCommandSkipsContentValidation verifies that when a
// script path is registered as a bare extra_commands entry, its contents are
// not recursively validated against the allowlist. Without this bypass, using
// the script under any prefix (e.g. `cd X && ./script.sh`) falls into the AST
// path and the script's body gets validated, defeating the user's opt-in.
func TestExecuteScript_BareExtraCommandSkipsContentValidation(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "wrapper.sh")
	// The script body uses `docker`, which is not in allowedCommands.
	// Without the bypass, executeScript would reject this.
	os.WriteFile(scriptPath, []byte("#!/bin/bash\necho wrapped-$1\n"), 0755)

	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		ExtraCommands: []string{"./wrapper.sh"},
	}, dir)

	// Leading invocation — hits the top-level executeRaw fast path.
	out, err := executeInDirWithSandbox(t, s, dir, `./wrapper.sh hello`)
	if err != nil {
		t.Fatalf("leading invocation failed: %v", err)
	}
	if strings.TrimSpace(out) != "wrapped-hello" {
		t.Errorf("leading invocation output %q, want %q", strings.TrimSpace(out), "wrapped-hello")
	}

	// Non-leading invocation (prefixed with another command) — hits the AST
	// path and the per-command ExecHandler. Must still bypass content validation.
	out, err = executeInDirWithSandbox(t, s, dir, `true && ./wrapper.sh world`)
	if err != nil {
		t.Fatalf("non-leading invocation failed: %v", err)
	}
	if strings.TrimSpace(out) != "wrapped-world" {
		t.Errorf("non-leading invocation output %q, want %q", strings.TrimSpace(out), "wrapped-world")
	}
}

// TestExecuteScript_BareExtraCommandBypassesBlockedBody verifies that a bare
// extra_commands script entry bypasses the script-body validator even when
// the body contains commands that would normally be rejected.
func TestExecuteScript_BareExtraCommandBypassesBlockedBody(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "wrapper.sh")
	// Body references a command not in the allowlist. We use `true "$@"` so the
	// script always exits 0 regardless of the banned-command line being parsed.
	body := "#!/bin/bash\n" +
		"if false; then docker run foo; fi\n" +
		"echo opted-in\n"
	os.WriteFile(scriptPath, []byte(body), 0755)

	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		ExtraCommands: []string{"./wrapper.sh"},
	}, dir)

	out, err := executeInDirWithSandbox(t, s, dir, `true && ./wrapper.sh`)
	if err != nil {
		t.Fatalf("expected bypass to allow script with non-allowlisted body: %v", err)
	}
	if !strings.Contains(out, "opted-in") {
		t.Errorf("expected output to include 'opted-in', got %q", out)
	}
}

// TestExecuteScript_NonBareExtraCommandStillValidatesBody verifies that when a
// script is registered with a subcommand restriction (not bare), the body is
// still validated — only bare entries get the full bypass.
func TestExecuteScript_NonBareExtraCommandStillValidatesBody(t *testing.T) {
	dir := t.TempDir()
	scriptPath := filepath.Join(dir, "wrapper.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/bash\ndocker run foo\n"), 0755)

	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		ExtraCommands: []string{"./wrapper.sh build"},
		LocalBinaryExecution: &config.LocalBinaryExecutionConfig{
			Enabled: boolPtr(true),
		},
	}, dir)

	_, err := executeInDirWithSandbox(t, s, dir, `true && ./wrapper.sh build`)
	if err == nil {
		t.Fatal("expected content validation to reject docker in script body")
	}
	if !strings.Contains(err.Error(), "docker") {
		t.Fatalf("expected error about 'docker', got: %v", err)
	}
}
