package bash_sandboxed

import (
	"path/filepath"
	"reflect"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

// extractCallArgs parses a command and returns the args of the first call expr.
func extractCallArgs(t *testing.T, command string) []*syntax.Word {
	t.Helper()
	f, err := ParseBash(command)
	if err != nil {
		t.Fatalf("failed to parse command: %v", err)
	}
	var args []*syntax.Word
	syntax.Walk(f, func(node syntax.Node) bool {
		if call, ok := node.(*syntax.CallExpr); ok && len(call.Args) > 0 {
			args = call.Args
			return false
		}
		return true
	})
	return args
}

func TestValidateRtkCommand(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		cfg       *config.Config
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "rtk disabled blocks proxy",
			command:   "rtk git status",
			cfg:       &config.Config{},
			wantErr:   true,
			errSubstr: "rtk.enabled is disabled",
		},
		{
			name:    "rtk git status allowed",
			command: "rtk git status",
			cfg:     &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr: false,
		},
		{
			name:      "rtk git push blocked by git validator",
			command:   "rtk git push origin main",
			cfg:       &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr:   true,
			errSubstr: "remote_write is disabled",
		},
		{
			name:    "rtk ls allowed",
			command: "rtk ls -la",
			cfg:     &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr: false,
		},
		{
			name:    "rtk grep allowed",
			command: "rtk grep foo .",
			cfg:     &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr: false,
		},
		{
			name:    "global flag before subcommand allowed",
			command: "rtk -u git status",
			cfg:     &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr: false,
		},
		{
			name:    "multiple global flags allowed",
			command: "rtk -v -u find .",
			cfg:     &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr: false,
		},
		{
			name:    "rtk cargo test allowed when rust enabled",
			command: "rtk cargo test",
			cfg: &config.Config{
				Rtk:      &config.RtkConfig{Enabled: boolPtr(true)},
				Runtimes: &config.RuntimesConfig{Rust: &config.RustConfig{Enabled: boolPtr(true)}},
			},
			wantErr: false,
		},
		{
			name:      "rtk cargo blocked when rust disabled",
			command:   "rtk cargo test",
			cfg:       &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr:   true,
			errSubstr: "runtimes.rust.enabled is disabled",
		},
		{
			name:    "rtk aws allowed when aws enabled",
			command: "rtk aws s3 ls",
			cfg: &config.Config{
				Rtk: &config.RtkConfig{Enabled: boolPtr(true)},
				AWS: &config.AWSConfig{AllowRawCredentials: boolPtr(true)},
			},
			wantErr: false,
		},
		{
			name:      "rtk aws blocked when aws disabled",
			command:   "rtk aws s3 ls",
			cfg:       &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr:   true,
			errSubstr: "aws.enabled is disabled",
		},
		{
			name:      "rtk init blocked",
			command:   "rtk init -g",
			cfg:       &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr:   true,
			errSubstr: "init",
		},
		{
			name:    "rtk gain allowed",
			command: "rtk gain",
			cfg:     &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr: false,
		},
		{
			name:    "rtk discover allowed",
			command: "rtk discover",
			cfg:     &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr: false,
		},
		{
			name:      "rtk does not proxy cat",
			command:   "rtk cat /etc/passwd",
			cfg:       &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr:   true,
			errSubstr: "does not proxy",
		},
		{
			name:      "rtk does not proxy bash",
			command:   "rtk bash -c 'echo hi'",
			cfg:       &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr:   true,
			errSubstr: "does not proxy",
		},
		{
			name:      "rtk does not proxy write command rm",
			command:   "rtk rm file.txt",
			cfg:       &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr:   true,
			errSubstr: "does not proxy",
		},
		{
			name:    "bare rtk allowed",
			command: "rtk",
			cfg:     &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr: false,
		},
		{
			name:    "rtk --version allowed",
			command: "rtk --version",
			cfg:     &config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSandbox()
			s.UpdateConfig(tt.cfg, "")
			args := extractCallArgs(t, tt.command)
			err := validateRtkCommand(s, args)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errSubstr)
				} else if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRerouteThroughRtk(t *testing.T) {
	tests := []struct {
		name    string
		cmdName string
		args    []string
		enabled bool
		want    []string
	}{
		{
			name:    "git rerouted when enabled",
			cmdName: "git",
			args:    []string{"git", "status"},
			enabled: true,
			want:    []string{"rtk", "git", "status"},
		},
		{
			name:    "git not rerouted when disabled",
			cmdName: "git",
			args:    []string{"git", "status"},
			enabled: false,
			want:    []string{"git", "status"},
		},
		{
			name:    "unsupported command not rerouted",
			cmdName: "cat",
			args:    []string{"cat", "file.txt"},
			enabled: true,
			want:    []string{"cat", "file.txt"},
		},
		{
			name:    "rtk itself not double-prefixed",
			cmdName: "rtk",
			args:    []string{"rtk", "git", "status"},
			enabled: true,
			want:    []string{"rtk", "git", "status"},
		},
		{
			name:    "cargo rerouted when enabled",
			cmdName: "cargo",
			args:    []string{"cargo", "test"},
			enabled: true,
			want:    []string{"rtk", "cargo", "test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rerouteThroughRtk(tt.cmdName, tt.args, tt.enabled)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rerouteThroughRtk() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRtkRuntimeReadPaths verifies that enabling rtk exposes its data directory
// via RuntimeReadPaths so the model can read the full output rtk saves for
// failed commands. serve.go and preflight.go fold RuntimeReadPaths into the
// sandbox's readable paths.
func TestRtkRuntimeReadPaths(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/custom/data")
	rtkDir := filepath.Join("/custom/data", "rtk")

	s := NewSandbox()
	s.UpdateConfig(&config.Config{Rtk: &config.RtkConfig{Enabled: boolPtr(true)}}, "")
	if !containsString(s.RuntimeReadPaths(), rtkDir) {
		t.Errorf("expected RuntimeReadPaths to include %q, got %v", rtkDir, s.RuntimeReadPaths())
	}

	s.UpdateConfig(&config.Config{}, "")
	if containsString(s.RuntimeReadPaths(), rtkDir) {
		t.Errorf("expected RuntimeReadPaths to exclude %q when rtk disabled, got %v", rtkDir, s.RuntimeReadPaths())
	}
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}

func TestDetectRtkBinds(t *testing.T) {
	t.Run("disabled returns nil", func(t *testing.T) {
		if got := detectRtkBinds(nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := detectRtkBinds(&config.RtkConfig{Enabled: boolPtr(false)}); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("respects XDG_DATA_HOME", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "/custom/data")
		got := detectRtkBinds(&config.RtkConfig{Enabled: boolPtr(true)})
		want := []string{filepath.Join("/custom/data", "rtk")}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("detectRtkBinds() = %v, want %v", got, want)
		}
	})

	t.Run("defaults to ~/.local/share/rtk", func(t *testing.T) {
		t.Setenv("XDG_DATA_HOME", "")
		t.Setenv("HOME", "/home/tester")
		got := detectRtkBinds(&config.RtkConfig{Enabled: boolPtr(true)})
		want := []string{filepath.Join("/home/tester", ".local", "share", "rtk")}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("detectRtkBinds() = %v, want %v", got, want)
		}
	})
}
