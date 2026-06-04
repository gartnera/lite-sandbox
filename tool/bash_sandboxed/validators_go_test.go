package bash_sandboxed

import (
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

func TestValidateGoArgs(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		goCfg     *config.GoConfig
		wantErr   bool
		errSubstr string
	}{
		// Basic allowed commands
		{
			name:    "go build allowed",
			command: "go build",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go test allowed",
			command: "go test ./...",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go mod tidy allowed",
			command: "go mod tidy",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go list allowed",
			command: "go list -m all",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go env allowed",
			command: "go env GOPATH",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go version allowed",
			command: "go version",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go vet allowed",
			command: "go vet ./...",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go fmt allowed",
			command: "go fmt ./...",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go doc allowed",
			command: "go doc fmt.Println",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go get allowed",
			command: "go get github.com/example/pkg",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go work allowed",
			command: "go work use ./module",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go clean allowed",
			command: "go clean -cache",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go tool allowed",
			command: "go tool pprof cpu.prof",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},

		// go run variants
		{
			name:    "go run local file allowed",
			command: "go run main.go",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go run current directory allowed",
			command: "go run .",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:      "go run with @ blocked",
			command:   "go run example.com/cmd@latest",
			goCfg:     &config.GoConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "remote package references",
		},
		{
			name:      "go run with @version blocked",
			command:   "go run github.com/user/tool@v1.0.0",
			goCfg:     &config.GoConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "remote package references",
		},
		{
			name:      "go run with -exec blocked",
			command:   "go run -exec echo main.go",
			goCfg:     &config.GoConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "-exec",
		},

		// go install variants
		{
			name:    "go install local package allowed",
			command: "go install ./cmd/tool",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go install all allowed",
			command: "go install ./...",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:      "go install with @ blocked",
			command:   "go install example.com/cmd@latest",
			goCfg:     &config.GoConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "remote package references",
		},
		{
			name:      "go install with @version blocked",
			command:   "go install github.com/user/tool@v1.2.3",
			goCfg:     &config.GoConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "remote package references",
		},

		// go generate
		{
			name:      "go generate blocked by default",
			command:   "go generate ./...",
			goCfg:     &config.GoConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "runtimes.go.generate is disabled",
		},
		{
			name:      "go generate blocked when generate=false",
			command:   "go generate ./...",
			goCfg:     &config.GoConfig{Enabled: boolPtr(true), Generate: boolPtr(false)},
			wantErr:   true,
			errSubstr: "runtimes.go.generate is disabled",
		},
		{
			name:    "go generate allowed when generate=true",
			command: "go generate ./...",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true), Generate: boolPtr(true)},
			wantErr: false,
		},

		// Edge cases
		{
			name:    "bare go command allowed",
			command: "go",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "go with only flags allowed",
			command: "go -C /path/to/dir version",
			goCfg:   &config.GoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
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

			err = validateGoArgs(args, tt.goCfg)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errSubstr)
				} else if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidateGofmtCommand(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		runtimes  *config.RuntimesConfig
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "gofmt allowed when go runtime enabled",
			command:  "gofmt -w main.go",
			runtimes: &config.RuntimesConfig{Go: &config.GoConfig{Enabled: boolPtr(true)}},
			wantErr:  false,
		},
		{
			name:     "gofmt list allowed when go runtime enabled",
			command:  "gofmt -l .",
			runtimes: &config.RuntimesConfig{Go: &config.GoConfig{Enabled: boolPtr(true)}},
			wantErr:  false,
		},
		{
			name:      "gofmt blocked when go runtime disabled",
			command:   "gofmt -w main.go",
			runtimes:  &config.RuntimesConfig{Go: &config.GoConfig{Enabled: boolPtr(false)}},
			wantErr:   true,
			errSubstr: `command "gofmt" is not allowed (runtimes.go.enabled is disabled)`,
		},
		{
			name:      "gofmt blocked by default",
			command:   "gofmt -w main.go",
			runtimes:  nil,
			wantErr:   true,
			errSubstr: `command "gofmt" is not allowed (runtimes.go.enabled is disabled)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSandboxWithRuntimesConfig(tt.runtimes)
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("failed to parse command: %v", err)
			}
			err = s.validate(f)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errSubstr)
				} else if tt.errSubstr != "" && !contains(err.Error(), tt.errSubstr) {
					t.Errorf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
