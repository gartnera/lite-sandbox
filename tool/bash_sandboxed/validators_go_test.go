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
		allow     bool
		wantErr   bool
		errSubstr string
	}{
		// Basic allowed commands
		{
			name:    "go build allowed",
			command: "go build",
			wantErr: false,
		},
		{
			name:    "go test allowed",
			command: "go test ./...",
			wantErr: false,
		},
		{
			name:    "go mod tidy allowed",
			command: "go mod tidy",
			wantErr: false,
		},
		{
			name:    "go list allowed",
			command: "go list -m all",
			wantErr: false,
		},
		{
			name:    "go env allowed",
			command: "go env GOPATH",
			wantErr: false,
		},
		{
			name:    "go version allowed",
			command: "go version",
			wantErr: false,
		},
		{
			name:    "go vet allowed",
			command: "go vet ./...",
			wantErr: false,
		},
		{
			name:    "go fmt allowed",
			command: "go fmt ./...",
			wantErr: false,
		},
		{
			name:    "go doc allowed",
			command: "go doc fmt.Println",
			wantErr: false,
		},
		{
			name:    "go get allowed",
			command: "go get github.com/example/pkg",
			wantErr: false,
		},
		{
			name:    "go work allowed",
			command: "go work use ./module",
			wantErr: false,
		},
		{
			name:    "go clean allowed",
			command: "go clean -cache",
			wantErr: false,
		},
		{
			name:    "go tool allowed",
			command: "go tool pprof cpu.prof",
			wantErr: false,
		},

		// go run variants
		{
			name:    "go run local file allowed",
			command: "go run main.go",
			wantErr: false,
		},
		{
			name:    "go run current directory allowed",
			command: "go run .",
			wantErr: false,
		},
		{
			name:      "go run with @ blocked",
			command:   "go run example.com/cmd@latest",
			wantErr:   true,
			errSubstr: "remote package references",
		},
		{
			name:      "go run with @version blocked",
			command:   "go run github.com/user/tool@v1.0.0",
			wantErr:   true,
			errSubstr: "remote package references",
		},
		{
			name:      "go run with -exec blocked",
			command:   "go run -exec echo main.go",
			wantErr:   true,
			errSubstr: "-exec",
		},

		// go install variants
		{
			name:    "go install local package allowed",
			command: "go install ./cmd/tool",
			wantErr: false,
		},
		{
			name:    "go install all allowed",
			command: "go install ./...",
			wantErr: false,
		},
		{
			name:      "go install with @ blocked",
			command:   "go install example.com/cmd@latest",
			wantErr:   true,
			errSubstr: "remote package references",
		},
		{
			name:      "go install with @version blocked",
			command:   "go install github.com/user/tool@v1.2.3",
			wantErr:   true,
			errSubstr: "remote package references",
		},

		// go generate
		{
			name:      "go generate blocked by default",
			command:   "go generate ./...",
			wantErr:   true,
			errSubstr: "go generate is not allowed",
		},
		{
			name:      "go generate blocked when generate=false",
			command:   "go generate ./...",
			wantErr:   true,
			errSubstr: "go generate is not allowed",
		},
		{
			name:    "go generate allowed when generate=true",
			command: "go generate ./...",
			allow:   true,
			wantErr: false,
		},

		// Edge cases
		{
			name:    "bare go command allowed",
			command: "go",
			wantErr: false,
		},
		{
			name:    "go with only flags allowed",
			command: "go -C /path/to/dir version",
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

			err = validateGoArgs(args, tt.allow)
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
		profiles  []config.ProfileEntry
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "gofmt allowed when go runtime enabled",
			command:  "gofmt -w main.go",
			profiles: []config.ProfileEntry{{Name: "go"}},
			wantErr:  false,
		},
		{
			name:     "gofmt list allowed when go runtime enabled",
			command:  "gofmt -l .",
			profiles: []config.ProfileEntry{{Name: "go"}},
			wantErr:  false,
		},
		{
			name:      "gofmt blocked when go runtime disabled",
			command:   "gofmt -w main.go",
			profiles:  []config.ProfileEntry{{Name: "go", Enabled: boolPtr(false)}},
			wantErr:   true,
			errSubstr: `command "gofmt" is not allowed (the go profile is not enabled)`,
		},
		{
			name:      "gofmt blocked by default",
			command:   "gofmt -w main.go",
			profiles:  nil,
			wantErr:   true,
			errSubstr: `command "gofmt" is not allowed (the go profile is not enabled)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestSandboxWithConfig(&config.Config{Profiles: tt.profiles})
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
