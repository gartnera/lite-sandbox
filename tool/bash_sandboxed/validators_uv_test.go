package bash_sandboxed

import (
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

func TestValidateUvArgs(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		allow     bool
		wantErr   bool
		errSubstr string
	}{
		// Basic allowed commands
		{
			name:    "uv sync allowed",
			command: "uv sync",
			wantErr: false,
		},
		{
			name:    "uv add allowed",
			command: "uv add requests",
			wantErr: false,
		},
		{
			name:    "uv run allowed",
			command: "uv run main.py",
			wantErr: false,
		},
		{
			name:    "uv pip install allowed",
			command: "uv pip install flask",
			wantErr: false,
		},
		{
			name:    "uv venv allowed",
			command: "uv venv",
			wantErr: false,
		},
		{
			name:    "uv lock allowed",
			command: "uv lock",
			wantErr: false,
		},
		{
			name:    "uv build allowed",
			command: "uv build",
			wantErr: false,
		},
		{
			name:    "uv tool install allowed",
			command: "uv tool install ruff",
			wantErr: false,
		},
		{
			name:    "uv python install allowed",
			command: "uv python install 3.12",
			wantErr: false,
		},
		{
			name:    "uv cache dir allowed",
			command: "uv cache dir",
			wantErr: false,
		},

		// publish gating
		{
			name:      "uv publish blocked by default",
			command:   "uv publish",
			wantErr:   true,
			errSubstr: "uv publish is not allowed",
		},
		{
			name:      "uv publish blocked when publish=false",
			command:   "uv publish",
			wantErr:   true,
			errSubstr: "uv publish is not allowed",
		},
		{
			name:    "uv publish allowed when publish=true",
			command: "uv publish",
			allow:   true,
			wantErr: false,
		},
		{
			name:      "uv publish behind global flag still blocked",
			command:   "uv --directory ./dist publish",
			wantErr:   true,
			errSubstr: "uv publish is not allowed",
		},

		// self update gating
		{
			name:      "uv self update blocked",
			command:   "uv self update",
			wantErr:   true,
			errSubstr: "modifies the uv executable",
		},
		{
			name:    "uv self version allowed",
			command: "uv self version",
			wantErr: false,
		},

		// Edge cases
		{
			name:    "bare uv command allowed",
			command: "uv",
			wantErr: false,
		},
		{
			name:    "uv with only flags allowed",
			command: "uv --version",
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

			err = validateUvArgs(args, tt.allow)
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

// TestValidateUvCommandGating verifies the runtime enable/disable gate for both
// uv and uvx, exercised through the full validate() path.
func TestValidateUvCommandGating(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		profiles  []config.ProfileEntry
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "uv allowed when enabled",
			command:  "uv sync",
			profiles: []config.ProfileEntry{{Name: "uv"}},
			wantErr:  false,
		},
		{
			name:      "uv blocked when disabled",
			command:   "uv sync",
			profiles:  []config.ProfileEntry{{Name: "uv", Enabled: boolPtr(false)}},
			wantErr:   true,
			errSubstr: `command "uv" is not allowed (the uv profile is not enabled)`,
		},
		{
			name:      "uv blocked by default",
			command:   "uv sync",
			profiles:  nil,
			wantErr:   true,
			errSubstr: `command "uv" is not allowed (the uv profile is not enabled)`,
		},
		{
			name:     "uvx allowed when enabled",
			command:  "uvx ruff check",
			profiles: []config.ProfileEntry{{Name: "uv"}},
			wantErr:  false,
		},
		{
			name:      "uvx blocked by default",
			command:   "uvx ruff check",
			profiles:  nil,
			wantErr:   true,
			errSubstr: `command "uvx" is not allowed (the uv profile is not enabled)`,
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
