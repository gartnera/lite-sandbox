package bash_sandboxed

import (
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func TestValidatePnpmArgs(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		allow     bool
		wantErr   bool
		errSubstr string
	}{
		// Basic allowed commands
		{
			name:    "pnpm install allowed",
			command: "pnpm install",
			wantErr: false,
		},
		{
			name:    "pnpm add allowed",
			command: "pnpm add react",
			wantErr: false,
		},
		{
			name:    "pnpm remove allowed",
			command: "pnpm remove lodash",
			wantErr: false,
		},
		{
			name:    "pnpm update allowed",
			command: "pnpm update",
			wantErr: false,
		},
		{
			name:    "pnpm test allowed",
			command: "pnpm test",
			wantErr: false,
		},
		{
			name:    "pnpm run allowed",
			command: "pnpm run build",
			wantErr: false,
		},
		{
			name:    "pnpm list allowed",
			command: "pnpm list",
			wantErr: false,
		},
		{
			name:    "pnpm outdated allowed",
			command: "pnpm outdated",
			wantErr: false,
		},
		{
			name:    "pnpm why allowed",
			command: "pnpm why react",
			wantErr: false,
		},
		{
			name:    "pnpm audit allowed",
			command: "pnpm audit",
			wantErr: false,
		},
		{
			name:    "pnpm exec allowed",
			command: "pnpm exec eslint .",
			wantErr: false,
		},
		{
			name:    "pnpm create allowed",
			command: "pnpm create vite",
			wantErr: false,
		},
		{
			name:    "pnpm init allowed",
			command: "pnpm init",
			wantErr: false,
		},
		{
			name:    "pnpm store status allowed",
			command: "pnpm store status",
			wantErr: false,
		},
		{
			name:    "pnpm prune allowed",
			command: "pnpm prune",
			wantErr: false,
		},

		// pnpm dlx variants (all blocked)
		{
			name:      "pnpm dlx blocked",
			command:   "pnpm dlx cowsay hello",
			wantErr:   true,
			errSubstr: "pnpm dlx is not allowed",
		},
		{
			name:      "pnpm dlx with flags blocked",
			command:   "pnpm dlx -y cowsay hello",
			wantErr:   true,
			errSubstr: "pnpm dlx is not allowed",
		},
		{
			name:      "pnpm dlx with package@version blocked",
			command:   "pnpm dlx cowsay@latest hello",
			wantErr:   true,
			errSubstr: "pnpm dlx is not allowed",
		},

		// pnpm publish
		{
			name:      "pnpm publish blocked by default",
			command:   "pnpm publish",
			wantErr:   true,
			errSubstr: "pnpm publish is not allowed",
		},
		{
			name:      "pnpm publish blocked when publish=false",
			command:   "pnpm publish",
			wantErr:   true,
			errSubstr: "pnpm publish is not allowed",
		},
		{
			name:    "pnpm publish allowed when publish=true",
			command: "pnpm publish",
			allow:   true,
			wantErr: false,
		},
		{
			name:    "pnpm publish with flags allowed when publish=true",
			command: "pnpm publish --tag beta",
			allow:   true,
			wantErr: false,
		},

		// Edge cases
		{
			name:    "bare pnpm command allowed",
			command: "pnpm",
			wantErr: false,
		},
		{
			name:    "pnpm with only flags allowed",
			command: "pnpm --version",
			wantErr: false,
		},
		{
			name:    "pnpm with -C flag allowed",
			command: "pnpm -C /path/to/dir install",
			wantErr: false,
		},
		{
			name:    "pnpm with --dir flag allowed",
			command: "pnpm --dir /path/to/dir install",
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

			err = validatePnpmArgs(args, tt.allow)
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
