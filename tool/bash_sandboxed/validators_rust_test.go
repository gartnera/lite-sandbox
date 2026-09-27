package bash_sandboxed

import (
	"testing"

	"mvdan.cc/sh/v3/syntax"
)

func TestValidateCargoArgs(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		allow     bool
		wantErr   bool
		errSubstr string
	}{
		// Basic allowed commands
		{
			name:    "cargo build allowed",
			command: "cargo build",
			wantErr: false,
		},
		{
			name:    "cargo build --release allowed",
			command: "cargo build --release",
			wantErr: false,
		},
		{
			name:    "cargo check allowed",
			command: "cargo check",
			wantErr: false,
		},
		{
			name:    "cargo test allowed",
			command: "cargo test",
			wantErr: false,
		},
		{
			name:    "cargo test with filter allowed",
			command: "cargo test my_test",
			wantErr: false,
		},
		{
			name:    "cargo run allowed",
			command: "cargo run",
			wantErr: false,
		},
		{
			name:    "cargo run with args allowed",
			command: "cargo run -- --arg1 value",
			wantErr: false,
		},
		{
			name:    "cargo fmt allowed",
			command: "cargo fmt",
			wantErr: false,
		},
		{
			name:    "cargo clippy allowed",
			command: "cargo clippy",
			wantErr: false,
		},
		{
			name:    "cargo clippy with args allowed",
			command: "cargo clippy -- -D warnings",
			wantErr: false,
		},
		{
			name:    "cargo add allowed",
			command: "cargo add serde",
			wantErr: false,
		},
		{
			name:    "cargo remove allowed",
			command: "cargo remove serde",
			wantErr: false,
		},
		{
			name:    "cargo new allowed",
			command: "cargo new my-project",
			wantErr: false,
		},
		{
			name:    "cargo init allowed",
			command: "cargo init",
			wantErr: false,
		},
		{
			name:    "cargo doc allowed",
			command: "cargo doc --open",
			wantErr: false,
		},
		{
			name:    "cargo clean allowed",
			command: "cargo clean",
			wantErr: false,
		},
		{
			name:    "cargo bench allowed",
			command: "cargo bench",
			wantErr: false,
		},
		{
			name:    "cargo update allowed",
			command: "cargo update",
			wantErr: false,
		},
		{
			name:    "cargo tree allowed",
			command: "cargo tree",
			wantErr: false,
		},
		{
			name:    "cargo metadata allowed",
			command: "cargo metadata --format-version 1",
			wantErr: false,
		},
		{
			name:    "cargo fix allowed",
			command: "cargo fix --allow-dirty",
			wantErr: false,
		},
		{
			name:    "cargo version allowed",
			command: "cargo version",
			wantErr: false,
		},

		// cargo install variants
		{
			name:    "cargo install --path local allowed",
			command: "cargo install --path .",
			wantErr: false,
		},
		{
			name:    "cargo install --path=local allowed",
			command: "cargo install --path=./my-crate",
			wantErr: false,
		},
		{
			name:      "cargo install remote crate blocked",
			command:   "cargo install ripgrep",
			wantErr:   true,
			errSubstr: "remote crate references",
		},
		{
			name:      "cargo install remote crate with version blocked",
			command:   "cargo install ripgrep --version 13.0.0",
			wantErr:   true,
			errSubstr: "remote crate references",
		},

		// cargo publish
		{
			name:      "cargo publish blocked by default",
			command:   "cargo publish",
			wantErr:   true,
			errSubstr: "cargo publish is not allowed",
		},
		{
			name:      "cargo publish blocked when publish=false",
			command:   "cargo publish",
			wantErr:   true,
			errSubstr: "cargo publish is not allowed",
		},
		{
			name:    "cargo publish allowed when publish=true",
			command: "cargo publish",
			allow:   true,
			wantErr: false,
		},
		{
			name:    "cargo publish with flags allowed when publish=true",
			command: "cargo publish --dry-run",
			allow:   true,
			wantErr: false,
		},

		// Blocked subcommands
		{
			name:      "cargo login blocked",
			command:   "cargo login",
			wantErr:   true,
			errSubstr: "not allowed",
		},
		{
			name:      "cargo logout blocked",
			command:   "cargo logout",
			wantErr:   true,
			errSubstr: "not allowed",
		},
		{
			name:      "cargo owner blocked",
			command:   "cargo owner --add user",
			wantErr:   true,
			errSubstr: "not allowed",
		},
		{
			name:      "cargo yank blocked",
			command:   "cargo yank --vers 1.0.0",
			wantErr:   true,
			errSubstr: "not allowed",
		},

		// Edge cases
		{
			name:    "bare cargo command allowed",
			command: "cargo",
			wantErr: false,
		},
		{
			name:    "cargo with only flags allowed",
			command: "cargo --version",
			wantErr: false,
		},
		{
			name:    "cargo with -C flag allowed",
			command: "cargo -C /path/to/dir build",
			wantErr: false,
		},
		{
			name:    "cargo with --manifest-path flag allowed",
			command: "cargo --manifest-path Cargo.toml build",
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

			err = validateCargoArgs(args, tt.allow)
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
