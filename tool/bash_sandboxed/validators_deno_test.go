package bash_sandboxed

import (
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

func TestValidateDenoArgs(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		denoCfg   *config.DenoConfig
		wantErr   bool
		errSubstr string
	}{
		// Basic allowed commands
		{
			name:    "deno run allowed",
			command: "deno run main.ts",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno run with allow flags allowed",
			command: "deno run --allow-read --allow-net main.ts",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno test allowed",
			command: "deno test",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno check allowed",
			command: "deno check main.ts",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno fmt allowed",
			command: "deno fmt",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno lint allowed",
			command: "deno lint",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno bench allowed",
			command: "deno bench",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno task allowed",
			command: "deno task build",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno add allowed",
			command: "deno add jsr:@std/path",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno remove allowed",
			command: "deno remove @std/path",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno install allowed",
			command: "deno install",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno compile allowed",
			command: "deno compile main.ts",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno info allowed",
			command: "deno info",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno eval allowed",
			command: "deno eval 'console.log(1)'",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},

		// deno publish
		{
			name:      "deno publish blocked by default",
			command:   "deno publish",
			denoCfg:   &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "runtimes.deno.publish is disabled",
		},
		{
			name:      "deno publish blocked when publish=false",
			command:   "deno publish",
			denoCfg:   &config.DenoConfig{Enabled: boolPtr(true), Publish: boolPtr(false)},
			wantErr:   true,
			errSubstr: "runtimes.deno.publish is disabled",
		},
		{
			name:    "deno publish allowed when publish=true",
			command: "deno publish",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true), Publish: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno publish with flags allowed when publish=true",
			command: "deno publish --dry-run",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true), Publish: boolPtr(true)},
			wantErr: false,
		},

		// Blocked subcommands
		{
			name:      "deno upgrade blocked",
			command:   "deno upgrade",
			denoCfg:   &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "not allowed",
		},

		// Edge cases
		{
			name:    "bare deno command allowed",
			command: "deno",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno with only flags allowed",
			command: "deno --version",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
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

			err = validateDenoArgs(args, tt.denoCfg)
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

func TestApplyDenoAutoSandbox(t *testing.T) {
	read := []string{"/work", "/tmp"}
	write := []string{"/work"}

	tests := []struct {
		name     string
		args     []string
		read     []string
		write    []string
		allowNet bool
		want     []string
	}{
		{
			name:  "run gets read, write, and deny-net injected after subcommand",
			args:  []string{"deno", "run", "main.ts"},
			read:  read,
			write: write,
			want:  []string{"deno", "run", "--allow-read=/work,/tmp", "--allow-write=/work", "--deny-net", "main.ts"},
		},
		{
			name:     "allow_network true omits deny-net",
			args:     []string{"deno", "run", "main.ts"},
			read:     read,
			write:    write,
			allowNet: true,
			want:     []string{"deno", "run", "--allow-read=/work,/tmp", "--allow-write=/work", "main.ts"},
		},
		{
			name:  "global flags before subcommand are preserved",
			args:  []string{"deno", "--quiet", "run", "main.ts"},
			read:  read,
			write: write,
			want:  []string{"deno", "--quiet", "run", "--allow-read=/work,/tmp", "--allow-write=/work", "--deny-net", "main.ts"},
		},
		{
			name:  "existing allow-read is not duplicated but net still denied",
			args:  []string{"deno", "run", "--allow-read=/custom", "main.ts"},
			read:  read,
			write: write,
			want:  []string{"deno", "run", "--allow-write=/work", "--deny-net", "--allow-read=/custom", "main.ts"},
		},
		{
			name:  "allow-all keeps fs scope but net is force-denied",
			args:  []string{"deno", "run", "-A", "main.ts"},
			read:  read,
			write: write,
			want:  []string{"deno", "run", "--deny-net", "-A", "main.ts"},
		},
		{
			name:     "allow-all with allow_network true is untouched",
			args:     []string{"deno", "run", "-A", "main.ts"},
			read:     read,
			write:    write,
			allowNet: true,
			want:     []string{"deno", "run", "-A", "main.ts"},
		},
		{
			name:  "existing deny-net not duplicated",
			args:  []string{"deno", "run", "--deny-net", "-A", "main.ts"},
			read:  read,
			write: write,
			want:  []string{"deno", "run", "--deny-net", "-A", "main.ts"},
		},
		{
			name:  "non-permission subcommand is untouched",
			args:  []string{"deno", "fmt"},
			read:  read,
			write: write,
			want:  []string{"deno", "fmt"},
		},
		{
			name:  "install gets flags injected",
			args:  []string{"deno", "install"},
			read:  read,
			write: write,
			want:  []string{"deno", "install", "--allow-read=/work,/tmp", "--allow-write=/work", "--deny-net"},
		},
		{
			name:  "empty paths still deny net",
			args:  []string{"deno", "run", "main.ts"},
			read:  nil,
			write: nil,
			want:  []string{"deno", "run", "--deny-net", "main.ts"},
		},
		{
			name:     "empty paths and allow_network true inject nothing",
			args:     []string{"deno", "run", "main.ts"},
			read:     nil,
			write:    nil,
			allowNet: true,
			want:     []string{"deno", "run", "main.ts"},
		},
		{
			name:  "bare deno untouched",
			args:  []string{"deno"},
			read:  read,
			write: write,
			want:  []string{"deno"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyDenoAutoSandbox(tt.args, tt.read, tt.write, tt.allowNet)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestDenoConfig(t *testing.T) {
	tests := []struct {
		name        string
		cfg         *config.DenoConfig
		wantEnabled bool
		wantPublish bool
	}{
		{"nil config", nil, false, false},
		{"empty config", &config.DenoConfig{}, false, false},
		{"enabled", &config.DenoConfig{Enabled: boolPtr(true)}, true, false},
		{"enabled with publish", &config.DenoConfig{Enabled: boolPtr(true), Publish: boolPtr(true)}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.DenoEnabled(); got != tt.wantEnabled {
				t.Errorf("DenoEnabled() = %v, want %v", got, tt.wantEnabled)
			}
			if got := tt.cfg.DenoPublish(); got != tt.wantPublish {
				t.Errorf("DenoPublish() = %v, want %v", got, tt.wantPublish)
			}
		})
	}
}
