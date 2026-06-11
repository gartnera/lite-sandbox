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

		// Fetch subcommands gated behind allow_import
		{
			name:      "deno cache blocked when allow_import disabled",
			command:   "deno cache https://example.com/mod.ts",
			denoCfg:   &config.DenoConfig{Enabled: boolPtr(true), AllowImport: boolPtr(false)},
			wantErr:   true,
			errSubstr: "runtimes.deno.allow_import is disabled",
		},
		{
			name:      "deno add blocked when allow_import disabled",
			command:   "deno add jsr:@std/path",
			denoCfg:   &config.DenoConfig{Enabled: boolPtr(true), AllowImport: boolPtr(false)},
			wantErr:   true,
			errSubstr: "runtimes.deno.allow_import is disabled",
		},
		{
			name:      "deno install blocked when allow_import disabled",
			command:   "deno install",
			denoCfg:   &config.DenoConfig{Enabled: boolPtr(true), AllowImport: boolPtr(false)},
			wantErr:   true,
			errSubstr: "runtimes.deno.allow_import is disabled",
		},
		{
			name:    "deno cache allowed when allow_import enabled (default)",
			command: "deno cache https://example.com/mod.ts",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "deno run not gated by allow_import (handled via injected deny-import)",
			command: "deno run main.ts",
			denoCfg: &config.DenoConfig{Enabled: boolPtr(true), AllowImport: boolPtr(false)},
			wantErr: false,
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

func TestApplyDenoSandbox(t *testing.T) {
	read := []string{"/work", "/tmp"}
	write := []string{"/work"}

	tests := []struct {
		name        string
		args        []string
		read        []string
		write       []string
		autoSandbox bool
		allowNet    bool
		allowImport bool
		want        []string
	}{
		{
			// Defaults: auto_sandbox on, network off, imports allowed.
			name:        "default: read, write, deny-net injected (imports allowed, no deny-import)",
			args:        []string{"deno", "run", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "run", "--allow-read=/work,/tmp", "--allow-write=/work", "--deny-net", "main.ts"},
		},
		{
			name:        "allow_import false adds deny-import",
			args:        []string{"deno", "run", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: false,
			want:        []string{"deno", "run", "--allow-read=/work,/tmp", "--allow-write=/work", "--deny-net", "--deny-import", "main.ts"},
		},
		{
			name:        "auto_sandbox off still denies net (no allow-read/write injected)",
			args:        []string{"deno", "run", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: false,
			allowImport: true,
			want:        []string{"deno", "run", "--deny-net", "main.ts"},
		},
		{
			name:        "auto_sandbox off with allow_import false denies net and import only",
			args:        []string{"deno", "run", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: false,
			allowImport: false,
			want:        []string{"deno", "run", "--deny-net", "--deny-import", "main.ts"},
		},
		{
			name:        "allow_network true and allow_import true inject only fs scope",
			args:        []string{"deno", "run", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowNet:    true,
			allowImport: true,
			want:        []string{"deno", "run", "--allow-read=/work,/tmp", "--allow-write=/work", "main.ts"},
		},
		{
			name:        "all allowed and auto_sandbox off is a no-op",
			args:        []string{"deno", "run", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: false,
			allowNet:    true,
			allowImport: true,
			want:        []string{"deno", "run", "main.ts"},
		},
		{
			name:        "global flags before subcommand are preserved",
			args:        []string{"deno", "--quiet", "run", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "--quiet", "run", "--allow-read=/work,/tmp", "--allow-write=/work", "--deny-net", "main.ts"},
		},
		{
			name:        "existing allow-read is not duplicated but net still denied",
			args:        []string{"deno", "run", "--allow-read=/custom", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "run", "--allow-write=/work", "--deny-net", "--allow-read=/custom", "main.ts"},
		},
		{
			name:        "short -R and -W are recognized as read/write grants",
			args:        []string{"deno", "run", "-R", "-W", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "run", "--deny-net", "-R", "-W", "main.ts"},
		},
		{
			// Script args after the script file must NOT be read as deno perms.
			name:        "permission-looking script args after script are not treated as grants",
			args:        []string{"deno", "run", "main.ts", "-A", "-W", "--allow-read=/etc"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "run", "--allow-read=/work,/tmp", "--allow-write=/work", "--deny-net", "main.ts", "-A", "-W", "--allow-read=/etc"},
		},
		{
			name:        "deno flags before the script are still scanned",
			args:        []string{"deno", "run", "--allow-read=/custom", "main.ts", "-A"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "run", "--allow-write=/work", "--deny-net", "--allow-read=/custom", "main.ts", "-A"},
		},
		{
			name:        "bundled short -RW is recognized as read and write grants",
			args:        []string{"deno", "run", "-RW", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "run", "--deny-net", "-RW", "main.ts"},
		},
		{
			name:        "allow-all keeps fs scope but net is force-denied",
			args:        []string{"deno", "run", "-A", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "run", "--deny-net", "-A", "main.ts"},
		},
		{
			name:        "allow-all with network and imports allowed is untouched",
			args:        []string{"deno", "run", "-A", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowNet:    true,
			allowImport: true,
			want:        []string{"deno", "run", "-A", "main.ts"},
		},
		{
			name:        "existing deny-net not duplicated",
			args:        []string{"deno", "run", "--deny-net", "-A", "main.ts"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "run", "--deny-net", "-A", "main.ts"},
		},
		{
			name:        "non-permission subcommand is untouched",
			args:        []string{"deno", "fmt"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "fmt"},
		},
		{
			name:        "install gets flags injected",
			args:        []string{"deno", "install"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "install", "--allow-read=/work,/tmp", "--allow-write=/work", "--deny-net"},
		},
		{
			name:        "empty paths still deny net",
			args:        []string{"deno", "run", "main.ts"},
			read:        nil,
			write:       nil,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno", "run", "--deny-net", "main.ts"},
		},
		{
			name:        "bare deno untouched",
			args:        []string{"deno"},
			read:        read,
			write:       write,
			autoSandbox: true,
			allowImport: true,
			want:        []string{"deno"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := applyDenoSandbox(tt.args, tt.read, tt.write, tt.autoSandbox, tt.allowNet, tt.allowImport)
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
		wantAuto    bool
		wantNetwork bool
		wantImport  bool
	}{
		// auto_sandbox and allow_import default to true; the rest default to false.
		{"nil config", nil, false, false, true, false, true},
		{"empty config", &config.DenoConfig{}, false, false, true, false, true},
		{"enabled", &config.DenoConfig{Enabled: boolPtr(true)}, true, false, true, false, true},
		{"enabled with publish", &config.DenoConfig{Enabled: boolPtr(true), Publish: boolPtr(true)}, true, true, true, false, true},
		{"auto_sandbox disabled", &config.DenoConfig{Enabled: boolPtr(true), AutoSandbox: boolPtr(false)}, true, false, false, false, true},
		{"network allowed", &config.DenoConfig{Enabled: boolPtr(true), AllowNetwork: boolPtr(true)}, true, false, true, true, true},
		{"import disabled", &config.DenoConfig{Enabled: boolPtr(true), AllowImport: boolPtr(false)}, true, false, true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.DenoEnabled(); got != tt.wantEnabled {
				t.Errorf("DenoEnabled() = %v, want %v", got, tt.wantEnabled)
			}
			if got := tt.cfg.DenoPublish(); got != tt.wantPublish {
				t.Errorf("DenoPublish() = %v, want %v", got, tt.wantPublish)
			}
			if got := tt.cfg.DenoAutoSandbox(); got != tt.wantAuto {
				t.Errorf("DenoAutoSandbox() = %v, want %v", got, tt.wantAuto)
			}
			if got := tt.cfg.DenoAllowNetwork(); got != tt.wantNetwork {
				t.Errorf("DenoAllowNetwork() = %v, want %v", got, tt.wantNetwork)
			}
			if got := tt.cfg.DenoAllowImport(); got != tt.wantImport {
				t.Errorf("DenoAllowImport() = %v, want %v", got, tt.wantImport)
			}
		})
	}
}
