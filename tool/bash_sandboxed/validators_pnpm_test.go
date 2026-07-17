package bash_sandboxed

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
	"mvdan.cc/sh/v3/syntax"
)

func TestValidatePnpmArgs(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		pnpmCfg   *config.PnpmConfig
		wantErr   bool
		errSubstr string
	}{
		// Basic allowed commands
		{
			name:    "pnpm install allowed",
			command: "pnpm install",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm add allowed",
			command: "pnpm add react",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm remove allowed",
			command: "pnpm remove lodash",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm update allowed",
			command: "pnpm update",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm test allowed",
			command: "pnpm test",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm run allowed",
			command: "pnpm run build",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm list allowed",
			command: "pnpm list",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm outdated allowed",
			command: "pnpm outdated",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm why allowed",
			command: "pnpm why react",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm audit allowed",
			command: "pnpm audit",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm exec allowed",
			command: "pnpm exec eslint .",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm create allowed",
			command: "pnpm create vite",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm init allowed",
			command: "pnpm init",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm store status allowed",
			command: "pnpm store status",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm prune allowed",
			command: "pnpm prune",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},

		// pnpm dlx variants (all blocked)
		{
			name:      "pnpm dlx blocked",
			command:   "pnpm dlx cowsay hello",
			pnpmCfg:   &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "pnpm dlx is not allowed",
		},
		{
			name:      "pnpm dlx with flags blocked",
			command:   "pnpm dlx -y cowsay hello",
			pnpmCfg:   &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "pnpm dlx is not allowed",
		},
		{
			name:      "pnpm dlx with package@version blocked",
			command:   "pnpm dlx cowsay@latest hello",
			pnpmCfg:   &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "pnpm dlx is not allowed",
		},

		// pnpm publish
		{
			name:      "pnpm publish blocked by default",
			command:   "pnpm publish",
			pnpmCfg:   &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr:   true,
			errSubstr: "runtimes.pnpm.publish is disabled",
		},
		{
			name:      "pnpm publish blocked when publish=false",
			command:   "pnpm publish",
			pnpmCfg:   &config.PnpmConfig{Enabled: boolPtr(true), Publish: boolPtr(false)},
			wantErr:   true,
			errSubstr: "runtimes.pnpm.publish is disabled",
		},
		{
			name:    "pnpm publish allowed when publish=true",
			command: "pnpm publish",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true), Publish: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm publish with flags allowed when publish=true",
			command: "pnpm publish --tag beta",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true), Publish: boolPtr(true)},
			wantErr: false,
		},

		// Edge cases
		{
			name:    "bare pnpm command allowed",
			command: "pnpm",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm with only flags allowed",
			command: "pnpm --version",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm with -C flag allowed",
			command: "pnpm -C /path/to/dir install",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
			wantErr: false,
		},
		{
			name:    "pnpm with --dir flag allowed",
			command: "pnpm --dir /path/to/dir install",
			pnpmCfg: &config.PnpmConfig{Enabled: boolPtr(true)},
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

			err = validatePnpmArgs(args, tt.pnpmCfg)
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

// fakePnpm installs a stub pnpm executable on PATH that answers the two
// detection queries: `store path` prints a fixed store, `config get cache-dir`
// prints $FAKE_PNPM_CACHE_DIR or "undefined" (pnpm's output when the setting
// is unset).
func fakePnpm(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := `#!/bin/sh
case "$1" in
store) echo /fake/pnpm-store ;;
config) echo "${FAKE_PNPM_CACHE_DIR:-undefined}" ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "pnpm"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
}

func TestDetectPnpmBinds(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stub pnpm is a shell script")
	}
	fakePnpm(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())

	t.Run("default cache dir", func(t *testing.T) {
		paths := detectPnpmBinds()
		userCache, err := os.UserCacheDir()
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"/fake/pnpm-store", filepath.Join(userCache, "pnpm")}
		for _, w := range want {
			if !slices.Contains(paths, w) {
				t.Errorf("expected detected paths to contain %q, got %v", w, paths)
			}
		}
		// The cache dir must be materialized so it can serve as a bind-mount source.
		if _, err := os.Stat(filepath.Join(userCache, "pnpm")); err != nil {
			t.Errorf("expected default cache dir to be created: %v", err)
		}
	})

	t.Run("configured cache dir", func(t *testing.T) {
		cacheDir := filepath.Join(t.TempDir(), "pnpm-cache")
		t.Setenv("FAKE_PNPM_CACHE_DIR", cacheDir)
		paths := detectPnpmBinds()
		if !slices.Contains(paths, cacheDir) {
			t.Errorf("expected detected paths to contain configured cache dir %q, got %v", cacheDir, paths)
		}
		if _, err := os.Stat(cacheDir); err != nil {
			t.Errorf("expected configured cache dir to be created: %v", err)
		}
	})
}
