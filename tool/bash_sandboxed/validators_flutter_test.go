package bash_sandboxed

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

func TestValidateFlutterRuntimeGate(t *testing.T) {
	enabled := &config.RuntimesConfig{Flutter: &config.FlutterConfig{Enabled: boolPtr(true)}}
	disabled := &config.RuntimesConfig{Flutter: &config.FlutterConfig{Enabled: boolPtr(false)}}

	tests := []struct {
		name      string
		command   string
		runtimes  *config.RuntimesConfig
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "flutter allowed when enabled",
			command:  "flutter test",
			runtimes: enabled,
			wantErr:  false,
		},
		{
			name:     "dart allowed when enabled",
			command:  "dart pub get",
			runtimes: enabled,
			wantErr:  false,
		},
		{
			name:     "fvm allowed when enabled",
			command:  "fvm flutter build apk",
			runtimes: enabled,
			wantErr:  false,
		},
		{
			name:      "flutter blocked when disabled",
			command:   "flutter test",
			runtimes:  disabled,
			wantErr:   true,
			errSubstr: `command "flutter" is not allowed (runtimes.flutter.enabled is disabled)`,
		},
		{
			name:      "dart blocked by default",
			command:   "dart run",
			runtimes:  nil,
			wantErr:   true,
			errSubstr: `command "dart" is not allowed (runtimes.flutter.enabled is disabled)`,
		},
		{
			name:      "fvm blocked by default",
			command:   "fvm use stable",
			runtimes:  nil,
			wantErr:   true,
			errSubstr: `command "fvm" is not allowed (runtimes.flutter.enabled is disabled)`,
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
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestDetectFlutterBinds(t *testing.T) {
	home := t.TempDir()
	fvmCache := filepath.Join(t.TempDir(), "fvm-cache")
	pubCache := filepath.Join(t.TempDir(), "pub-cache")

	// Build a fake Flutter SDK root: it needs a packages/ dir to be recognized
	// and a bin/flutter binary so FLUTTER_ROOT resolution accepts it.
	sdkRoot := t.TempDir()
	mustMkdir(t, filepath.Join(sdkRoot, "packages"))

	t.Setenv("HOME", home)
	t.Setenv("FVM_CACHE_PATH", fvmCache)
	t.Setenv("PUB_CACHE", pubCache)
	t.Setenv("FLUTTER_ROOT", sdkRoot)

	paths := detectFlutterBinds()

	want := []string{
		fvmCache,
		pubCache,
		sdkRoot,
		filepath.Join(home, ".config", "flutter"),
		filepath.Join(home, ".config", "dart"),
		filepath.Join(home, ".flutter"),
		filepath.Join(home, ".dart"),
	}
	for _, w := range want {
		if !slices.Contains(paths, w) {
			t.Errorf("expected detected paths to contain %q, got %v", w, paths)
		}
	}
}

func TestDetectFlutterSDKRootRejectsNonSDK(t *testing.T) {
	// A FLUTTER_ROOT that is not a real SDK checkout (no packages/ dir) must be
	// rejected so it can't widen access to an arbitrary directory.
	t.Setenv("FLUTTER_ROOT", t.TempDir())
	// Ensure no flutter binary on PATH influences the result.
	t.Setenv("PATH", t.TempDir())
	if got := detectFlutterSDKRoot(); got != "" {
		t.Errorf("expected empty SDK root for non-SDK FLUTTER_ROOT, got %q", got)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if ensureDir(dir) == "" {
		t.Fatalf("failed to create dir %q", dir)
	}
}
