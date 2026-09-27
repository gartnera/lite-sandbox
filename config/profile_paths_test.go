package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

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
