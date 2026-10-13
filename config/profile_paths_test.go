package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// fakePnpm installs a stub pnpm executable on PATH that answers the
// detection queries: `store path` prints a fixed store, `config get cache-dir`
// and `config get global-dir` print $FAKE_PNPM_CACHE_DIR and
// $FAKE_PNPM_GLOBAL_DIR, or "undefined" (pnpm's output when the setting is
// unset).
func fakePnpm(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := `#!/bin/sh
case "$1 $3" in
"store "*) echo /fake/pnpm-store ;;
"config cache-dir") echo "${FAKE_PNPM_CACHE_DIR:-undefined}" ;;
"config global-dir") echo "${FAKE_PNPM_GLOBAL_DIR:-undefined}" ;;
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
	t.Setenv("PNPM_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")

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

	t.Run("default global dir", func(t *testing.T) {
		pnpmHome := filepath.Join(t.TempDir(), "pnpm-home")
		t.Setenv("PNPM_HOME", pnpmHome)
		globalDir := filepath.Join(pnpmHome, "global")
		paths := detectPnpmBinds()
		if !slices.Contains(paths, globalDir) {
			t.Errorf("expected detected paths to contain default global dir %q, got %v", globalDir, paths)
		}
		// Only the global dir: the pnpm home's bin/ is on the user's PATH.
		if slices.Contains(paths, pnpmHome) {
			t.Errorf("expected detected paths not to contain the pnpm home %q, got %v", pnpmHome, paths)
		}
		if _, err := os.Stat(globalDir); err != nil {
			t.Errorf("expected default global dir to be created: %v", err)
		}
	})

	t.Run("configured global dir", func(t *testing.T) {
		globalDir := filepath.Join(t.TempDir(), "pnpm-global")
		t.Setenv("FAKE_PNPM_GLOBAL_DIR", globalDir)
		paths := detectPnpmBinds()
		if !slices.Contains(paths, globalDir) {
			t.Errorf("expected detected paths to contain configured global dir %q, got %v", globalDir, paths)
		}
	})
}

func TestPnpmHomeDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	t.Setenv("PNPM_HOME", "/custom/pnpm")
	t.Setenv("XDG_DATA_HOME", "/xdg/data")
	if got := pnpmHomeDir(); got != "/custom/pnpm" {
		t.Errorf("PNPM_HOME set: got %q", got)
	}

	t.Setenv("PNPM_HOME", "")
	if got, want := pnpmHomeDir(), filepath.Join("/xdg/data", "pnpm"); got != want {
		t.Errorf("XDG_DATA_HOME set: got %q, want %q", got, want)
	}

	t.Setenv("XDG_DATA_HOME", "")
	want := filepath.Join(home, ".local", "share", "pnpm")
	switch runtime.GOOS {
	case "darwin":
		want = filepath.Join(home, "Library", "pnpm")
	case "windows":
		t.Skip("default depends on LOCALAPPDATA")
	}
	if got := pnpmHomeDir(); got != want {
		t.Errorf("default: got %q, want %q", got, want)
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

func TestXcodeBindsFor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	darwin := xcodeBindsFor("darwin", func(string) bool { t.Fatal("darwin must not look for tools"); return false })
	want := []string{
		filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData"),
		filepath.Join(home, "Library", "Developer", "Xcode", "Archives"),
		filepath.Join(home, "Library", "Caches", "org.swift.swiftpm"),
		filepath.Join(home, "Library", "org.swift.swiftpm"),
		filepath.Join(home, ".xcodegen"),
	}
	if !slices.Equal(darwin, want) {
		t.Errorf("darwin = %v, want %v", darwin, want)
	}
	for _, p := range darwin {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was created; sandbox-exec does not need it to exist", p)
		}
	}

	// The legacy ~/.swiftpm is added only when it exists.
	if err := os.Mkdir(filepath.Join(home, ".swiftpm"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := xcodeBindsFor("darwin", nil); !slices.Contains(got, filepath.Join(home, ".swiftpm")) {
		t.Errorf("darwin with ~/.swiftpm = %v, want it included", got)
	}

	if got := xcodeBindsFor("linux", func(string) bool { return false }); got != nil {
		t.Errorf("linux without swift or xcodegen = %v, want nil (bubblewrap would create them)", got)
	}
	linux := xcodeBindsFor("linux", func(string) bool { return true })
	want = []string{
		filepath.Join(home, ".cache", "org.swift.swiftpm"),
		filepath.Join(home, ".cache", "clang", "ModuleCache"),
		filepath.Join(home, ".swiftpm"),
		filepath.Join(home, ".xcodegen"),
	}
	if !slices.Equal(linux, want) {
		t.Errorf("linux = %v, want %v", linux, want)
	}
	// SwiftPM keeps its state under XDG_CONFIG_HOME when that is set.
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	if got := xcodeBindsFor("linux", func(string) bool { return true }); !slices.Contains(got, filepath.Join(home, "cfg", "swiftpm")) || slices.Contains(got, filepath.Join(home, ".swiftpm")) {
		t.Errorf("linux with XDG_CONFIG_HOME = %v, want $XDG_CONFIG_HOME/swiftpm in place of ~/.swiftpm", got)
	}
	if got := xcodeBindsFor("linux", func(tool string) bool { return tool == "xcodegen" }); !slices.Equal(got, []string{filepath.Join(home, ".xcodegen")}) {
		t.Errorf("linux with only xcodegen = %v", got)
	}
}

func TestXcodeSimulatorDataFor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	want := []string{filepath.Join(home, "Library", "Developer", "CoreSimulator", "Devices")}
	if got := xcodeSimulatorDataFor("darwin"); !slices.Equal(got, want) {
		t.Errorf("darwin = %v, want %v", got, want)
	}
	if _, err := os.Stat(want[0]); err == nil {
		t.Errorf("%s was created; sandbox-exec does not need it to exist", want[0])
	}
	if got := xcodeSimulatorDataFor("linux"); got != nil {
		t.Errorf("linux = %v, want nil (there are no simulators)", got)
	}
}

func TestDetectXcodeDeveloperDir(t *testing.T) {
	fakeDeveloperDir := func(tool string) string {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "usr", "bin"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "usr", "bin", tool), nil, 0o755); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	xcode := fakeDeveloperDir("xcodebuild")
	clt := fakeDeveloperDir("clang")

	link := filepath.Join(t.TempDir(), "xcode_select_link")
	if err := os.Symlink(clt, link); err != nil {
		t.Fatal(err)
	}
	old := xcodeSelectLink
	xcodeSelectLink = link
	t.Cleanup(func() { xcodeSelectLink = old })

	t.Setenv("DEVELOPER_DIR", "")
	if got := detectXcodeDeveloperDir(); got != clt {
		t.Errorf("from the xcode-select link = %q, want %q", got, clt)
	}
	t.Setenv("DEVELOPER_DIR", xcode)
	if got := detectXcodeDeveloperDir(); got != xcode {
		t.Errorf("DEVELOPER_DIR = %q, want %q", got, xcode)
	}
	// A DEVELOPER_DIR that holds no developer tools must not widen what the
	// agent may read; the link is used instead.
	t.Setenv("DEVELOPER_DIR", t.TempDir())
	if got := detectXcodeDeveloperDir(); got != clt {
		t.Errorf("bogus DEVELOPER_DIR = %q, want the link's %q", got, clt)
	}
	xcodeSelectLink = filepath.Join(t.TempDir(), "missing")
	if got := detectXcodeDeveloperDir(); got != "" {
		t.Errorf("no developer dir = %q, want empty", got)
	}
}
