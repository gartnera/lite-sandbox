package config

import (
	"cmp"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// detectGoBinds detects Go environment paths that need to be writable.
// Returns GOPATH and GOCACHE (build cache) directories.
func detectGoBinds() []string {
	cmd := exec.Command("go", "env", "GOPATH", "GOCACHE")
	output, err := cmd.Output()
	if err != nil {
		slog.Warn("failed to detect Go paths", "error", err)
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var paths []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && line != "off" {
			paths = append(paths, line)
		}
	}

	if len(paths) > 0 {
		slog.Info("detected Go runtime paths", "paths", paths)
	}

	return paths
}

// detectPnpmBinds detects pnpm paths that need to be writable.
// Returns the pnpm store directory (downloaded packages) and the pnpm cache
// directory (registry metadata and the `pnpm dlx` cache), which live in
// separate trees (e.g. ~/Library/pnpm/store vs ~/Library/Caches/pnpm on
// macOS). Without the cache dir bound, pnpm invoked inside the sandbox — e.g.
// by a lefthook job or package script — fails with EPERM creating its cache.
func detectPnpmBinds() []string {
	var paths []string

	cmd := exec.Command("pnpm", "store", "path")
	output, err := cmd.Output()
	if err != nil {
		slog.Warn("failed to detect pnpm store path", "error", err)
	} else if storePath := strings.TrimSpace(string(output)); storePath != "" {
		paths = append(paths, storePath)
	}

	// `pnpm config get cache-dir` prints "undefined" when the setting is
	// unset; pnpm then defaults to the OS cache dir joined with "pnpm".
	// pnpm creates cache subdirs lazily, so materialize the directory up
	// front — a bind-mount source must exist for the OS sandbox to mount it.
	cacheDir := ""
	if output, err := exec.Command("pnpm", "config", "get", "cache-dir").Output(); err != nil {
		slog.Warn("failed to detect pnpm cache dir", "error", err)
	} else {
		cacheDir = strings.TrimSpace(string(output))
	}
	if cacheDir == "" || cacheDir == "undefined" {
		if userCache, err := os.UserCacheDir(); err == nil {
			cacheDir = filepath.Join(userCache, "pnpm")
		} else {
			cacheDir = ""
		}
	}
	if p := ensureDir(cacheDir); p != "" {
		paths = append(paths, p)
	}

	if len(paths) > 0 {
		slog.Info("detected pnpm runtime paths", "paths", paths)
	}
	return paths
}

// existingHomeSubdir resolves a runtime directory that is configured by an
// environment variable and otherwise defaults to a subdirectory of the user's
// home. It returns "" when the variable is unset and no home directory can be
// resolved, or when the resulting directory does not exist — unlike the caches
// materialized by ensureDir, these are never created here, so a toolchain that
// is not installed contributes no bind.
func existingHomeSubdir(envVar, homeSubdir string) string {
	dir := os.Getenv(envVar)
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = home + "/" + homeSubdir
		}
	}
	if dir == "" {
		return ""
	}
	if _, err := os.Stat(dir); err != nil {
		return ""
	}
	return dir
}

// detectRustBinds detects Rust/Cargo paths that need to be writable.
// Returns CARGO_HOME (registry, git) and RUSTUP_HOME directories.
func detectRustBinds() []string {
	var paths []string

	// CARGO_HOME defaults to ~/.cargo; RUSTUP_HOME defaults to ~/.rustup.
	for _, d := range []struct{ envVar, homeSubdir string }{
		{"CARGO_HOME", ".cargo"},
		{"RUSTUP_HOME", ".rustup"},
	} {
		if p := existingHomeSubdir(d.envVar, d.homeSubdir); p != "" {
			paths = append(paths, p)
		}
	}

	if len(paths) > 0 {
		slog.Info("detected Rust runtime paths", "paths", paths)
	}

	return paths
}

// detectDenoBinds detects Deno paths that need to be writable.
// Returns DENO_DIR (module/npm cache) and DENO_INSTALL_ROOT (global scripts
// installed via `deno install -g`).
//
// Unlike the other toolchains, deno creates its cache lazily on first run, so
// these directories frequently do not exist yet. We create them up front: a
// bind mount source must exist for the OS sandbox to mount it writable, and
// the sandbox cannot create the directory itself (its parent is not bound), so
// without this the very first `deno run` would fail to populate its cache.
func detectDenoBinds() []string {
	var paths []string

	// Detect DENO_DIR (module and npm cache). Defaults to the OS cache dir
	// joined with "deno" (e.g. ~/.cache/deno on Linux).
	denoDir := os.Getenv("DENO_DIR")
	if denoDir == "" {
		if cacheDir, err := os.UserCacheDir(); err == nil {
			denoDir = filepath.Join(cacheDir, "deno")
		}
	}
	if p := ensureDir(denoDir); p != "" {
		paths = append(paths, p)
	}

	// Detect DENO_INSTALL_ROOT (global executables). Defaults to ~/.deno.
	installRoot := os.Getenv("DENO_INSTALL_ROOT")
	if installRoot == "" {
		if home, err := os.UserHomeDir(); err == nil {
			installRoot = filepath.Join(home, ".deno")
		}
	}
	if p := ensureDir(installRoot); p != "" {
		paths = append(paths, p)
	}

	if len(paths) > 0 {
		slog.Info("detected Deno runtime paths", "paths", paths)
	}

	return paths
}

// detectUvBinds detects the uv (Python package manager) paths that need to be
// writable. uv downloads and builds wheels into its cache, installs Python
// interpreters, and stores tool environments; all live outside the working
// directory, so they must be bound in for uv to function under the OS sandbox:
//   - `uv cache dir`  — the package/wheel cache (default ~/.cache/uv)
//   - `uv python dir` — uv-managed Python interpreters (default ~/.local/share/uv/python)
//   - `uv tool dir`   — tool environments from `uv tool install` (default ~/.local/share/uv/tools)
//
// The tool *bin* directory (`uv tool dir --bin`, default ~/.local/bin) is
// deliberately NOT bound: it lives on the user's PATH, so binding it writable
// would let a sandboxed command install executables that persist and run
// outside the sandbox boundary. `uv tool install` therefore cannot place its
// launcher and fails, which is the intended restriction; `uvx` (ephemeral tool
// runs cached under `uv cache dir`) still works.
//
// Like Deno, uv creates these lazily on first use, so they frequently do not
// exist yet. We create them up front because a bind-mount source must exist for
// the OS sandbox to mount it, and the sandbox cannot create the directory
// itself (its parent is not bound).
func detectUvBinds() []string {
	var paths []string
	seen := map[string]bool{}
	for _, sub := range [][]string{
		{"cache", "dir"},
		{"python", "dir"},
		{"tool", "dir"},
	} {
		cmd := exec.Command("uv", sub...)
		output, err := cmd.Output()
		if err != nil {
			slog.Warn("failed to detect uv path", "subcommand", strings.Join(sub, " "), "error", err)
			continue
		}
		dir := strings.TrimSpace(string(output))
		if p := ensureDir(dir); p != "" && !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}

	if len(paths) > 0 {
		slog.Info("detected uv runtime paths", "paths", paths)
	}

	return paths
}

// ensureDir creates dir (and parents) if needed and returns it, or "" if dir
// is empty or cannot be created. Used to materialize runtime cache directories
// so they exist as bind-mount sources for the OS sandbox.
func ensureDir(dir string) string {
	if dir == "" {
		return ""
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		slog.Warn("failed to create runtime directory", "path", dir, "error", err)
		return ""
	}
	return dir
}

// detectFlutterBinds detects the paths that Flutter, Dart, and fvm read and
// write, so the sandbox can grant access to them automatically (mirroring the
// Go runtime's GOPATH/GOCACHE handling). The paths are:
//
//   - the fvm cache (FVM_CACHE_PATH / legacy FVM_HOME, default ~/fvm), where fvm
//     stores each managed Flutter SDK version;
//   - the pub cache (PUB_CACHE, default ~/.pub-cache), where Dart/Flutter
//     packages are downloaded;
//   - the active Flutter SDK root (FLUTTER_ROOT, or resolved from a flutter
//     binary on PATH), which Flutter writes to under bin/cache;
//   - the Flutter/Dart config directories, where the tools persist settings.
//
// Like the caches for other toolchains these directories are frequently created
// lazily on first run, so cache directories are materialized up front (a bind
// mount source must exist for the OS sandbox to mount it). Only directories that
// exist (or can be created) are returned, so a partial toolchain still works.
func detectFlutterBinds() []string {
	var paths []string
	home, _ := os.UserHomeDir()

	// fvm cache: FVM_CACHE_PATH is the current override, FVM_HOME the legacy one.
	fvmCache := cmp.Or(os.Getenv("FVM_CACHE_PATH"), os.Getenv("FVM_HOME"))
	if fvmCache == "" && home != "" {
		fvmCache = filepath.Join(home, "fvm")
	}
	if p := ensureDir(fvmCache); p != "" {
		paths = append(paths, p)
	}

	// pub cache: PUB_CACHE overrides the default ~/.pub-cache.
	pubCache := os.Getenv("PUB_CACHE")
	if pubCache == "" && home != "" {
		pubCache = filepath.Join(home, ".pub-cache")
	}
	if p := ensureDir(pubCache); p != "" {
		paths = append(paths, p)
	}

	// Active Flutter SDK root (for a non-fvm global install). fvm-managed SDKs
	// live under the fvm cache above, or the project's .fvm/flutter_sdk symlink,
	// which is already under the working directory.
	if sdk := detectFlutterSDKRoot(); sdk != "" {
		paths = append(paths, sdk)
	}

	// Config directories where Flutter and Dart persist settings and analytics
	// state. These already exist on a configured machine; create them so the
	// tools can write on a fresh one.
	if home != "" {
		for _, rel := range []string{
			filepath.Join(".config", "flutter"),
			filepath.Join(".config", "dart"),
			".flutter",
			".dart",
		} {
			if p := ensureDir(filepath.Join(home, rel)); p != "" {
				paths = append(paths, p)
			}
		}
	}

	if len(paths) > 0 {
		slog.Info("detected Flutter runtime paths", "paths", paths)
	}
	return paths
}

// detectFlutterSDKRoot returns the root directory of the active Flutter SDK, or
// "" if it cannot be located. FLUTTER_ROOT wins when set; otherwise a flutter
// binary on PATH is resolved (following symlinks) to <root>/bin/flutter and the
// grandparent is returned. The candidate is only accepted when it looks like a
// Flutter SDK checkout (it contains a packages directory), so a stray binary in
// a system directory like /usr/bin never widens access to /usr.
func detectFlutterSDKRoot() string {
	if root := os.Getenv("FLUTTER_ROOT"); root != "" {
		if isFlutterSDKRoot(root) {
			return root
		}
	}
	bin, err := exec.LookPath("flutter")
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(bin); err == nil {
		bin = resolved
	}
	root := filepath.Dir(filepath.Dir(bin))
	if isFlutterSDKRoot(root) {
		return root
	}
	return ""
}

// isFlutterSDKRoot reports whether dir looks like a Flutter SDK checkout. Every
// SDK ships a top-level packages directory alongside bin/, which distinguishes a
// real SDK from an ordinary bin directory such as /usr/bin.
func isFlutterSDKRoot(dir string) bool {
	if dir == "" {
		return false
	}
	info, err := os.Stat(filepath.Join(dir, "packages"))
	return err == nil && info.IsDir()
}

// detectXcodeBinds returns the directories Xcode's build tools and SwiftPM
// write outside the project, for the xcode profile. On macOS:
//
//   - ~/Library/Developer/Xcode/DerivedData, xcodebuild's build products,
//     index, logs, and the checkouts of a project's Swift packages;
//   - ~/Library/Developer/Xcode/Archives, where `xcodebuild archive` puts the
//     .xcarchive;
//   - ~/Library/Caches/org.swift.swiftpm (repository and manifest caches) and
//     ~/Library/org.swift.swiftpm (configuration and fingerprints), SwiftPM's
//     user-level state for both `swift build` and xcodebuild's package support;
//   - ~/.swiftpm when it exists, where older SwiftPM kept that state;
//   - ~/.xcodegen, where `xcodegen generate --use-cache` keeps its cache.
//
// None are created: sandbox-exec does not need a rule's path to exist, and
// Xcode makes them on first use. On Linux there is no Xcode, only a Swift
// toolchain, whose SwiftPM keeps its state in ~/.cache/org.swift.swiftpm and
// ~/.swiftpm ($XDG_CONFIG_HOME/swiftpm when that is set), and whose swiftc
// writes clang's module cache to ~/.cache/clang/ModuleCache even to compile a
// package manifest; bubblewrap has to create a bind's source, so those are returned
// only when swift is installed, and ~/.xcodegen only when xcodegen is, so a
// host without them gets nothing created.
//
// DerivedData can be moved in Xcode's settings; a moved one needs a paths
// grant, or `-derivedDataPath` inside the project.
func detectXcodeBinds() []string {
	return xcodeBindsFor(runtime.GOOS, func(tool string) bool {
		_, err := exec.LookPath(tool)
		return err == nil
	})
}

func xcodeBindsFor(goos string, installed func(tool string) bool) []string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	var paths []string
	switch goos {
	case "darwin":
		paths = []string{
			filepath.Join(home, "Library", "Developer", "Xcode", "DerivedData"),
			filepath.Join(home, "Library", "Developer", "Xcode", "Archives"),
			filepath.Join(home, "Library", "Caches", "org.swift.swiftpm"),
			filepath.Join(home, "Library", "org.swift.swiftpm"),
			filepath.Join(home, ".xcodegen"),
		}
		if p := existingHomeSubdir("", ".swiftpm"); p != "" {
			paths = append(paths, p)
		}
	case "linux":
		if installed("swift") {
			cache := os.Getenv("XDG_CACHE_HOME")
			if cache == "" {
				cache = filepath.Join(home, ".cache")
			}
			// SwiftPM's dotSwiftPM moves under XDG_CONFIG_HOME when it is set.
			dotSwiftPM := filepath.Join(home, ".swiftpm")
			if config := os.Getenv("XDG_CONFIG_HOME"); config != "" {
				dotSwiftPM = filepath.Join(config, "swiftpm")
			}
			paths = append(paths,
				filepath.Join(cache, "org.swift.swiftpm"),
				filepath.Join(cache, "clang", "ModuleCache"),
				dotSwiftPM,
			)
		}
		if installed("xcodegen") {
			paths = append(paths, filepath.Join(home, ".xcodegen"))
		}
	}
	if len(paths) > 0 {
		slog.Info("detected Xcode profile paths", "paths", paths)
	}
	return paths
}

// xcodeSimulatorDataFor returns where CoreSimulator keeps the simulators'
// data on goos: ~/Library/Developer/CoreSimulator/Devices, one directory per
// simulator holding its device.plist and its data volume (app containers,
// preferences, the simulated home directory). Only macOS has simulators.
// Nothing is created: sandbox-exec does not need a rule's path to exist.
func xcodeSimulatorDataFor(goos string) []string {
	if goos != "darwin" {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	return []string{filepath.Join(home, "Library", "Developer", "CoreSimulator", "Devices")}
}

// xcodeSelectLink is the symlink `xcode-select --switch` points at the active
// developer directory. A var so tests can aim it elsewhere.
var xcodeSelectLink = "/var/db/xcode_select_link"

// detectXcodeDeveloperDir returns the active developer directory — an
// Xcode.app's Contents/Developer or /Library/Developer/CommandLineTools — or
// "" when there is none. DEVELOPER_DIR wins, as it does for xcrun; otherwise
// the xcode-select link is read, without running xcode-select. A candidate is
// accepted only when it holds the developer tools (usr/bin/xcodebuild in an
// Xcode, usr/bin/clang in the Command Line Tools), so a stray DEVELOPER_DIR
// cannot widen what the agent may read to an arbitrary directory.
func detectXcodeDeveloperDir() string {
	for _, dir := range []string{os.Getenv("DEVELOPER_DIR"), readLink(xcodeSelectLink)} {
		if isXcodeDeveloperDir(dir) {
			return dir
		}
	}
	return ""
}

func readLink(path string) string {
	target, err := os.Readlink(path)
	if err != nil {
		return ""
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	return target
}

func isXcodeDeveloperDir(dir string) bool {
	if dir == "" || !filepath.IsAbs(dir) {
		return false
	}
	for _, tool := range []string{"xcodebuild", "clang"} {
		if info, err := os.Stat(filepath.Join(dir, "usr", "bin", tool)); err == nil && !info.IsDir() {
			return true
		}
	}
	return false
}
