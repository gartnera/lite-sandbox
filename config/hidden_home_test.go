package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestOSSandboxHidesHomeDefault(t *testing.T) {
	if !(&Config{}).OSSandboxHidesHome() || !(*Config)(nil).OSSandboxHidesHome() {
		t.Error("hiding should be on by default")
	}
	off := false
	if (&Config{OSSandboxHideHome: &off}).OSSandboxHidesHome() {
		t.Error("os_sandbox_hide_home: false should turn hiding off")
	}
}

func TestHiddenDirs(t *testing.T) {
	home := t.TempDir()
	runtimeDir := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	if got := (&Config{}).HiddenDirs(); !slices.Equal(got, []string{home, runtimeDir}) {
		t.Errorf("allowlist mode hides $HOME and the runtime dir, got %v", got)
	}
	// denylist mode binds $HOME writable and relies on its deny lists, but
	// still hides the runtime dir.
	if got := (&Config{Mode: "denylist"}).HiddenDirs(); !slices.Equal(got, []string{runtimeDir}) {
		t.Errorf("denylist mode hides only the runtime dir, got %v", got)
	}
	if got := (&Config{Mode: "open"}).HiddenDirs(); got != nil {
		t.Errorf("open mode enforces nothing, got %v", got)
	}
	off := false
	if got := (&Config{OSSandboxHideHome: &off}).HiddenDirs(); got != nil {
		t.Errorf("opted out, got %v", got)
	}
}

func TestHomePathToolchains(t *testing.T) {
	// Resolved, since links are followed to their real targets (macOS's /var
	// is /private/var).
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mkdir := func(rel string) string {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cargoBin := mkdir(".cargo/bin")
	nodeBin := mkdir(".nvm/versions/node/v22/bin")
	localBin := mkdir(".local/bin")
	homeBin := mkdir("bin")
	shims := mkdir(".pyenv/shims")
	ruffBin := mkdir(".local/share/uv/tools/ruff/bin")
	if err := os.WriteFile(filepath.Join(ruffBin, "ruff"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	// The tool's venv links its interpreter from a uv-managed install.
	pyBin := mkdir(".local/share/uv/python/cpython-3.13/bin")
	if err := os.WriteFile(filepath.Join(pyBin, "python3.13"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(pyBin, "python3.13"), filepath.Join(ruffBin, "python")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(ruffBin, "ruff"), filepath.Join(localBin, "ruff")); err != nil {
		t.Fatal(err)
	}
	// A link out of $HOME exposes nothing.
	if err := os.Symlink("/usr/bin/env", filepath.Join(localBin, "env")); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(home, ".cargo/bin") + ":" + nodeBin + ":" + localBin + ":" + homeBin + ":" + shims + ":/usr/bin:relative/bin:"
	got := HomePathToolchains(home, path)
	want := []string{
		cargoBin, filepath.Join(home, ".cargo"),
		nodeBin, filepath.Join(home, ".nvm/versions/node/v22"),
		localBin, ruffBin, filepath.Join(home, ".local/share/uv/tools/ruff"),
		pyBin, filepath.Join(home, ".local/share/uv/python/cpython-3.13"),
		homeBin,
		shims, filepath.Join(home, ".pyenv"),
	}
	if !slices.Equal(got, want) {
		t.Errorf("HomePathToolchains =\n  %v\nwant\n  %v", got, want)
	}
	for _, shared := range []string{home, filepath.Join(home, ".local")} {
		if slices.Contains(got, shared) {
			t.Errorf("%s holds more than one tool's state and must not be exposed whole", shared)
		}
	}
}

func TestHomeVisiblePathsDockerConfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DOCKER_CONFIG", "")
	t.Setenv("PATH", "")
	dockerDir := filepath.Join(home, ".docker")
	if err := os.MkdirAll(dockerDir, 0o755); err != nil {
		t.Fatal(err)
	}
	yes, no := true, false
	if got := (&Config{}).HomeVisiblePaths(); slices.Contains(got, dockerDir) {
		t.Errorf("docker not configured: %s should stay hidden, got %v", dockerDir, got)
	}
	if got := (&Config{Docker: &DockerConfig{Enabled: &no}}).HomeVisiblePaths(); slices.Contains(got, dockerDir) {
		t.Errorf("docker disabled: %s should stay hidden, got %v", dockerDir, got)
	}
	enabled := &Config{Docker: &DockerConfig{Enabled: &yes}}
	if got := enabled.HomeVisiblePaths(); !slices.Contains(got, dockerDir) {
		t.Errorf("docker enabled: %s should be visible, got %v", dockerDir, got)
	}
	custom := filepath.Join(home, "docker-config")
	if err := os.MkdirAll(custom, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", custom)
	if got := enabled.HomeVisiblePaths(); !slices.Contains(got, custom) || slices.Contains(got, dockerDir) {
		t.Errorf("DOCKER_CONFIG: want %s (and not %s), got %v", custom, dockerDir, got)
	}
	if err := os.Remove(custom); err != nil {
		t.Fatal(err)
	}
	if got := enabled.HomeVisiblePaths(); slices.Contains(got, custom) {
		t.Errorf("a missing config dir cannot be bound, got %v", got)
	}
}

func TestHiddenHomeDeniedReadEntries(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("CARGO_HOME", "")
	paths := func(c *Config) []string {
		var out []string
		for _, d := range c.HiddenHomeDeniedReadEntries() {
			out = append(out, d.Path)
		}
		return out
	}
	cargoCreds := filepath.Join(home, ".cargo", "credentials.toml")
	for _, f := range []string{cargoCreds, filepath.Join(home, ".config", "git", "credentials")} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := paths(&Config{}); !slices.Contains(got, cargoCreds) || !slices.Contains(got, filepath.Join(home, ".config", "git", "credentials")) {
		t.Errorf("missing built-in credential entries: %v", got)
	}
	// A grant on the file itself lifts its entry; a grant on its directory
	// (the rust profile's ~/.cargo) does not.
	yes := true
	c := &Config{Paths: []PathEntry{
		{Path: "~/.cargo", Read: &yes, Internal: true},
		{Path: "~/.cargo/credentials.toml", Read: &yes, Internal: true},
	}}
	if got := paths(c); slices.Contains(got, cargoCreds) {
		t.Errorf("a grant on %s should lift it: %v", cargoCreds, got)
	}
	c = &Config{Paths: []PathEntry{{Path: "~/.cargo", Read: &yes, Internal: true}}}
	if got := paths(c); !slices.Contains(got, cargoCreds) {
		t.Errorf("a grant on ~/.cargo must not lift %s: %v", cargoCreds, got)
	}
}
