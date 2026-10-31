package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestAgentBrowserPaths checks the profile grants agent-browser's installed
// browsers and the user's config read-only, its output dirs read-write
// (creating them), and nothing else under ~/.agent-browser: not the saved
// sessions, the auth vault or its key, nor the user's daemon sockets.
func TestAgentBrowserPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PLAYWRIGHT_BROWSERS_PATH", "")
	t.Setenv("PUPPETEER_CACHE_DIR", "")
	root := filepath.Join(home, ".agent-browser")
	for _, d := range []string{"browsers", "sessions", "auth", filepath.Join("..", ".cache", "ms-playwright")} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"config.json", ".encryption-key", "default.sock"} {
		if err := os.WriteFile(filepath.Join(root, f), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var reads, writes []string
	for _, e := range agentBrowserPaths() {
		if e.Read != nil && *e.Read {
			reads = append(reads, e.Path)
		}
		if e.Write != nil && *e.Write {
			writes = append(writes, e.Path)
		}
	}
	outputs := []string{
		filepath.Join(root, "tmp", "screenshots"),
		filepath.Join(root, "tmp", "pdfs"),
		filepath.Join(root, "tmp", "har"),
		filepath.Join(root, "tmp", "traces"),
	}
	wantReads := append([]string{
		filepath.Join(root, "browsers"),
		filepath.Join(root, "config.json"),
		filepath.Join(home, ".cache", "ms-playwright"),
	}, outputs...)
	slices.Sort(reads)
	slices.Sort(wantReads)
	if !slices.Equal(reads, wantReads) {
		t.Errorf("read grants = %v, want %v", reads, wantReads)
	}
	if !slices.Equal(writes, outputs) {
		t.Errorf("write grants = %v, want %v", writes, outputs)
	}
	for _, d := range outputs {
		if _, err := os.Stat(d); err != nil {
			t.Errorf("output dir %s not created: %v", d, err)
		}
	}
}

// TestAgentBrowserPaths_MissingBrowsers checks a browser cache that doesn't
// exist is not granted (nothing to bind).
func TestAgentBrowserPaths_MissingBrowsers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PLAYWRIGHT_BROWSERS_PATH", "")
	t.Setenv("PUPPETEER_CACHE_DIR", "")
	for _, e := range agentBrowserPaths() {
		if e.Write == nil || !*e.Write {
			t.Errorf("unexpected read-only grant %s", e.Path)
		}
	}
}
