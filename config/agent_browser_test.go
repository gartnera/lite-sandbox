package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestAgentBrowserPaths checks the profile gives ~/.agent-browser to
// agent-browser alone (a scoped, internal read-write grant), its tmp output
// dir to the agent, and the browser caches that exist read-only.
func TestAgentBrowserPaths(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PLAYWRIGHT_BROWSERS_PATH", "")
	t.Setenv("PUPPETEER_CACHE_DIR", "")
	if err := os.MkdirAll(filepath.Join(home, ".cache", "ms-playwright"), 0o700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(home, ".agent-browser")

	got := agentBrowserPaths()
	if len(got) != 3 {
		t.Fatalf("paths = %+v, want 3 entries", got)
	}
	scoped := got[0]
	if scoped.Path != root || !scoped.GrantsWrite() || !scoped.Internal || !slices.Equal(scoped.Commands, []string{"agent-browser"}) {
		t.Errorf("first entry = %+v, want ~/.agent-browser read-write, internal, scoped to agent-browser", scoped)
	}
	tmp := got[1]
	if tmp.Path != filepath.Join(root, "tmp") || !tmp.GrantsWrite() || tmp.Internal || tmp.Scoped() {
		t.Errorf("second entry = %+v, want ~/.agent-browser/tmp read-write for the agent", tmp)
	}
	if pw := got[2]; pw.Path != filepath.Join(home, ".cache", "ms-playwright") || pw.GrantsWrite() {
		t.Errorf("third entry = %+v, want the Playwright cache read-only", pw)
	}
	for _, d := range []string{root, filepath.Join(root, "tmp"), AgentBrowserSocketDir()} {
		if !dirExists(d) {
			t.Errorf("%s not created", d)
		}
	}
	if !underDir(AgentBrowserSocketDir(), root) {
		t.Errorf("socket dir %s is not under %s, which other workers hide", AgentBrowserSocketDir(), root)
	}
}

// TestAgentBrowserProfile_Scope checks enabling the profile routes
// agent-browser to a worker of its own and hides ~/.agent-browser from
// every other worker.
func TestAgentBrowserProfile_Scope(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PLAYWRIGHT_BROWSERS_PATH", "")
	t.Setenv("PUPPETEER_CACHE_DIR", "")
	cfg := &Config{Profiles: []ProfileEntry{{Name: AgentBrowserProfile}}}
	eff := cfg.Effective()
	if _, ok := eff.ScopeForCommand("agent-browser"); !ok {
		t.Fatal("agent-browser has no scope of its own")
	}
	root := filepath.Join(home, ".agent-browser")
	var hidden bool
	for _, d := range eff.ScopedDeniedReadEntries() {
		if d.Path == root {
			hidden = true
		}
	}
	if !hidden {
		t.Errorf("~/.agent-browser is not hidden from other workers: %+v", eff.ScopedDeniedReadEntries())
	}
}

func underDir(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && (len(rel) < 3 || rel[:3] != "../")
}
