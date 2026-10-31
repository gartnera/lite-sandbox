package config

import (
	"os"
	"path/filepath"
)

// AgentBrowserProfile is the name of the profile that whitelists
// agent-browser (https://github.com/vercel-labs/agent-browser).
const AgentBrowserProfile = "agent-browser"

// agentBrowserPaths is the agent-browser profile's paths:
//
//   - ~/.agent-browser, readable and writable by agent-browser alone: a grant
//     scoped to it (internal, with commands: [agent-browser]), so it runs in
//     an OS sandbox worker of its own that has the directory, and every other
//     worker hides it, in every mode. That gives agent-browser everything it
//     keeps there — the browsers `agent-browser install` downloads, the
//     user's config, saved sessions (cookies and storage of the sites logged
//     into), the auth vault and its key, plugins and skills — while a
//     dependency's install script, a test, or a program the agent writes can
//     read none of it. agent-browser itself takes no argument validation, so
//     whatever it can read the agent can have it read (open a file:// URL,
//     upload a file), and what it writes there (a plugin, the config, a
//     browser) is what the user's own agent-browser runs later.
//   - ~/.agent-browser/tmp, readable and writable by the agent: a screenshot
//     or PDF taken without a path lands under it, and agent-browser prints the
//     path for the agent to read back. The shared worker still hides it with
//     the rest of ~/.agent-browser; the agent's own file tools can read it.
//   - Playwright's and Puppeteer's browser caches, readable, when they exist:
//     agent-browser launches a Chrome from there when it has none of its own.
//
// The scoped worker's daemons put their sockets in AgentBrowserSocketDir.
func agentBrowserPaths() []PathEntry {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	yes := true
	root := ensureDir(filepath.Join(home, ".agent-browser"))
	if root == "" {
		return nil
	}
	ensureDir(AgentBrowserSocketDir())
	out := []PathEntry{
		{Path: root, Read: &yes, Write: &yes, Internal: true, Commands: []string{"agent-browser"}},
	}
	if tmp := ensureDir(filepath.Join(root, "tmp")); tmp != "" {
		out = append(out, PathEntry{Path: tmp, Read: &yes, Write: &yes})
	}
	for _, p := range []string{agentBrowserPlaywrightCache(home), agentBrowserPuppeteerCache(home)} {
		if _, err := os.Stat(p); err == nil {
			out = append(out, PathEntry{Path: p, Read: &yes})
		}
	}
	return out
}

// agentBrowserPlaywrightCache returns the Playwright browser cache
// agent-browser searches for a Chrome: PLAYWRIGHT_BROWSERS_PATH, else
// ~/.cache/ms-playwright (on every platform, as agent-browser looks there).
func agentBrowserPlaywrightCache(home string) string {
	if d := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); filepath.IsAbs(d) {
		return d
	}
	return filepath.Join(home, ".cache", "ms-playwright")
}

// agentBrowserPuppeteerCache returns the Puppeteer browser cache
// agent-browser searches: PUPPETEER_CACHE_DIR, else ~/.cache/puppeteer.
func agentBrowserPuppeteerCache(home string) string {
	if d := os.Getenv("PUPPETEER_CACHE_DIR"); filepath.IsAbs(d) {
		return d
	}
	return filepath.Join(home, ".cache", "puppeteer")
}

// AgentBrowserSocketDir returns the socket directory (AGENT_BROWSER_SOCKET_DIR)
// of the agent-browser daemons lite-sandbox starts in agent-browser's worker.
// agent-browser keeps a daemon per session that holds the browser open between
// commands, and a command reuses whichever daemon's socket it finds, wherever
// that daemon runs. Its default directories are $XDG_RUNTIME_DIR/agent-browser
// and ~/.agent-browser, where the user's own daemons — unsandboxed, possibly
// logged in with the user's own Chrome profile — keep theirs; this one is
// apart from both, inside ~/.agent-browser, so the shared worker hides it with
// the rest of the directory and no other command can drive the sandbox's
// daemons either.
func AgentBrowserSocketDir() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".agent-browser", "lite-sandbox")
}
