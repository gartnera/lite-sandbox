package config

import (
	"os"
	"path/filepath"
	"strconv"
)

// AgentBrowserProfile is the name of the profile that whitelists
// agent-browser (https://github.com/vercel-labs/agent-browser).
const AgentBrowserProfile = "agent-browser"

// agentBrowserOutputDirs are the directories under ~/.agent-browser/tmp where
// agent-browser writes a screenshot, PDF, HAR file, or trace that the command
// names no path for, and prints the path so the agent can read it back.
var agentBrowserOutputDirs = []string{"screenshots", "pdfs", "har", "traces"}

// agentBrowserPaths is the agent-browser profile's paths:
//
//   - read: the browsers agent-browser launches when the command names none —
//     Chrome for Testing from `agent-browser install` (~/.agent-browser/browsers),
//     and Playwright's and Puppeteer's caches, which agent-browser also
//     searches — and the user's own defaults (~/.agent-browser/config.json).
//     None of them is writable: a browser binary planted there would run
//     outside the sandbox the next time the user runs agent-browser, and the
//     config names the browser binary, its launch arguments, and extensions.
//   - read and write: the output directories under ~/.agent-browser/tmp, where
//     a screenshot or PDF taken without a path lands, so the agent can read it.
//
// The rest of ~/.agent-browser stays hidden by the hidden home: the saved
// sessions (cookies and storage of the sites the user logged into), the auth
// vault and its encryption key, the plugins and skills the user installed,
// and the sockets of the user's own daemons. The daemons started in the
// sandbox use a socket directory of their own (AgentBrowserSocketDir).
func agentBrowserPaths() []PathEntry {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return nil
	}
	yes := true
	var out []PathEntry
	root := filepath.Join(home, ".agent-browser")
	reads := []string{
		filepath.Join(root, "browsers"),
		filepath.Join(root, "config.json"),
		agentBrowserPlaywrightCache(home),
		agentBrowserPuppeteerCache(home),
	}
	for _, p := range reads {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err == nil {
			out = append(out, PathEntry{Path: p, Read: &yes})
		}
	}
	for _, d := range agentBrowserOutputDirs {
		if p := ensureDir(filepath.Join(root, "tmp", d)); p != "" {
			out = append(out, PathEntry{Path: p, Read: &yes, Write: &yes})
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
// of the agent-browser daemons started in the OS sandbox worker. agent-browser
// keeps a daemon per session that holds the browser open between commands,
// and by default puts its socket in $XDG_RUNTIME_DIR/agent-browser or
// ~/.agent-browser, which the worker hides (the hidden home), so the daemon
// could not start there. The temp dir is writable in the worker, and on Linux
// it is the worker's own tmpfs, so the daemon (and the browser) run, and die,
// with the worker. Every command a worker runs gets it while the profile is
// enabled, so agent-browser started by a script or a test finds the same
// daemons.
func AgentBrowserSocketDir() string {
	return filepath.Join(os.TempDir(), "lite-sandbox-ab-"+strconv.Itoa(os.Getuid()))
}
