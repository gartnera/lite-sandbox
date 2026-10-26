package config

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// HostProgramDirs returns the directories the host runs programs from, which
// the OS sandbox worker must never write even where a grant makes their parent
// writable: a program planted there runs outside the sandbox the next time
// the user, or the agent's harness, starts it. Those are every absolute
// directory on pathEnv (the server's PATH, which is the agent's), and, when
// the go profile is on, Go's install directory: GOBIN, else each GOPATH's
// bin. The go profile grants GOPATH writable for the module cache, and
// `go install` puts binaries in $GOPATH/bin — lite-sandbox's own among them
// when it was installed that way.
func (c *Config) HostProgramDirs(pathEnv string) []string {
	var out []string
	add := func(dir string) {
		if dir == "" || !filepath.IsAbs(dir) {
			return
		}
		dir = filepath.Clean(dir)
		if !slices.Contains(out, dir) {
			out = append(out, dir)
		}
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		add(dir)
	}
	if c.ProfileEnabled("go") {
		for _, dir := range cachedDetect("gobin", []string{"GOBIN", "GOPATH", "GOENV", "HOME"}, detectGoBinDirs) {
			add(dir)
		}
	}
	return out
}

// detectGoBinDirs returns where `go install` writes binaries: GOBIN when set,
// otherwise the bin directory of each GOPATH entry.
func detectGoBinDirs() []string {
	output, err := exec.Command("go", "env", "GOBIN", "GOPATH").Output()
	if err != nil {
		slog.Warn("failed to detect Go install directory", "error", err)
		return nil
	}
	gobin, gopath, _ := strings.Cut(strings.TrimRight(string(output), "\n"), "\n")
	if gobin = strings.TrimSpace(gobin); gobin != "" {
		return []string{gobin}
	}
	var out []string
	for _, p := range filepath.SplitList(strings.TrimSpace(gopath)) {
		if p != "" {
			out = append(out, filepath.Join(p, "bin"))
		}
	}
	return out
}

// ServerExecutable returns the path of the running lite-sandbox binary and,
// when it differs, its symlink-resolved form: what the agents' configurations
// name as the MCP server and hook command, so a worker must never write it.
func ServerExecutable() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	out := []string{exe}
	if r, err := filepath.EvalSymlinks(exe); err == nil && r != exe {
		out = append(out, r)
	}
	return out
}
