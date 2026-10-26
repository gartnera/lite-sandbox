package bash_sandboxed

import (
	"os"
	"path/filepath"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/os_sandbox"
)

// guardHost adds to opts the parts of the worker's policy that keep what a
// command runs from reaching the host through a side door rather than a path
// grant:
//
//   - the programs the host runs are write-denied wherever a grant makes their
//     directory writable (hostProgramDenies);
//   - the coding agents' control sockets are unreachable
//     (config.AgentSocketDirs, config.AgentSocketPaths);
//   - on macOS, the preferences daemon is out of reach unless the worker may
//     write ~/Library/Preferences itself, since cfprefsd writes (and reads)
//     the plists there on its client's behalf;
//   - the worker's environment leaves out the credentials (cfg.SandboxEnv).
func guardHost(cfg *config.Config, opts *os_sandbox.WorkerOptions) {
	opts.DeniedWritePaths = append(opts.DeniedWritePaths, hostProgramDenies(cfg, *opts)...)

	opts.MaskDirs = config.AgentSocketDirs()
	for _, sock := range config.AgentSocketPaths() {
		inDir := false
		for _, d := range opts.MaskDirs {
			if underAny(sock, d) {
				inDir = true
				break
			}
		}
		// A socket in a masked directory is masked with it; bubblewrap could
		// not create a mount point for it inside the masked tmpfs anyway.
		if !inDir {
			opts.MaskPaths = append(opts.MaskPaths, sock)
		}
	}

	if home, err := os.UserHomeDir(); err == nil {
		opts.DenyPreferences = !workerWrites(*opts, filepath.Join(home, "Library", "Preferences"), true)
	}

	if cfg.ScrubsEnv() {
		opts.Env = cfg.SandboxEnv(os.Environ())
	}
}

// hostProgramDenies returns the write denials that keep a worker from
// replacing a program the host runs: each directory on the server's PATH, and
// Go's install directory (config.HostProgramDirs), that a writable bind would
// otherwise expose — the go profile binds GOPATH, which holds GOBIN — and the
// lite-sandbox binary itself (config.ServerExecutable), which every agent
// session starts as its MCP server and hook. A program planted in either runs
// outside the sandbox the next time it starts. Directories in the working
// directory are left writable (a project's own bin/ on PATH is the user's
// choice to trust); the server's binary is denied even there.
func hostProgramDenies(cfg *config.Config, opts os_sandbox.WorkerOptions) []os_sandbox.DenyPath {
	var out []os_sandbox.DenyPath
	seen := map[string]bool{}
	add := func(p string, dir bool) {
		if !seen[p] {
			seen[p] = true
			out = append(out, os_sandbox.DenyPath{Path: p, Dir: dir})
		}
	}
	for _, dir := range cfg.HostProgramDirs(os.Getenv("PATH")) {
		if workerWrites(opts, dir, false) {
			add(dir, true)
		}
	}
	for _, exe := range config.ServerExecutable() {
		if workerWrites(opts, exe, true) {
			add(exe, false)
		}
	}
	return out
}

// workerWrites reports whether a worker with opts may write p (or its
// symlink-resolved form) through its writable binds, its home directory in
// denylist mode, and — when withWorkDir — its working directory.
func workerWrites(opts os_sandbox.WorkerOptions, p string, withWorkDir bool) bool {
	writable := append([]string(nil), opts.ExtraBinds...)
	if opts.HomeWritable {
		if home, err := os.UserHomeDir(); err == nil {
			writable = append(writable, home)
		}
	}
	if withWorkDir && opts.WorkDir != "" {
		writable = append(writable, opts.WorkDir)
	}
	for _, cand := range []string{filepath.Clean(p), resolveIfExists(p)} {
		for _, w := range writable {
			if underAny(cand, w) {
				return true
			}
		}
	}
	return false
}
