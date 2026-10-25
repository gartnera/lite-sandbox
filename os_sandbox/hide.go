package os_sandbox

import (
	"os"
	"path/filepath"
	"strings"
)

// hidePlan is WorkerOptions.HideDirs resolved against what the worker
// exposes: the directories actually hidden, and the paths shown inside them.
type hidePlan struct {
	// dirs are the hidden directories that exist and that no exposed path
	// contains, symlink-resolved.
	dirs []string
	// exposed are the paths the worker shows (WorkDir, the binds, the worker
	// binary), each as given and symlink-resolved.
	exposed []string
}

// newHidePlan resolves hide against exposed. A hidden directory that is
// missing, or that an exposed path equals or contains (the working directory
// is $HOME, a grant on ~), is dropped: the exposed path shows all of it.
func newHidePlan(hide, exposed []string) hidePlan {
	var p hidePlan
	for _, e := range exposed {
		if e == "" {
			continue
		}
		p.exposed = append(p.exposed, withResolved(filepath.Clean(e))...)
	}
	for _, d := range hide {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		real, err := filepath.EvalSymlinks(d)
		if err != nil {
			continue
		}
		if fi, err := os.Stat(real); err != nil || !fi.IsDir() {
			continue
		}
		covered := false
		for _, e := range p.exposed {
			if within(real, e) || within(filepath.Clean(d), e) {
				covered = true
				break
			}
		}
		if !covered {
			p.dirs = append(p.dirs, real)
		}
	}
	return p
}

// hidden reports whether path ends up hidden: inside a hidden directory and
// not inside anything exposed.
func (p hidePlan) hidden(path string) bool {
	if len(p.dirs) == 0 {
		return false
	}
	candidates := withResolved(filepath.Clean(path))
	// A missing path does not resolve; resolve its nearest existing parent so
	// a path under a symlinked home still compares against the real one.
	if _, err := os.Lstat(path); err != nil {
		if r, err := filepath.EvalSymlinks(filepath.Dir(path)); err == nil {
			candidates = append(candidates, filepath.Join(r, filepath.Base(path)))
		}
	}
	for _, c := range candidates {
		for _, e := range p.exposed {
			if within(c, e) {
				return false
			}
		}
	}
	for _, c := range candidates {
		for _, d := range p.dirs {
			if within(c, d) {
				return true
			}
		}
	}
	return false
}

// visibleDeny keeps the deny-list entries that are not hidden anyway.
func (p hidePlan) visibleDeny(entries []DenyPath) []DenyPath {
	if len(p.dirs) == 0 {
		return entries
	}
	var out []DenyPath
	for _, e := range entries {
		if !p.hidden(e.Path) {
			out = append(out, e)
		}
	}
	return out
}

// visiblePaths keeps the paths that are not hidden anyway.
func (p hidePlan) visiblePaths(paths []string) []string {
	if len(p.dirs) == 0 {
		return paths
	}
	var out []string
	for _, path := range paths {
		if !p.hidden(path) {
			out = append(out, path)
		}
	}
	return out
}

// ancestorsWithin returns the ancestors of path that are dir or inside it,
// from dir down: what must stay stat-able for path to be reached by its full
// name (getcwd, realpath) when dir is hidden.
func ancestorsWithin(path, dir string) []string {
	if !within(path, dir) || path == dir {
		return nil
	}
	var out []string
	for a := filepath.Dir(path); within(a, dir); a = filepath.Dir(a) {
		out = append([]string{a}, out...)
		if a == dir {
			break
		}
	}
	return out
}

// within reports whether path is dir or inside it. Both must be clean.
func within(path, dir string) bool {
	if dir == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == dir || strings.HasPrefix(path, dir+string(filepath.Separator))
}
