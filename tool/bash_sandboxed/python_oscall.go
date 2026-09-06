package bash_sandboxed

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	montygo "github.com/fugue-labs/monty-go"
)

// The monty interpreter performs no I/O of its own: when Python touches the
// filesystem or the environment the VM suspends and hands the host a typed OS
// call, which is serviced here. That makes this file the entire filesystem
// attack surface of the Python runtime — everything Python can reach, it
// reaches through montyOsCall.
//
// Two layers guard each call:
//
//  1. checkPathBoundary, the same function the bash CallHandler and OpenHandler
//     use, decides whether the path is inside the read or write set. There is
//     deliberately no second path policy here; `python3` and `sed` answer to
//     the same boundary.
//  2. The operation is then performed through os.Root (openat2-rooted on
//     Linux), so the resolution the kernel performs cannot leave the allowed
//     directory even if a symlink along the way is swapped after the check.
//
// The second layer matters because this code runs in the MCP server process,
// not in the bwrap/sandbox-exec worker — monty is in-process wasm, so the OS
// sandbox is not underneath these host-side file operations. os.Root is what
// makes the boundary kernel-enforced rather than the result of path arithmetic.

// montyFS performs authorized filesystem operations on behalf of Python code.
// It holds one os.Root per allowed base directory, opened lazily and reused for
// the duration of a single python invocation.
type montyFS struct {
	workDir string
	sets    resolvedPathSets

	mu     sync.Mutex
	roots  map[string]rootedDir
	closed bool
}

// rootedDir is an open os.Root plus the directory it is anchored at, which is
// not always the allowed entry itself (see rootFor).
type rootedDir struct {
	root *os.Root
	dir  string
}

func newMontyFS(workDir string, sets resolvedPathSets) *montyFS {
	return &montyFS{workDir: workDir, sets: sets, roots: map[string]rootedDir{}}
}

// close releases every root opened during the run.
func (m *montyFS) close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.roots {
		r.root.Close()
	}
	m.roots = nil
	m.closed = true
}

// errPathMissing marks a path that is inside the boundary but does not exist.
// It is a sentinel rather than a message match: authorizeAllowMissing has to
// tell "missing, so the answer is False" apart from "denied", and deciding that
// on error text would be one refactor away from turning a denial into an allow.
var errPathMissing = errors.New("no such file or directory")

// authorize checks path against the read or write set and returns a root
// confined to the allowed directory that contains it, along with the path
// relative to that root. The returned root must not be closed by the caller;
// it is shared for the run and released by close.
func (m *montyFS) authorize(path string, isWrite bool) (*os.Root, string, error) {
	if path == "" {
		return nil, "", fmt.Errorf("empty path")
	}
	allowed := m.sets.read
	if isWrite {
		allowed = m.sets.write
	}
	if err := checkPathBoundary(path, path, m.workDir, isWrite, allowed); err != nil {
		return nil, "", err
	}
	resolved := ResolvePath(path, m.workDir)

	// checkPathBoundary lets a non-existent absolute path through on the read
	// side so that reading a missing file reports "no such file" rather than a
	// boundary error. Such a path has no containing root, so report the same
	// thing the real filesystem would.
	base, ok := m.baseFor(resolved, allowed)
	if !ok {
		if !isWrite {
			return nil, "", fmt.Errorf("%s: %w", path, errPathMissing)
		}
		return nil, "", fmt.Errorf("path %q resolves to %q which is outside allowed directories", path, resolved)
	}

	rd, err := m.rootFor(base)
	if err != nil {
		return nil, "", err
	}
	rel, err := filepath.Rel(rd.dir, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("path %q resolves to %q which is outside allowed directories", path, resolved)
	}
	return rd.root, rel, nil
}

// baseFor returns the allowed base directory containing resolved. The longest
// match wins so that a path under a nested allowed directory is opened against
// the closest root rather than an ancestor.
func (m *montyFS) baseFor(resolved string, allowed []resolvedAllowedPath) (string, bool) {
	best := ""
	for _, a := range allowed {
		if !a.nestedOnly && resolved == a.base {
			if len(a.base) > len(best) {
				best = a.base
			}
			continue
		}
		if strings.HasPrefix(resolved, a.base+string(filepath.Separator)) && len(a.base) > len(best) {
			best = a.base
		}
	}
	return best, best != ""
}

// rootFor opens the confinement root for an allowed base directory.
//
// os.OpenRoot needs a real directory, but an allowed entry need not be one:
// it can name a single file (a file-granular grant) or a directory that does
// not exist yet — bash handles both, so Python must too. In those cases the
// root is anchored at the nearest existing ancestor directory instead, and the
// returned dir says where. That is sound because checkPathBoundary has already
// decided whether the path is inside the boundary; the root's job is only to
// stop the kernel's path resolution from leaving the directory it is anchored
// at, and it still cannot be escaped by a swapped symlink.
func (m *montyFS) rootFor(base string) (rootedDir, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return rootedDir{}, fmt.Errorf("python: filesystem access after the run ended")
	}
	if rd, ok := m.roots[base]; ok {
		return rd, nil
	}
	dir := base
	for {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return rootedDir{}, fmt.Errorf("cannot open allowed directory %s: no existing parent directory", base)
		}
		dir = parent
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return rootedDir{}, fmt.Errorf("cannot open allowed directory %s: %w", dir, err)
	}
	rd := rootedDir{root: root, dir: dir}
	m.roots[base] = rd
	return rd, nil
}

// montyOsCall returns the OsCallFunc that services monty's OS calls.
//
// Denials are returned as errors rather than as a denial value. Returning an
// error ends the run; returning a value would let a script retry in a loop,
// burning the suspension budget probing the boundary. Python cannot catch
// these — monty surfaces them to the host, not to the interpreter — which is
// what makes a denial final.
func (s *Sandbox) montyOsCall(m *montyFS) montygo.OsCallFunc {
	return func(ctx context.Context, call *montygo.OsCall) (any, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch call.Function {

		// --- read side -------------------------------------------------
		case "Path.exists", "Path.is_file", "Path.is_dir", "Path.is_symlink":
			return m.statPredicate(call)
		case "Path.read_text":
			data, err := m.readFile(call, "read_text")
			if err != nil {
				return nil, err
			}
			return string(data), nil
		case "Path.read_bytes":
			data, err := m.readFile(call, "read_bytes")
			if err != nil {
				return nil, err
			}
			// monty represents bytes as a list of integers. A Go string would
			// come back as a str and a []byte would be base64-encoded by the
			// JSON bridge, so neither is usable here.
			out := make([]any, len(data))
			for i, b := range data {
				out[i] = int(b)
			}
			return out, nil
		case "Path.stat":
			return m.stat(call)
		case "Path.iterdir":
			return m.iterdir(call)
		case "Path.resolve", "Path.absolute":
			path, err := pathArg(call, 0)
			if err != nil {
				return nil, err
			}
			// Resolution reveals where a path points, so it answers to the
			// read boundary like any other filesystem question.
			if _, _, err := m.authorizeAllowMissing(path, false); err != nil {
				return nil, err
			}
			if call.Function == "Path.absolute" {
				return absPath(path, m.workDir), nil
			}
			return ResolvePath(path, m.workDir), nil

		// --- write side ------------------------------------------------
		case "Path.write_text", "Path.append_text":
			return nil, m.writeText(call)
		case "Path.write_bytes", "Path.append_bytes":
			return nil, m.writeBytes(call)
		case "Path.mkdir":
			return nil, m.mkdir(call)
		case "Path.unlink":
			return nil, m.remove(call, false)
		case "Path.rmdir":
			return nil, m.remove(call, true)
		case "Path.rename":
			return nil, m.rename(call)

		// --- open ------------------------------------------------------
		case "open":
			return nil, m.refuseOpen(call)

		// --- non-filesystem --------------------------------------------
		case "os.getenv":
			// monty has no environment of its own, and re-exposing the host's
			// would hand Python the credentials the rest of the sandbox goes
			// out of its way to mask. Report every variable as unset; the
			// second argument is Python's own default.
			if len(call.Args) > 1 {
				return call.Args[1], nil
			}
			return nil, nil
		case "os.environ":
			return map[string]any{}, nil
		case "date.today":
			return time.Now().Format(time.DateOnly), nil
		case "datetime.now":
			return time.Now().Format("2006-01-02T15:04:05.000000"), nil
		}
		return nil, fmt.Errorf("%s is not supported in the sandbox", call.Function)
	}
}

// authorizeAllowMissing is authorize for calls that ask a question about a path
// rather than opening it (exists, resolve): a path that does not exist is not
// an error, but it must still be inside the boundary.
func (m *montyFS) authorizeAllowMissing(path string, isWrite bool) (*os.Root, string, error) {
	root, rel, err := m.authorize(path, isWrite)
	if errors.Is(err, errPathMissing) {
		return nil, "", nil
	}
	return root, rel, err
}

func (m *montyFS) statPredicate(call *montygo.OsCall) (any, error) {
	path, err := pathArg(call, 0)
	if err != nil {
		return nil, err
	}
	root, rel, err := m.authorizeAllowMissing(path, false)
	if err != nil {
		return nil, err
	}
	if root == nil {
		return false, nil
	}
	if call.Function == "Path.is_symlink" {
		info, err := root.Lstat(rel)
		if err != nil {
			return false, nil
		}
		return info.Mode()&fs.ModeSymlink != 0, nil
	}
	info, err := root.Stat(rel)
	if err != nil {
		return false, nil
	}
	switch call.Function {
	case "Path.is_file":
		return info.Mode().IsRegular(), nil
	case "Path.is_dir":
		return info.IsDir(), nil
	}
	return true, nil
}

func (m *montyFS) readFile(call *montygo.OsCall, what string) ([]byte, error) {
	path, err := pathArg(call, 0)
	if err != nil {
		return nil, err
	}
	root, rel, err := m.authorize(path, false)
	if err != nil {
		return nil, err
	}
	data, err := root.ReadFile(rel)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, cleanFSError(err, path))
	}
	return data, nil
}

func (m *montyFS) stat(call *montygo.OsCall) (any, error) {
	path, err := pathArg(call, 0)
	if err != nil {
		return nil, err
	}
	root, rel, err := m.authorize(path, false)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(rel)
	if err != nil {
		return nil, fmt.Errorf("stat: %w", cleanFSError(err, path))
	}
	// monty hands this straight back to Python as a dict, so the fields are
	// reachable as s["st_size"]. Attribute access (s.st_size) is not supported
	// by this monty build regardless of what is returned here.
	mtime := float64(info.ModTime().UnixNano()) / 1e9
	return map[string]any{
		"st_mode":  int(info.Mode().Perm()) | modeTypeBits(info.Mode()),
		"st_size":  int(info.Size()),
		"st_mtime": mtime,
		"st_atime": mtime,
		"st_ctime": mtime,
	}, nil
}

// modeTypeBits maps Go's portable file-type bits onto the POSIX S_IF* values
// Python code expects to find in st_mode.
func modeTypeBits(mode fs.FileMode) int {
	switch {
	case mode&fs.ModeDir != 0:
		return 0o040000
	case mode&fs.ModeSymlink != 0:
		return 0o120000
	default:
		return 0o100000
	}
}

func (m *montyFS) iterdir(call *montygo.OsCall) (any, error) {
	path, err := pathArg(call, 0)
	if err != nil {
		return nil, err
	}
	root, rel, err := m.authorize(path, false)
	if err != nil {
		return nil, err
	}
	dir, err := root.Open(rel)
	if err != nil {
		return nil, fmt.Errorf("iterdir: %w", cleanFSError(err, path))
	}
	defer dir.Close()
	names, err := dir.Readdirnames(-1)
	if err != nil {
		return nil, fmt.Errorf("iterdir: %w", cleanFSError(err, path))
	}
	sort.Strings(names)
	// CPython yields paths with the parent still attached, so join them back
	// onto the argument as written. They arrive in Python as plain strings —
	// this monty build does not rebuild them into Path objects.
	out := make([]any, 0, len(names))
	resolvedDir := ResolvePath(path, m.workDir)
	for _, name := range names {
		if isGitInternalPath(filepath.Join(resolvedDir, name)) {
			continue
		}
		out = append(out, filepath.Join(path, name))
	}
	return out, nil
}

func (m *montyFS) writeText(call *montygo.OsCall) error {
	path, err := pathArg(call, 0)
	if err != nil {
		return err
	}
	if len(call.Args) < 2 {
		return fmt.Errorf("%s: missing content", call.Function)
	}
	text, ok := call.Args[1].(string)
	if !ok {
		return fmt.Errorf("%s: expected string content", call.Function)
	}
	return m.write(call.Function, path, []byte(text), strings.HasPrefix(call.Function, "Path.append"))
}

func (m *montyFS) writeBytes(call *montygo.OsCall) error {
	path, err := pathArg(call, 0)
	if err != nil {
		return err
	}
	if len(call.Args) < 2 {
		return fmt.Errorf("%s: missing content", call.Function)
	}
	raw, ok := call.Args[1].([]any)
	if !ok {
		return fmt.Errorf("%s: expected bytes content", call.Function)
	}
	data := make([]byte, len(raw))
	for i, v := range raw {
		n, ok := v.(float64)
		if !ok || n < 0 || n > 255 {
			return fmt.Errorf("%s: invalid byte value at index %d", call.Function, i)
		}
		data[i] = byte(n)
	}
	return m.write(call.Function, path, data, strings.HasPrefix(call.Function, "Path.append"))
}

func (m *montyFS) write(fn, path string, data []byte, appendMode bool) error {
	root, rel, err := m.authorize(path, true)
	if err != nil {
		return err
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if appendMode {
		flags = os.O_WRONLY | os.O_CREATE | os.O_APPEND
	}
	f, err := root.OpenFile(rel, flags, 0o644)
	if err != nil {
		return fmt.Errorf("%s: %w", fn, cleanFSError(err, path))
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("%s: %w", fn, cleanFSError(err, path))
	}
	return nil
}

func (m *montyFS) mkdir(call *montygo.OsCall) error {
	path, err := pathArg(call, 0)
	if err != nil {
		return err
	}
	root, rel, err := m.authorize(path, true)
	if err != nil {
		return err
	}
	parents, _ := call.Kwargs["parents"].(bool)
	existOK, _ := call.Kwargs["exist_ok"].(bool)

	if parents {
		if err := root.MkdirAll(rel, 0o755); err != nil {
			return fmt.Errorf("mkdir: %w", cleanFSError(err, path))
		}
		return nil
	}
	if err := root.Mkdir(rel, 0o755); err != nil {
		if existOK && os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("mkdir: %w", cleanFSError(err, path))
	}
	return nil
}

func (m *montyFS) remove(call *montygo.OsCall, dir bool) error {
	path, err := pathArg(call, 0)
	if err != nil {
		return err
	}
	root, rel, err := m.authorize(path, true)
	if err != nil {
		return err
	}
	info, err := root.Lstat(rel)
	if err != nil {
		return fmt.Errorf("%s: %w", call.Function, cleanFSError(err, path))
	}
	// Keep unlink and rmdir honest about what they remove, as CPython does;
	// Root.Remove itself is happy to take either.
	if dir && !info.IsDir() {
		return fmt.Errorf("rmdir: %s: not a directory", path)
	}
	if !dir && info.IsDir() {
		return fmt.Errorf("unlink: %s: is a directory", path)
	}
	if err := root.Remove(rel); err != nil {
		return fmt.Errorf("%s: %w", call.Function, cleanFSError(err, path))
	}
	return nil
}

func (m *montyFS) rename(call *montygo.OsCall) error {
	src, err := pathArg(call, 0)
	if err != nil {
		return err
	}
	dst, err := pathArg(call, 1)
	if err != nil {
		return err
	}
	// Both ends are writes: rename removes the source as surely as unlink.
	srcRoot, srcRel, err := m.authorize(src, true)
	if err != nil {
		return err
	}
	dstRoot, dstRel, err := m.authorize(dst, true)
	if err != nil {
		return err
	}
	// os.Root.Rename cannot cross roots. Both ends are already authorized, so
	// this only rejects a rename between two *different* allowed directories.
	if srcRoot != dstRoot {
		return fmt.Errorf("rename: %s and %s are in different allowed directories; "+
			"use read_text/write_text plus unlink instead", src, dst)
	}
	if err := srcRoot.Rename(srcRel, dstRel); err != nil {
		return fmt.Errorf("rename: %w", cleanFSError(err, src))
	}
	return nil
}

// refuseOpen rejects the builtin open(). monty forwards open() to the host and
// then uses whatever comes back as the file object itself — there is no read,
// write, iteration or context-manager protocol behind it — so nothing this
// handler returns produces a working file. Say so, and name the calls that do
// work, rather than handing back a value that fails one line later with
// "'str' object has no attribute 'read'".
//
// The path is still authorized first, so a script probing outside the boundary
// with open() is told it is outside the boundary rather than being handed the
// more inviting "use pathlib instead".
func (m *montyFS) refuseOpen(call *montygo.OsCall) error {
	path, err := pathArg(call, 0)
	if err != nil {
		return err
	}
	mode := "r"
	if len(call.Args) > 1 {
		if s, ok := call.Args[1].(string); ok && s != "" {
			mode = s
		}
	}
	isWrite := strings.ContainsAny(mode, "wax+")
	if _, _, err := m.authorizeAllowMissing(path, isWrite); err != nil {
		return err
	}
	verb := "Path(...).read_text()"
	if isWrite {
		verb = "Path(...).write_text(...)"
	}
	return fmt.Errorf("open() is not available: %s It returns no file object here. "+
		"Use %s from pathlib instead, or:\n%s", pythonIsMontyNote, verb, pythonEscapeHatches)
}

// pathArg extracts the path at index i, rejecting anything that is not a
// string. monty passes paths through as plain strings.
func pathArg(call *montygo.OsCall, i int) (string, error) {
	if len(call.Args) <= i {
		return "", fmt.Errorf("%s: missing path argument", call.Function)
	}
	path, ok := call.Args[i].(string)
	if !ok {
		return "", fmt.Errorf("%s: path argument must be a string", call.Function)
	}
	if path == "" {
		return "", fmt.Errorf("%s: empty path", call.Function)
	}
	return path, nil
}

// cleanFSError rewrites a *PathError so the message names the path as Python
// wrote it rather than the root-relative form os.Root reports, which is
// meaningless to the script author.
func cleanFSError(err error, path string) error {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return fmt.Errorf("%s: %v", path, pathErr.Err)
	}
	return err
}
