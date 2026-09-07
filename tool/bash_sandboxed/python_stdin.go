package bash_sandboxed

import (
	"fmt"
	"io"
	"strings"
	"sync"

	montygo "github.com/fugue-labs/monty-go"
)

// monty has no sys.stdin, for the same reason it has no sys.argv: the `sys`
// module is built in Rust from a fixed attribute list. But unlike argv, stdin
// cannot be solved by baking a value into the prologue — its contents are not
// known when the program is compiled, and a pipeline like
//
//	cat data.json | python3 -c 'import sys, json; print(json.loads(sys.stdin.read()))'
//
// wants the bytes as they arrive.
//
// The interpreter already has the piece needed: a file handle. Reading one is
// not a special interpreter capability, it is an OS call. `f.read()` on a
// handle suspends with Path.read_text for the handle's *path*, and monty keeps
// the answer in the file's buffer and slices it by position from then on. So
// sys.stdin is a file handle the host hands in as an input, anchored at a path
// that only the host understands, and the read that follows is served from the
// command's real stdin instead of the filesystem.
//
// That keeps stdin inside the same boundary as everything else rather than
// beside it: it arrives as an OS call like any other, and every path that is
// not this one still answers to python_oscall.go's authorization.

// pythonStdinPath is the file handle's path.
//
// It is absolute on purpose. A relative sentinel resolves *into* the working
// directory, so the interception below would shadow a real file that happened
// to carry the name. This one cannot be a workspace file, and a program that
// names it deliberately gets the stream the name means — reading /dev/stdin is
// what /dev/stdin is for, and it hands the program nothing it did not already
// have, since this is the stdin its own command was given.
const pythonStdinPath = "/dev/stdin"

// stdinSource serves the command's stdin to sandboxed Python.
//
// The contents are read once and cached. monty buffers the result of the first
// read into the file object and answers later reads, readline() and seek()
// from that buffer, so in practice this reads at most once per invocation; the
// cache is what keeps that true if the interpreter ever asks twice.
type stdinSource struct {
	mu   sync.Mutex
	r    io.Reader
	data []byte
	read bool
	err  error
}

func newStdinSource(r io.Reader) *stdinSource { return &stdinSource{r: r} }

// contents returns everything on stdin, reading it on first use.
//
// A nil reader is not an error: the interpreter leaves Stdin nil when nothing
// is piped or redirected in, and a program reading stdin at a terminal should
// see EOF rather than a failure, which is what an empty result gives it.
func (s *stdinSource) contents() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.read {
		return s.data, s.err
	}
	s.read = true
	if s.r == nil {
		return nil, nil
	}
	data, err := io.ReadAll(s.r)
	if err != nil {
		s.err = fmt.Errorf("python: cannot read stdin: %w", err)
		return nil, s.err
	}
	s.data = data
	return s.data, nil
}

// serveStdin answers a call against pythonStdinPath, or reports that it did not
// handle it so the caller falls through to the filesystem boundary.
//
// Only reading is served: the two reads a file handle produces, and an open()
// in a read mode, which hands back the same handle so `open("/dev/stdin")`
// behaves the way the name promises. Everything else naming this path — a
// write, a stat, Path.exists — is left to the regular authorization, which
// denies it. This is a stream, and answering more of the file interface than
// reading would invent answers CPython does not give.
func serveStdin(stdin *stdinSource, call *montygo.OsCall) (any, bool, error) {
	if stdin == nil {
		return nil, false, nil
	}
	switch call.Function {
	case "Path.read_text", "Path.read_bytes", "open":
	default:
		return nil, false, nil
	}
	path, err := pathArg(call, 0)
	if err != nil || path != pythonStdinPath {
		return nil, false, nil
	}

	if call.Function == "open" {
		mode := "r"
		if len(call.Args) > 1 {
			if s, ok := call.Args[1].(string); ok && s != "" {
				mode = s
			}
		}
		if strings.ContainsAny(mode, "wax+") {
			return nil, true, fmt.Errorf("python: %s is read-only", pythonStdinPath)
		}
		return montygo.FileHandle{Path: pythonStdinPath, Mode: mode}, true, nil
	}

	data, err := stdin.contents()
	if err != nil {
		return nil, true, err
	}
	if call.Function == "Path.read_bytes" {
		// montygo.Bytes is what makes this arrive as Python bytes; see the
		// read_bytes case in montyOsCall.
		return montygo.Bytes(data), true, nil
	}
	return string(data), true, nil
}
