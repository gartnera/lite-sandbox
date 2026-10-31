package bash_sandboxed

import (
	"context"
	"io"

	"mvdan.cc/sh/v3/interp"
)

// stdStreamFDs maps the names bash treats specially in redirections to the
// descriptor they duplicate (see REDIRECTION in bash(1)). The interpreter runs
// in the lite-sandbox process, whose own stdin and stdout may be the MCP
// transport, so these names must never reach the host filesystem from it:
// openStdStream serves them from the command's current streams instead, the
// way bash emulates them where the OS lacks them.
var stdStreamFDs = map[string]int{
	"/dev/stdin":  0,
	"/dev/fd/0":   0,
	"/dev/stdout": 1,
	"/dev/fd/1":   1,
	"/dev/stderr": 2,
	"/dev/fd/2":   2,
}

// isStdStreamRedirect reports whether a redirect to path names a standard
// stream in the redirect's direction: /dev/stdin for input, /dev/stdout or
// /dev/stderr for output.
func isStdStreamRedirect(path string, isWrite bool) bool {
	fd, ok := stdStreamFDs[path]
	return ok && (fd != 0) == isWrite
}

// isStdStreamArg reports whether arg is a standard-stream name passed to a
// command that opens it as its own descriptor (`tee /dev/stdout`,
// `cat /dev/stdin`, `dd of=/dev/stderr`). That is a separate process, so the
// name reaches only the streams the sandbox already gave it. In-process
// commands (commandSpec.inProcess), which open it with the host's own
// descriptors, are left to the boundary check.
func isStdStreamArg(cmdName, arg string) bool {
	_, ok := stdStreamFDs[arg]
	return ok && !lookupCommand(cmdName).inProcess
}

// openStdStream serves a redirect to a standard-stream name from the
// command's current streams (hc), so `echo hi > /dev/stdout` writes where
// stdout points at that redirect, `2> /dev/stdout` included. ok is false when
// path is not such a name in the direction flag opens it.
func openStdStream(ctx context.Context, path string, flag int) (io.ReadWriteCloser, bool) {
	if !isStdStreamRedirect(path, isWriteFlag(flag)) {
		return nil, false
	}
	hc := interp.HandlerCtx(ctx)
	s := stdStream{r: hc.Stdin, w: io.Discard}
	switch stdStreamFDs[path] {
	case 1:
		s.w = hc.Stdout
	case 2:
		s.w = hc.Stderr
	}
	if s.r == nil {
		s.r = eofReader{}
	}
	if s.w == nil {
		s.w = io.Discard
	}
	return s, true
}

// stdStream is a borrowed stream: closing it leaves the underlying one open.
type stdStream struct {
	r io.Reader
	w io.Writer
}

func (s stdStream) Read(p []byte) (int, error)  { return s.r.Read(p) }
func (s stdStream) Write(p []byte) (int, error) { return s.w.Write(p) }
func (stdStream) Close() error                  { return nil }

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) { return 0, io.EOF }
