package os_sandbox

import (
	"io"
	"os"

	"golang.org/x/term"
)

// isTerminal reports whether r is a terminal: an interactive shell's own
// stdin, which Exec does not pass on to the worker.
func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	// Fd is only called on character devices: it puts the file in blocking
	// mode, which a pipe's reader may rely on not being in.
	if fi, err := f.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}
