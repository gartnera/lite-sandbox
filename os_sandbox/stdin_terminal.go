package os_sandbox

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// terminalPollMillis is how often a terminal stdin pump wakes to check
// whether its command has finished.
const terminalPollMillis = 50

// stdinTerminal returns the descriptor of r when it is a terminal: an
// interactive shell's own stdin, which unlike a pipe never reaches EOF on its
// own when the command is done with it.
func stdinTerminal(r io.Reader) (int, bool) {
	f, ok := r.(*os.File)
	if !ok {
		return -1, false
	}
	// Fd is only called on character devices: it puts the file in blocking
	// mode, which a pipe's reader may rely on not being in.
	if fi, err := f.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return -1, false
	}
	fd := int(f.Fd())
	return fd, term.IsTerminal(fd)
}

// terminalReader reads a terminal until done is closed, then reports EOF. It
// only reads input that poll says is already there, so once done is closed it
// takes nothing more from the terminal: keystrokes typed after the command
// finished stay for whoever reads the terminal next (the shell's prompt).
type terminalReader struct {
	fd   int
	done <-chan struct{}
}

func (t *terminalReader) Read(p []byte) (int, error) {
	fds := []unix.PollFd{{Fd: int32(t.fd), Events: unix.POLLIN}}
	for {
		select {
		case <-t.done:
			return 0, io.EOF
		default:
		}
		n, err := unix.Poll(fds, terminalPollMillis)
		if errors.Is(err, unix.EINTR) || (err == nil && n == 0) {
			continue
		}
		if err != nil {
			return 0, err
		}
		n, err = unix.Read(t.fd, p)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		if err != nil {
			return 0, err
		}
		if n == 0 {
			// Ctrl-D at the start of a line.
			return 0, io.EOF
		}
		return n, nil
	}
}
