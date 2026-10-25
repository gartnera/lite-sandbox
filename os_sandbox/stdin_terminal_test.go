package os_sandbox

import (
	"io"
	"os"
	"testing"
	"time"
)

// terminalReader works on any pollable descriptor; a pipe stands in for the
// terminal here.
func TestTerminalReaderStopsWithoutConsuming(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	done := make(chan struct{})
	tr := &terminalReader{fd: int(r.Fd()), done: done}

	if _, err := w.WriteString("abc"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	n, err := tr.Read(buf)
	if err != nil || string(buf[:n]) != "abc" {
		t.Fatalf("Read = %q, %v; want abc", buf[:n], err)
	}

	// Blocked with nothing to read, it returns once done is closed.
	result := make(chan error, 1)
	go func() {
		_, err := tr.Read(buf)
		result <- err
	}()
	time.Sleep(2 * terminalPollMillis * time.Millisecond)
	close(done)
	select {
	case err := <-result:
		if err != io.EOF {
			t.Fatalf("Read after done = %v, want EOF", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return after done was closed")
	}

	// Input that arrives afterwards is left for the next reader.
	if _, err := w.WriteString("next"); err != nil {
		t.Fatal(err)
	}
	if n, err := tr.Read(buf); err != io.EOF || n != 0 {
		t.Fatalf("Read after done = %d, %v; want 0, EOF", n, err)
	}
	n, err = r.Read(buf)
	if err != nil || string(buf[:n]) != "next" {
		t.Fatalf("pipe read = %q, %v; want next", buf[:n], err)
	}
}
