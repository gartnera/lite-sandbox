package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// realTempDir returns a t.TempDir with its own symlinks resolved (macOS
// resolves /var to /private/var), so expected paths compare equal.
func realTempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// TestResolvePath_DanglingSymlink checks that a symlink whose target doesn't
// exist is resolved to that target, as the kernel does when the path is
// created, rather than judged as the link's own path.
func TestResolvePath_DanglingSymlink(t *testing.T) {
	project := realTempDir(t)
	outside := realTempDir(t)
	mk := func(target, link string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(project, link)); err != nil {
			t.Fatal(err)
		}
	}
	mk(filepath.Join(outside, "planted"), "notes.txt")
	mk(filepath.Join(outside, "missing", "dir"), "dir")
	mk("notes.txt", "chain")
	mk("../"+filepath.Base(outside)+"/rel", "rel")
	mk("loop-b", "loop-a")
	mk("loop-a", "loop-b")
	if err := os.Mkdir(filepath.Join(project, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	mk(filepath.Join(project, "sub"), "inlink")
	mk(filepath.Join(project, "sub", "new.txt"), "inside")

	tests := []struct {
		path, want string
	}{
		{"notes.txt", filepath.Join(outside, "planted")},
		{"dir/x", filepath.Join(outside, "missing", "dir", "x")},
		{"chain", filepath.Join(outside, "planted")},
		{"rel", filepath.Join(outside, "rel")},
		{"inlink/new/../y", filepath.Join(project, "sub", "y")},
		{"inside", filepath.Join(project, "sub", "new.txt")},
		{"missing/notes.txt", filepath.Join(project, "missing", "notes.txt")},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := ResolvePath(tt.path, project); got != tt.want {
				t.Errorf("ResolvePath(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
	// A link loop can't be opened; it resolves to a path in the project.
	if got := ResolvePath("loop-a", project); filepath.Dir(got) != project {
		t.Errorf("ResolvePath(loop-a) = %q, want a path in %q", got, project)
	}
}

// TestExecute_DanglingSymlinkWriteEscape checks that a write through a
// symlink in the working directory whose target is a missing file outside it
// is refused, and doesn't create the target.
func TestExecute_DanglingSymlinkWriteEscape(t *testing.T) {
	project := realTempDir(t)
	outside := realTempDir(t)
	planted := filepath.Join(outside, "planted")
	if err := os.Symlink(planted, filepath.Join(project, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	s := newTestSandbox()
	for _, cmd := range []string{"echo hi > notes.txt", "touch notes.txt", "echo hi | tee notes.txt"} {
		t.Run(cmd, func(t *testing.T) {
			if _, err := s.Execute(context.Background(), cmd, project, []string{project}, []string{project}); err == nil {
				t.Fatalf("expected %q to be refused", cmd)
			}
			if _, err := os.Lstat(planted); err == nil {
				t.Fatalf("%q created %s outside the boundary", cmd, planted)
			}
		})
	}
}
