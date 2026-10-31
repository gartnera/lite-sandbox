package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// A backslash in an argument that was expanded at runtime is real: the
// validators must see it, or sed's script check reads another script than
// sed does.
func TestRuntimeBackslashesAreNotStripped(t *testing.T) {
	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "f"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := newTestSandbox()
	for _, cmd := range []string{
		"X=$'a foo\\\\\\\\\\nw pwn'; sed -n \"$X\" f",
		"sed -n $'a foo\\\\\\\\\\nw pwn' f",
		"sort $'--compress\\x2dprogram=sh' f",
		"sort $'--compress-program\\x3dsh' f",
		"X=$'--compress\\x2dprogram=sh'; sort \"$X\" f",
	} {
		_, err := s.Execute(context.Background(), cmd, workDir, []string{workDir}, []string{workDir})
		if err == nil {
			t.Errorf("%q was allowed", cmd)
		}
		if _, statErr := os.Stat(filepath.Join(workDir, "pwn")); statErr == nil {
			t.Fatalf("%q wrote pwn", cmd)
		}
	}
}
