package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExecute_BlockedEnvVarsRuntime covers assignments to blocked variables
// whose name the static check cannot see: the runtime check refuses the next
// external command instead of running it with the changed environment.
func TestExecute_BlockedEnvVarsRuntime(t *testing.T) {
	workDir := t.TempDir()
	evil := filepath.Join(workDir, "evil")
	if err := os.Mkdir(evil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(evil, "ls"), []byte("#!/bin/sh\necho PWNED\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	paths := []string{workDir}

	for _, cmd := range []string{
		`export "PATH=$PWD/evil:$PATH"; ls`,
		`n=PATH; export "$n=$PWD/evil:$PATH"; ls`,
		`set -a; read -r PATH <<< "$PWD/evil"; ls`,
		`set -a; for PATH in "$PWD/evil"; do ls; done`,
		`for PATH in "$PWD/evil"; do ls; done`,
		`export "LD_PRELOAD=$PWD/evil/x.so"; ls`,
		`set -a; for GIT_TEMPLATE_DIR in "$PWD/evil"; do ls; done`,
		`n=LESSOPEN; export "$n=|evil %s"; ls`,
		`export "PATH=$PWD/evil:$PATH"; bash -c ls`,
	} {
		t.Run(cmd, func(t *testing.T) {
			out, err := NewSandbox().Execute(context.Background(), cmd, workDir, paths, paths)
			if err == nil || !strings.Contains(err.Error(), "is not allowed") {
				t.Fatalf("expected a blocked variable refusal, got err=%v out=%q", err, out)
			}
			if strings.Contains(out, "PWNED") {
				t.Fatalf("command ran with the changed environment: %q", out)
			}
		})
	}

	for _, cmd := range []string{
		`export "FOO=bar"; ls`,
		`export "PATH=$PATH"; ls`,
		// Not exported, so no child inherits it.
		`for ENV in dev prod; do ls; done`,
		`read -r ZIP <<< x; ls`,
		`unset CDPATH; ls`,
	} {
		t.Run(cmd, func(t *testing.T) {
			if out, err := NewSandbox().Execute(context.Background(), cmd, workDir, paths, paths); err != nil {
				t.Fatalf("unexpected error: %v (out=%q)", err, out)
			}
		})
	}
}
