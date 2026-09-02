package bash_sandboxed

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"mvdan.cc/sh/v3/interp"
)

// runCallHandlerOnly runs command through the interpreter with the sandbox's
// security handlers installed, but with the final ExecHandler replaced by a
// no-op. This exercises the runtime CallHandler exactly as Execute does,
// without needing an OS-sandbox worker for the useOSSandbox=true case.
func runCallHandlerOnly(t *testing.T, s *Sandbox, useOSSandbox bool, command string) (string, error) {
	t.Helper()
	f, err := ParseBash(command)
	if err != nil {
		t.Fatalf("parse error for %q: %v", command, err)
	}
	dir := t.TempDir()
	var stderr bytes.Buffer
	opts := []interp.RunnerOption{
		interp.Dir(dir),
		interp.StdIO(nil, &stderr, &stderr),
	}
	opts = append(opts, s.buildSecurityHandlers([]string{dir}, []string{dir}, useOSSandbox)...)
	// Later options win, so this replaces the dispatching ExecHandler.
	opts = append(opts, interp.ExecHandler(func(ctx context.Context, args []string) error { return nil }))
	r, err := interp.New(opts...)
	if err != nil {
		t.Fatalf("interp.New: %v", err)
	}
	err = r.Run(context.Background(), f)
	return stderr.String(), err
}

// The interpreter reports kill as a builtin it does not implement, so the
// CallHandler's builtin whitelist sees it before anything else. Without the OS
// sandbox it must stay rejected as "not allowed"; with it, the CallHandler must
// let it through so the interpreter's own "unsupported builtin" error is what
// the agent sees (and can fall back to pkill from). The static-only
// TestValidate_ProcessControlGatedOnOSSandbox cannot observe either.
func TestRuntime_KillGatedOnOSSandbox(t *testing.T) {
	if !interp.IsBuiltin("kill") {
		t.Skip("interp does not report kill as a builtin; the CallHandler never sees it")
	}
	stderr, err := runCallHandlerOnly(t, newTestSandbox(), false, "kill -0 1")
	if err == nil || !strings.Contains(err.Error(), `command "kill" is not allowed`) {
		t.Errorf("without OS sandbox: expected kill to be rejected as not allowed, got err=%v stderr=%q", err, stderr)
	}

	stderr, err = runCallHandlerOnly(t, newTestSandbox(), true, "kill -0 1")
	if err != nil && strings.Contains(err.Error(), "is not allowed") {
		t.Fatalf("with OS sandbox: kill must not be rejected by the whitelist, got: %v", err)
	}
	if !strings.Contains(stderr, "unsupported builtin") {
		t.Errorf("with OS sandbox: expected the interpreter's unsupported-builtin error, got err=%v stderr=%q", err, stderr)
	}
}
