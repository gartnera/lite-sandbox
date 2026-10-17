package bash_sandboxed

import (
	"strings"
	"testing"
)

func TestValidatePgrep_Allowed(t *testing.T) {
	workDir := t.TempDir()
	s := newTestSandbox()
	for _, cmd := range []string{
		"pgrep node",
		"pgrep -f /usr/bin/node",
		"pgrep -af 'go run ./cmd/server'",
		"pgrep -l -u root sshd",
		"pgrep -d/ -f server",
		"pgrep -dF /etc/passwd", // delimiter "F"; /etc/passwd is the pattern
		"pgrep --delimiter /etc server",
		"pgrep -F server.pid",
		"pgrep -lF ./server.pid",
		"pgrep --pidfile " + workDir + "/server.pid",
		"pgrep -- -F /etc/passwd",
		"pgrep -c sleep",
	} {
		t.Run(cmd, func(t *testing.T) {
			f, err := ParseBash(cmd)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := s.validate(f); err != nil {
				t.Fatalf("expected %q to validate, got: %v", cmd, err)
			}
			if err := validatePaths(f, workDir, []string{workDir}, []string{workDir}); err != nil {
				t.Fatalf("expected %q to pass the path check, got: %v", cmd, err)
			}
		})
	}
}

func TestValidatePgrep_Blocked(t *testing.T) {
	workDir := t.TempDir()
	s := newTestSandbox()
	for _, tt := range []struct {
		command string
		errMsg  string
	}{
		{"pgrep -F /etc/passwd", "outside allowed directories"},
		{"pgrep -lF /etc/passwd", "outside allowed directories"},
		{"pgrep -F -/../../etc/passwd", "outside allowed directories"},
		{"pgrep --pidfile /etc/passwd", "outside allowed directories"},
		{"pgrep --pidf /etc/passwd", "outside allowed directories"},
		{"pgrep node -F ../outside.pid", "outside allowed directories"},
		{"pgrep -F/etc/passwd", "pid file as its own argument"},
		{"pgrep -lF/etc/passwd", "pid file as its own argument"},
		{"pgrep --pidfile=/etc/passwd", "pid file as its own argument"},
		{"pgrep --pi=server.pid", "pid file as its own argument"},
	} {
		t.Run(tt.command, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = s.validate(f)
			if err == nil {
				err = validatePaths(f, workDir, []string{workDir}, []string{workDir})
			}
			if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected %q to be blocked with %q, got: %v", tt.command, tt.errMsg, err)
			}
		})
	}
}

// The pid file is re-checked after expansion, where the static pass saw only
// a dynamic word.
func TestRuntime_PgrepPidfileExpanded(t *testing.T) {
	_, err := runCallHandlerOnly(t, newTestSandbox(), false, `p=/etc/passwd; pgrep -F "$p"`)
	if err == nil || !strings.Contains(err.Error(), "outside allowed directories") {
		t.Errorf("expected expanded pid file to be refused, got: %v", err)
	}
	_, err = runCallHandlerOnly(t, newTestSandbox(), false, `p=/usr/bin/node; pgrep -f "$p"`)
	if err != nil {
		t.Errorf("expected expanded pattern to be allowed, got: %v", err)
	}
}
