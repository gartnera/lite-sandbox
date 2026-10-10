package approval

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// isolate points the ticket directory at a fresh temp dir (os.UserCacheDir
// reads XDG_CACHE_HOME on Linux and HOME on macOS).
// It returns a project directory to make requests from.
func isolate(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("HOME", dir)
	return t.TempDir()
}

func TestIssueConsume(t *testing.T) {
	cwd := isolate(t)
	sub := CommandSubject("rm -rf build")
	if err := Consume(cwd, sub); !errors.Is(err, ErrNoTicket) {
		t.Fatalf("Consume before Issue = %v, want ErrNoTicket", err)
	}
	if err := Issue(cwd, sub, "rm -rf build"); err != nil {
		t.Fatal(err)
	}
	if err := Consume(cwd, CommandSubject("rm -rf build ")); !errors.Is(err, ErrNoTicket) {
		t.Fatalf("Consume of another command = %v, want ErrNoTicket", err)
	}
	if err := Consume(cwd, sub); err != nil {
		t.Fatalf("Consume after Issue: %v", err)
	}
	if err := Consume(cwd, sub); !errors.Is(err, ErrNoTicket) {
		t.Fatalf("second Consume = %v, want ErrNoTicket", err)
	}
}

// TestSubjectsDistinct: the parts are length-prefixed and the kind leads, so
// no two subjects name the same ticket.
func TestSubjectsDistinct(t *testing.T) {
	cwd := isolate(t)
	if err := Issue(cwd, Subject{"config", "commands", "allow"}, ""); err != nil {
		t.Fatal(err)
	}
	for _, s := range []Subject{
		CommandSubject("commands allow"),
		{"command", "commands", "allow"},
		{"config", "commands allow"},
		{"config", "commands", "allow", ""},
	} {
		if err := Consume(cwd, s); !errors.Is(err, ErrNoTicket) {
			t.Errorf("Consume(%q) = %v, want ErrNoTicket", s, err)
		}
	}
}

func TestConsumeExpired(t *testing.T) {
	cwd := isolate(t)
	sub := Subject{"config", "paths", "allow", "/srv"}
	if err := Issue(cwd, sub, ""); err != nil {
		t.Fatal(err)
	}
	dir, err := Dir()
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-TicketTTL - time.Minute)
	if err := os.Chtimes(filepath.Join(dir, key(cwd, sub)), old, old); err != nil {
		t.Fatal(err)
	}
	if err := Consume(cwd, sub); !errors.Is(err, ErrNoTicket) {
		t.Fatalf("Consume of an expired ticket = %v, want ErrNoTicket", err)
	}
}

func TestIssuePrunesExpired(t *testing.T) {
	cwd := isolate(t)
	stale := Subject{"config", "profiles", "enable", "go"}
	if err := Issue(cwd, stale, ""); err != nil {
		t.Fatal(err)
	}
	dir, _ := Dir()
	old := time.Now().Add(-TicketTTL - time.Minute)
	if err := os.Chtimes(filepath.Join(dir, key(cwd, stale)), old, old); err != nil {
		t.Fatal(err)
	}
	if err := Issue(cwd, CommandSubject("rm x"), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, key(cwd, stale))); !os.IsNotExist(err) {
		t.Fatalf("expired ticket not pruned: %v", err)
	}
}
