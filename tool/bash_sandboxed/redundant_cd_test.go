package bash_sandboxed

import (
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// TestValidateNoRedundantCd covers the narrow match: only a leading `cd` with a
// single literal absolute-path argument that resolves to workDir is rejected.
func TestValidateNoRedundantCd(t *testing.T) {
	workDir := t.TempDir()

	rejected := []struct {
		name    string
		command string
	}{
		{"chained", "cd " + workDir + " && echo hi"},
		{"chained with pipeline", "cd " + workDir + " && ls | wc -l"},
		{"standalone", "cd " + workDir},
		{"trailing slash", "cd " + workDir + "/ && echo hi"},
	}
	for _, tt := range rejected {
		t.Run("reject/"+tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validateNoRedundantCd(f, workDir)
			if err == nil {
				t.Fatal("expected redundant cd to be rejected")
			}
			if !strings.Contains(err.Error(), "unneeded cd") {
				t.Fatalf("expected 'unneeded cd' error, got %q", err.Error())
			}
		})
	}

	allowed := []struct {
		name    string
		command string
	}{
		{"subdirectory absolute", "cd " + workDir + "/sub && echo hi"},
		{"subdirectory relative", "cd sub && echo hi"},
		{"dot", "cd . && echo hi"},
		{"no cd", "echo hi"},
		{"dynamic target", `cd "$PWD" && echo hi`},
		{"cd with flag", "cd -P " + workDir + " && echo hi"},
		{"no argument", "cd && echo hi"},
	}
	for _, tt := range allowed {
		t.Run("allow/"+tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := validateNoRedundantCd(f, workDir); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

// TestValidateNoRedundantCd_EmptyWorkDir is a no-op guard: with no working
// directory there is nothing to compare against, so nothing is rejected.
func TestValidateNoRedundantCd_EmptyWorkDir(t *testing.T) {
	f, err := ParseBash("cd /some/abs/path && echo hi")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if err := validateNoRedundantCd(f, ""); err != nil {
		t.Fatalf("expected no rejection with empty workDir, got: %v", err)
	}
}

// TestRedundantCd_DefaultOnViaValidateCommand confirms the check is wired into
// the shared validateFile preflight and enabled by default.
func TestRedundantCd_DefaultOnViaValidateCommand(t *testing.T) {
	workDir := t.TempDir()
	s := newTestSandbox()

	err := s.ValidateCommand("cd "+workDir+" && echo hi", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected redundant cd to be rejected by default")
	}
	if !strings.Contains(err.Error(), "unneeded cd") {
		t.Fatalf("expected 'unneeded cd' error, got %q", err.Error())
	}
}

// TestRedundantCd_Disabled confirms the config toggle turns the check off.
func TestRedundantCd_Disabled(t *testing.T) {
	workDir := t.TempDir()
	s := newTestSandbox()
	s.UpdateConfig(&config.Config{RejectRedundantCd: boolPtr(false)}, workDir)

	err := s.ValidateCommand("cd "+workDir+" && echo hi", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("expected redundant cd to be allowed when disabled, got: %v", err)
	}
}
