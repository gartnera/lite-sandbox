package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/audit"
)

// newModeSandbox returns a sandbox in the given mode with auditing on, writing
// to a temp log whose path is returned.
func newModeSandbox(t *testing.T, mode config.Mode, workDir string) (*Sandbox, string) {
	t.Helper()
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("LITE_SANDBOX_AUDIT_LOG", logPath)
	on := true
	s := NewSandbox()
	s.UpdateConfig(&config.Config{Mode: string(mode), Audit: &on}, workDir)
	t.Cleanup(func() { s.Close() })
	return s, logPath
}

func readAudit(t *testing.T, path string) []audit.Record {
	t.Helper()
	recs, err := audit.Read(path, time.Time{})
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	return recs
}

func TestRule_BlockedIn(t *testing.T) {
	cases := []struct {
		r         rule
		open, dl  bool
		allowlist bool
	}{
		{ruleCommandWhitelist, false, false, true},
		{ruleRuntimeDisabled, false, false, true},
		{ruleLocalBinary, false, false, true},
		{rulePathBoundary, false, true, true},
		{ruleArgValidator, false, true, true},
		{ruleStructural, false, true, true},
		{ruleRedundantCd, false, true, true},
	}
	for _, c := range cases {
		if got := c.r.blockedIn(config.ModeOpen); got != c.open {
			t.Errorf("%s open = %v", c.r, got)
		}
		if got := c.r.blockedIn(config.ModeDenylist); got != c.dl {
			t.Errorf("%s denylist = %v", c.r, got)
		}
		if got := c.r.blockedIn(config.ModeAllowlist); got != c.allowlist {
			t.Errorf("%s allowlist = %v", c.r, got)
		}
	}
}

func TestDenylistMode_UnlistedCommandsRun(t *testing.T) {
	workDir := t.TempDir()
	s, logPath := newModeSandbox(t, config.ModeDenylist, workDir)

	// An unlisted external runs. perl is not on the whitelist and is present on
	// every CI runner, so this exercises the ExecHandler gate, not just the
	// static one.
	out, err := s.Execute(context.Background(), `perl -e 'print "ran\n"'`, workDir, []string{workDir}, []string{workDir})
	if err != nil || !strings.Contains(out, "ran") {
		t.Fatalf("unlisted command should run in denylist mode: out=%q err=%v", out, err)
	}

	// Static validation alone also passes for a classic day-one blocker.
	if err := s.ValidateCommand("npm test", workDir, []string{workDir}, []string{workDir}); err != nil {
		t.Errorf("npm should validate in denylist mode: %v", err)
	}

	// The whitelist finding was audited as advisory, tagged allowlist-only.
	recs := readAudit(t, logPath)
	var found bool
	for _, r := range recs {
		if r.Rule == string(ruleCommandWhitelist) && r.Subject == "npm" {
			found = true
			if r.Blocked {
				t.Errorf("npm finding should not be blocked in denylist: %+v", r)
			}
			if !slices.Equal(r.WouldBlockIn, []string{"allowlist"}) {
				t.Errorf("npm would_block_in = %v", r.WouldBlockIn)
			}
			if r.Mode != "denylist" || r.Source != "hook" || r.Command != "npm test" || r.CWD != workDir {
				t.Errorf("npm record attribution = %+v", r)
			}
		}
	}
	if !found {
		t.Errorf("no advisory whitelist record for npm in %+v", recs)
	}
}

func TestDenylistMode_KeepsBoundaryAndValidators(t *testing.T) {
	workDir := t.TempDir()
	outside := t.TempDir()
	for _, f := range []string{"secret", "x.py"} {
		if err := os.WriteFile(filepath.Join(outside, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s, logPath := newModeSandbox(t, config.ModeDenylist, workDir)
	paths := []string{workDir}

	blocked := []struct{ name, cmd, want string }{
		{"static path", "find " + outside, "outside allowed directories"},
		{"expanded path", "D=" + outside + "; cat $D/secret", "outside allowed directories"},
		{"redirect", "echo x > " + outside + "/out", "outside allowed directories"},
		{"git push", "git push origin main", "push"},
		{"find -delete", "find . -delete", "not allowed"},
		{"read-write redirect", "cat <> file", "not allowed"},
		{"unlisted cmd, bad path", "python3 " + outside + "/x.py", "outside allowed directories"},
	}
	for _, c := range blocked {
		t.Run(c.name, func(t *testing.T) {
			_, err := s.Execute(context.Background(), c.cmd, workDir, paths, paths)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%q: want error containing %q, got %v", c.cmd, c.want, err)
			}
		})
	}

	recs := readAudit(t, logPath)
	var blockedRecs int
	for _, r := range recs {
		if r.Blocked {
			blockedRecs++
			if !slices.Equal(r.WouldBlockIn, []string{"denylist", "allowlist"}) {
				t.Errorf("blocked finding tagged %v: %+v", r.WouldBlockIn, r)
			}
		}
	}
	if blockedRecs < len(blocked) {
		t.Errorf("expected at least %d blocked audit records, got %d", len(blocked), blockedRecs)
	}
}

func TestDenylistMode_RuntimeGatesAdvisory(t *testing.T) {
	workDir := t.TempDir()
	s, logPath := newModeSandbox(t, config.ModeDenylist, workDir)
	paths := []string{workDir}

	// go is whitelisted but runtime-gated; in denylist it validates without the
	// runtime being enabled...
	if err := s.ValidateCommand("go test ./...", workDir, paths, paths); err != nil {
		t.Fatalf("go should validate in denylist mode: %v", err)
	}
	// ...while the runtime's own shared-state checks still apply.
	if err := s.ValidateCommand("pnpm publish", workDir, paths, paths); err == nil || !strings.Contains(err.Error(), "publish") {
		t.Fatalf("pnpm publish should still be rejected in denylist mode, got %v", err)
	}
	// Wrapped unlisted commands are advisory too.
	if err := s.ValidateCommand("xargs python3", workDir, paths, paths); err != nil {
		t.Fatalf("xargs python3 should validate in denylist mode: %v", err)
	}

	recs := readAudit(t, logPath)
	var sawGo bool
	for _, r := range recs {
		if r.Rule == string(ruleRuntimeDisabled) && r.Subject == "go" && !r.Blocked {
			sawGo = true
		}
	}
	if !sawGo {
		t.Errorf("expected an advisory runtime_disabled record for go: %+v", recs)
	}
}

func TestDenylistMode_LocalScripts(t *testing.T) {
	workDir := t.TempDir()
	s, _ := newModeSandbox(t, config.ModeDenylist, workDir)
	paths := []string{workDir}

	sh := filepath.Join(workDir, "run.sh")
	if err := os.WriteFile(sh, []byte("#!/bin/bash\necho from-script\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := s.Execute(context.Background(), "./run.sh", workDir, paths, paths)
	if err != nil || !strings.Contains(out, "from-script") {
		t.Fatalf("./run.sh in denylist: out=%q err=%v", out, err)
	}

	// A script for another interpreter is exec'd, not parsed as bash. Use a
	// shebang naming a binary that certainly exists so the test does not depend
	// on python being installed.
	other := filepath.Join(workDir, "run.other")
	if err := os.WriteFile(other, []byte("#!/bin/echo\nthis is not bash: import os\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err = s.Execute(context.Background(), "./run.other", workDir, paths, paths)
	if err != nil || !strings.Contains(out, "run.other") {
		t.Fatalf("./run.other should exec via its shebang interpreter: out=%q err=%v", out, err)
	}
	// Static validation must not parse it as bash either.
	if err := s.ValidateCommand("./run.other", workDir, paths, paths); err != nil {
		t.Errorf("static validation of a non-shell script: %v", err)
	}
}

func TestAllowlistMode_UnchangedAndHinted(t *testing.T) {
	workDir := t.TempDir()
	s, logPath := newModeSandbox(t, config.ModeAllowlist, workDir)
	paths := []string{workDir}

	_, err := s.Execute(context.Background(), "npm test", workDir, paths, paths)
	if err == nil {
		t.Fatal("npm should be blocked in allowlist mode")
	}
	for _, want := range []string{`command "npm" is not allowed`, "extra-commands add npm", "mode set denylist"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks hint %q", err, want)
		}
	}
	_, err = s.Execute(context.Background(), "go test ./...", workDir, paths, paths)
	if err == nil || !strings.Contains(err.Error(), "runtimes go enable") {
		t.Errorf("go error should hint the enable command: %v", err)
	}
	_, err = s.Execute(context.Background(), "./run.sh", workDir, paths, paths)
	if err == nil || !strings.Contains(err.Error(), "direct execution") || !strings.Contains(err.Error(), "local-binary-execution enable") {
		t.Errorf("script error should name the local-binary gate: %v", err)
	}

	for _, r := range readAudit(t, logPath) {
		if !r.Blocked {
			t.Errorf("allowlist mode should block every finding: %+v", r)
		}
	}
}

func TestOpenMode_EverythingRunsAndIsAudited(t *testing.T) {
	workDir := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("shh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, logPath := newModeSandbox(t, config.ModeOpen, workDir)
	paths := []string{workDir}

	out, err := s.Execute(context.Background(), "cat "+outside+"/secret", workDir, paths, paths)
	if err != nil || out != "shh\n" {
		t.Fatalf("open mode should run an out-of-boundary read: out=%q err=%v", out, err)
	}
	if _, err := s.Execute(context.Background(), `perl -e 'print 1'`, workDir, paths, paths); err != nil {
		t.Fatalf("open mode should run unlisted commands: %v", err)
	}

	recs := readAudit(t, logPath)
	var sawBoundary, sawWhitelist bool
	for _, r := range recs {
		if r.Blocked {
			t.Errorf("open mode must not block: %+v", r)
		}
		switch r.Rule {
		case string(rulePathBoundary):
			sawBoundary = true
			if r.Subject != filepath.Join(outside, "secret") {
				t.Errorf("boundary subject = %q", r.Subject)
			}
			if !slices.Equal(r.WouldBlockIn, []string{"denylist", "allowlist"}) {
				t.Errorf("boundary would_block_in = %v", r.WouldBlockIn)
			}
		case string(ruleCommandWhitelist):
			sawWhitelist = true
		}
	}
	if !sawBoundary || !sawWhitelist {
		t.Errorf("expected boundary and whitelist advisories, got %+v", recs)
	}
}

func TestAudit_OffWritesNothing(t *testing.T) {
	workDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("LITE_SANDBOX_AUDIT_LOG", logPath)
	s := NewSandbox()
	s.UpdateConfig(&config.Config{Mode: "open"}, workDir)
	defer s.Close()
	if _, err := s.Execute(context.Background(), "true", workDir, []string{workDir}, []string{workDir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("audit log should not exist when audit is off (stat err=%v)", err)
	}

	// Toggling audit on via a config reload starts logging; off again stops it.
	on := true
	s.UpdateConfig(&config.Config{Mode: "open", Audit: &on}, workDir)
	if s.auditLogger() == nil {
		t.Fatal("audit logger should be set after enabling")
	}
	s.UpdateConfig(&config.Config{Mode: "open"}, workDir)
	if s.auditLogger() != nil {
		t.Fatal("audit logger should be dropped after disabling")
	}
}

func TestScriptInterpreter(t *testing.T) {
	cases := map[string]string{
		"":                                   "",
		"echo hi\n":                          "",
		"#!/bin/bash\necho":                  "bash",
		"#!/usr/bin/env python3\nimport os":  "python3",
		"#!/usr/bin/env -S node --harmony\n": "node",
		"#!/usr/bin/env FOO=1 ruby\n":        "ruby",
		"#!/usr/local/bin/node":              "node",
		"#! /bin/sh -e\n":                    "sh",
	}
	for in, want := range cases {
		if got := scriptInterpreter(in); got != want {
			t.Errorf("scriptInterpreter(%q) = %q, want %q", in, got, want)
		}
	}
}
