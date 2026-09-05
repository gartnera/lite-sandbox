package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/internal/audit"
)

func TestBuildReport(t *testing.T) {
	dir := t.TempDir()
	recs := []audit.Record{
		{Rule: "command_whitelist", Subject: "npm", Command: "npm test", Blocked: false, WouldBlockIn: []string{"allowlist"}},
		{Rule: "command_whitelist", Subject: "npm", Command: "npm run build", Blocked: false, WouldBlockIn: []string{"allowlist"}},
		{Rule: "command_whitelist", Subject: "./run.sh", Blocked: true, WouldBlockIn: []string{"allowlist"}},
		{Rule: "runtime_disabled", Subject: "go", Blocked: false, WouldBlockIn: []string{"allowlist"}},
		{Rule: "path_boundary", Subject: filepath.Join(dir, "a.txt"), Blocked: true, WouldBlockIn: []string{"denylist", "allowlist"}},
		{Rule: "path_boundary", Subject: dir, Blocked: true, WouldBlockIn: []string{"denylist", "allowlist"}},
	}
	rep := buildReport(recs, 10, nil)

	if rep.Records != 6 {
		t.Errorf("records = %d", rep.Records)
	}
	if rep.Blocked["path_boundary"] != 2 || rep.Blocked["command_whitelist"] != 1 {
		t.Errorf("blocked = %v", rep.Blocked)
	}
	if rep.WouldBlock["allowlist"] != 3 {
		t.Errorf("would_block = %v", rep.WouldBlock)
	}
	subj := rep.Subjects["command_whitelist"]
	if len(subj) != 2 || subj[0].Subject != "npm" || subj[0].Count != 2 || subj[0].Example != "npm test" {
		t.Errorf("subjects = %+v", subj)
	}

	want := map[string]int{
		"lite-sandbox config extra-commands add npm":        2,
		"lite-sandbox config local-binary-execution enable": 1,
		"lite-sandbox config runtimes go enable":            1,
		"lite-sandbox config readable-paths add " + dir:     2,
	}
	got := map[string]int{}
	for _, s := range rep.Suggestions {
		got[s.Command] = s.Count
	}
	for cmd, n := range want {
		if got[cmd] != n {
			t.Errorf("suggestion %q count = %d, want %d (all: %+v)", cmd, got[cmd], n, rep.Suggestions)
		}
	}
	// Most findings first.
	if rep.Suggestions[0].Count < rep.Suggestions[len(rep.Suggestions)-1].Count {
		t.Errorf("suggestions not sorted by count: %+v", rep.Suggestions)
	}
}

func TestBuildReport_ProtectedPathsNotSuggested(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	aws := filepath.Join(home, ".aws")
	recs := []audit.Record{
		{Rule: "path_boundary", Subject: filepath.Join(aws, "credentials"), Blocked: true, WouldBlockIn: []string{"denylist", "allowlist"}},
		{Rule: "path_boundary", Subject: home, Blocked: true, WouldBlockIn: []string{"denylist", "allowlist"}},
		{Rule: "path_boundary", Subject: filepath.Join(home, "other-repo", "x.go"), Blocked: true, WouldBlockIn: []string{"denylist", "allowlist"}},
	}
	rep := buildReport(recs, 10, []string{home, aws})
	for _, s := range rep.Suggestions {
		if strings.Contains(s.Command, aws) || strings.HasSuffix(s.Command, " "+home) {
			t.Errorf("must not suggest widening to a protected path: %+v", s)
		}
	}
	if len(rep.Suggestions) != 1 || !strings.Contains(rep.Suggestions[0].Command, filepath.Join(home, "other-repo")) {
		t.Errorf("expected only the other-repo suggestion, got %+v", rep.Suggestions)
	}
	// The findings themselves still show up.
	if len(rep.Subjects["path_boundary"]) != 3 {
		t.Errorf("subjects = %+v", rep.Subjects["path_boundary"])
	}
}

func TestParseSince(t *testing.T) {
	if d, err := parseSince("7d"); err != nil || d != 7*24*time.Hour {
		t.Errorf("7d = %v, %v", d, err)
	}
	if d, err := parseSince("36h"); err != nil || d != 36*time.Hour {
		t.Errorf("36h = %v, %v", d, err)
	}
	if _, err := parseSince("soon"); err == nil {
		t.Error("expected error")
	}
}

func TestAuditReportCmd_EndToEnd(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("LITE_SANDBOX_AUDIT_LOG", logPath)
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))

	out := captureStdout(t, func() {
		if err := auditReportCmd.RunE(auditReportCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "No findings recorded") {
		t.Errorf("empty report = %q", out)
	}

	l := audit.New(logPath, 0)
	if err := l.Write(audit.Record{Mode: "denylist", Source: "bash", Layer: "static", Rule: "command_whitelist", Subject: "npm", Command: "npm test", WouldBlockIn: []string{"allowlist"}}); err != nil {
		t.Fatal(err)
	}
	out = captureStdout(t, func() {
		if err := auditReportCmd.RunE(auditReportCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{"Findings: 1", "allowlist", "npm", "extra-commands add npm"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}

	auditReportJSON = true
	t.Cleanup(func() { auditReportJSON = false })
	out = captureStdout(t, func() {
		if err := auditReportCmd.RunE(auditReportCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"records": 1`) {
		t.Errorf("json report = %q", out)
	}

	if err := auditClearCmd.RunE(auditClearCmd, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("log should be cleared, stat err=%v", err)
	}
}
