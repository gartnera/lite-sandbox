package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/internal/audit"
)

func TestAuditReportCmd_EndToEnd(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.jsonl")
	t.Setenv("LITE_SANDBOX_AUDIT_LOG", logPath)
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { auditReportJSON = false; auditReportCWD = "" })

	out := captureStdout(t, func() {
		if err := auditReportCmd.RunE(auditReportCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "No findings recorded") {
		t.Errorf("empty report = %q", out)
	}

	l := audit.New(logPath, 0)
	for _, r := range []audit.Record{
		{CWD: "/work/app", Mode: "denylist", Source: "bash", Layer: "static", Rule: "command_whitelist", Subject: "npm", Command: "npm test", Fix: "lite-sandbox config extra-commands add npm", WouldBlockIn: []string{"allowlist"}},
		{CWD: "/work/other", Mode: "denylist", Source: "bash", Layer: "static", Rule: "command_whitelist", Subject: "evil\x1b[2Kname", Command: "x", Fix: "lite-sandbox config extra-commands add evil", WouldBlockIn: []string{"allowlist"}},
	} {
		if err := l.Write(r); err != nil {
			t.Fatal(err)
		}
	}
	out = captureStdout(t, func() {
		if err := auditReportCmd.RunE(auditReportCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	for _, want := range []string{"Findings: 2", "allowlist", "npm", "extra-commands add npm", "review before applying"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("control characters leaked into the report:\n%q", out)
	}

	auditReportCWD = "/work/app"
	out = captureStdout(t, func() {
		if err := auditReportCmd.RunE(auditReportCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Findings: 1") || !strings.Contains(out, "Working directory: /work/app") {
		t.Errorf("cwd-filtered report:\n%s", out)
	}
	auditReportCWD = ""

	auditReportJSON = true
	out = captureStdout(t, func() {
		if err := auditReportCmd.RunE(auditReportCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"records": 2`) {
		t.Errorf("json report = %q", out)
	}
	auditReportJSON = false

	if err := auditClearCmd.RunE(auditClearCmd, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Errorf("log should be cleared, stat err=%v", err)
	}
}

func TestProtectedPaths_IncludesBothDenyLists(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	got := protectedPaths(nil)
	for _, want := range []string{home, filepath.Join(home, ".aws"), filepath.Join(home, ".ssh"), filepath.Join(home, ".bashrc")} {
		found := false
		for _, p := range got {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("protected paths missing %s", want)
		}
	}
}
