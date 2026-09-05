package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildReport(t *testing.T) {
	// The boundary subjects live under a fake home: on macOS t.TempDir() is
	// under /var/folders, which the report treats as a system root unless the
	// path is inside the home directory.
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, "repo")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	recs := []Record{
		{Rule: "command_whitelist", Subject: "npm", Command: "npm test", Fix: "lite-sandbox config extra-commands add npm", WouldBlockIn: []string{"allowlist"}},
		{Rule: "command_whitelist", Subject: "npm", Command: "npm run build", Fix: "lite-sandbox config extra-commands add npm", WouldBlockIn: []string{"allowlist"}},
		{Rule: "local_binary", Subject: "./run.sh", Fix: "lite-sandbox config local-binary-execution enable", Blocked: true, WouldBlockIn: []string{"allowlist"}},
		{Rule: "runtime_disabled", Subject: "go", Fix: "lite-sandbox config runtimes go enable", WouldBlockIn: []string{"allowlist"}},
		{Rule: "path_boundary", Subject: filepath.Join(dir, "a.txt"), Blocked: true, WouldBlockIn: []string{"denylist", "allowlist"}},
		{Rule: "path_boundary", Subject: dir, Blocked: true, WouldBlockIn: []string{"denylist", "allowlist"}},
	}
	rep := BuildReport(recs, Options{Top: 10})

	if rep.Records != 6 {
		t.Errorf("records = %d", rep.Records)
	}
	if rep.Blocked["path_boundary"] != 2 || rep.Blocked["local_binary"] != 1 {
		t.Errorf("blocked = %v", rep.Blocked)
	}
	if rep.WouldBlock["allowlist"] != 3 {
		t.Errorf("would_block = %v", rep.WouldBlock)
	}
	subj := rep.Subjects["command_whitelist"]
	if len(subj) != 1 || subj[0].Subject != "npm" || subj[0].Count != 2 || subj[0].Example != "npm test" {
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
	if len(got) != len(want) {
		t.Errorf("unexpected suggestions: %+v", rep.Suggestions)
	}
	if rep.Suggestions[0].Count < rep.Suggestions[len(rep.Suggestions)-1].Count {
		t.Errorf("suggestions not sorted by count: %+v", rep.Suggestions)
	}
	// The bare-entry caveat rides along with every extra-commands suggestion.
	for _, s := range rep.Suggestions {
		if strings.Contains(s.Command, "extra-commands add") && !strings.Contains(s.Reason, "skips validation") {
			t.Errorf("extra-commands suggestion lacks the caveat: %+v", s)
		}
	}
}

func TestBuildReport_NeverSuggestsDangerousCommands(t *testing.T) {
	var recs []Record
	for _, c := range []string{"sudo", "curl", "ssh", "bash", "chmod", "crontab"} {
		for i := 0; i < 50; i++ { // the agent can make anything the top finding
			recs = append(recs, Record{Rule: "command_whitelist", Subject: c, Fix: "lite-sandbox config extra-commands add " + c, Blocked: true, WouldBlockIn: []string{"allowlist"}})
		}
	}
	recs = append(recs, Record{Rule: "command_whitelist", Subject: "make", Fix: "lite-sandbox config extra-commands add make", Blocked: true, WouldBlockIn: []string{"allowlist"}})
	rep := BuildReport(recs, Options{})
	if len(rep.Suggestions) != 1 || !strings.HasSuffix(rep.Suggestions[0].Command, " make") {
		t.Errorf("only make should be suggested, got %+v", rep.Suggestions)
	}
	// The findings themselves are still reported.
	if len(rep.Subjects["command_whitelist"]) != 7 {
		t.Errorf("subjects = %+v", rep.Subjects["command_whitelist"])
	}
}

func TestBuildReport_ProtectedPathsNotSuggested(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	aws := filepath.Join(home, ".aws")
	ssh := filepath.Join(home, ".ssh")
	recs := []Record{
		{Rule: "path_boundary", Subject: filepath.Join(aws, "credentials"), Blocked: true},
		{Rule: "path_boundary", Subject: filepath.Join(ssh, "id_rsa"), Blocked: true},
		{Rule: "path_boundary", Subject: home, Blocked: true},
		{Rule: "path_boundary", Subject: "/etc/passwd", Blocked: true},
		{Rule: "path_boundary", Subject: "/usr/lib/x.so", Blocked: true},
		{Rule: "path_boundary", Subject: "/", Blocked: true},
		{Rule: "path_boundary", Subject: filepath.Join(home, "other-repo", "x.go"), Blocked: true},
	}
	rep := BuildReport(recs, Options{Protected: []string{home, aws, ssh}})
	if len(rep.Suggestions) != 1 || !strings.Contains(rep.Suggestions[0].Command, filepath.Join(home, "other-repo")) {
		t.Errorf("expected only the other-repo suggestion, got %+v", rep.Suggestions)
	}
	if len(rep.Subjects["path_boundary"]) != 7 {
		t.Errorf("subjects = %+v", rep.Subjects["path_boundary"])
	}
}

func TestIsProtected_SystemRootsButNotHome(t *testing.T) {
	home := "/var/folders/xy/T/home" // a home under a system root, as on macOS runners
	t.Setenv("HOME", home)
	if !isProtected("/var/log/syslog", nil) || !isProtected("/etc/passwd", nil) || !isProtected("/", nil) {
		t.Error("system roots must be protected")
	}
	if isProtected(home+"/repo/x.go", nil) {
		t.Error("a path inside the home directory is never a system path")
	}
	if !isProtected(home, nil) {
		t.Error("the home directory itself is protected")
	}
}

func TestBuildReport_CWDFilter(t *testing.T) {
	recs := []Record{
		{CWD: "/work/a", Rule: "command_whitelist", Subject: "npm", WouldBlockIn: []string{"allowlist"}},
		{CWD: "/work/a/sub", Rule: "command_whitelist", Subject: "npm", WouldBlockIn: []string{"allowlist"}},
		{CWD: "/work/b", Rule: "command_whitelist", Subject: "make", WouldBlockIn: []string{"allowlist"}},
		{CWD: "/work/ab", Rule: "command_whitelist", Subject: "make", WouldBlockIn: []string{"allowlist"}},
	}
	rep := BuildReport(recs, Options{CWD: "/work/a"})
	if rep.Records != 2 || len(rep.Subjects["command_whitelist"]) != 1 || rep.Subjects["command_whitelist"][0].Subject != "npm" {
		t.Errorf("cwd filter: records=%d subjects=%+v", rep.Records, rep.Subjects)
	}
}

func TestParseSince(t *testing.T) {
	if d, err := ParseSince("7d"); err != nil || d != 7*24*time.Hour {
		t.Errorf("7d = %v, %v", d, err)
	}
	if d, err := ParseSince("36h"); err != nil || d != 36*time.Hour {
		t.Errorf("36h = %v, %v", d, err)
	}
	if _, err := ParseSince("soon"); err == nil {
		t.Error("expected error")
	}
}

func TestSanitize(t *testing.T) {
	in := "npm\x1b[2K\rlite-sandbox config extra-commands add sudo\ttail\n"
	out := Sanitize(in)
	if strings.ContainsAny(out, "\x1b\r\t\n") {
		t.Errorf("control characters survived: %q", out)
	}
	if !strings.HasPrefix(out, "npm?") {
		t.Errorf("sanitized = %q", out)
	}
	if Sanitize("plain ./path-ok") != "plain ./path-ok" {
		t.Error("plain text must pass through")
	}
}
