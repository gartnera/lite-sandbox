package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "audit.jsonl")
	l := New(path, 0)
	if err := l.Write(Record{Mode: "denylist", Source: "bash", Layer: "static", Rule: "command_whitelist", Message: "command \"npm\" is not allowed", Subject: "npm", WouldBlockIn: []string{"allowlist"}}); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Record{Mode: "denylist", Source: "bash", Layer: "runtime", Rule: "path_boundary", Blocked: true, WouldBlockIn: []string{"denylist", "allowlist"}}); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("log perms = %o, want 0600", fi.Mode().Perm())
	}

	recs, err := Read(path, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2", len(recs))
	}
	if recs[0].Rule != "command_whitelist" || recs[0].Blocked || recs[0].Time.IsZero() {
		t.Errorf("first record = %+v", recs[0])
	}
	if !recs[1].Blocked {
		t.Errorf("second record should be blocked: %+v", recs[1])
	}

	// since filter
	future := time.Now().Add(time.Hour)
	recs, err = Read(path, future)
	if err != nil || len(recs) != 0 {
		t.Errorf("since-future read = %d records, %v", len(recs), err)
	}
}

func TestRead_MissingAndMalformed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	recs, err := Read(path, time.Time{})
	if err != nil || recs != nil {
		t.Fatalf("missing file: recs=%v err=%v", recs, err)
	}
	if err := os.WriteFile(path, []byte("not json\n{\"rule\":\"x\",\"would_block_in\":[]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, err = Read(path, time.Time{})
	if err != nil || len(recs) != 1 || recs[0].Rule != "x" {
		t.Fatalf("malformed skip: recs=%v err=%v", recs, err)
	}
}

func TestTrim(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l := New(path, 2000)
	for i := 0; i < 50; i++ {
		if err := l.Write(Record{Mode: "open", Rule: "r", Message: strings.Repeat("x", 100)}); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Each record is ~200 bytes; the cap is 2000, so the file must have been
	// trimmed and stay within roughly the cap plus one record.
	if fi.Size() > 2500 {
		t.Errorf("log not trimmed: %d bytes", fi.Size())
	}
	recs, err := Read(path, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 || len(recs) >= 50 {
		t.Errorf("after trim got %d records", len(recs))
	}
}

func TestClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := Clear(path); err != nil {
		t.Fatalf("clear missing: %v", err)
	}
	if err := New(path, 0).Write(Record{Rule: "r"}); err != nil {
		t.Fatal(err)
	}
	if err := Clear(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file should be gone, stat err=%v", err)
	}
}

func TestDefaultPath(t *testing.T) {
	t.Setenv("LITE_SANDBOX_AUDIT_LOG", "/x/audit.jsonl")
	p, err := DefaultPath()
	if err != nil || p != "/x/audit.jsonl" {
		t.Fatalf("env override: %q %v", p, err)
	}
	t.Setenv("LITE_SANDBOX_AUDIT_LOG", "")
	p, err = DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(p) != "audit.jsonl" || filepath.Base(filepath.Dir(p)) != "lite-sandbox" {
		t.Errorf("default path = %q", p)
	}
}
