package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// scriptedEditor returns an editor func that replaces the file with each of
// writes in turn, recording what it was handed each time.
func scriptedEditor(t *testing.T, writes ...string) (func(string) error, *[]string) {
	t.Helper()
	var seen []string
	return func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		seen = append(seen, string(data))
		if len(seen) > len(writes) {
			t.Fatalf("editor opened %d times, want %d", len(seen), len(writes))
		}
		return os.WriteFile(path, []byte(writes[len(seen)-1]), 0o600)
	}, &seen
}

func TestConfigEdit_SavesValidEditVerbatim(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	if err := os.WriteFile(p, []byte("mode: allowlist\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	edited := "# keep this comment\nmode: denylist\nprofiles:\n  - go\n"
	editor, seen := scriptedEditor(t, edited)
	var out, errOut bytes.Buffer
	if err := editConfig(strings.NewReader(""), &out, &errOut, editor); err != nil {
		t.Fatalf("edit: %v (stderr %q)", err, errOut.String())
	}
	if (*seen)[0] != "mode: allowlist\n" {
		t.Errorf("editor was handed %q, want the config file", (*seen)[0])
	}
	got, _ := os.ReadFile(p)
	if string(got) != edited {
		t.Errorf("config = %q, want the edit verbatim", got)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.EffectiveMode() != config.ModeDenylist {
		t.Errorf("mode = %q", cfg.EffectiveMode())
	}
}

func TestConfigEdit_RejectsInvalidEdit(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	orig := "mode: allowlist\n"
	if err := os.WriteFile(p, []byte(orig), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]string{
		"syntax":      "mode: [\n",
		"bad mode":    "mode: strict\n",
		"unknown key": "os_sandbx: true\n",
		"profile":     "profiles:\n  - gopher\n",
	} {
		t.Run(name, func(t *testing.T) {
			editor, _ := scriptedEditor(t, bad)
			var out, errOut bytes.Buffer
			err := editConfig(strings.NewReader("n\n"), &out, &errOut, editor)
			if err == nil || !strings.Contains(err.Error(), "not saved") {
				t.Fatalf("edit = %v, want a rejection", err)
			}
			if !strings.Contains(errOut.String(), "Invalid config") {
				t.Errorf("stderr = %q", errOut.String())
			}
			if got, _ := os.ReadFile(p); string(got) != orig {
				t.Errorf("config = %q, want it untouched", got)
			}
			// The rejected edit is kept for recovery.
			_, kept, ok := strings.Cut(err.Error(), "your edit is in ")
			if !ok {
				t.Fatalf("error does not name the kept edit: %v", err)
			}
			kept = strings.TrimSuffix(kept, ")")
			defer os.Remove(kept)
			if data, _ := os.ReadFile(kept); string(data) != bad {
				t.Errorf("kept edit = %q, want %q", data, bad)
			}
		})
	}
}

func TestConfigEdit_ReopensWithErrorThenSaves(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	editor, seen := scriptedEditor(t, "mode: strict\n", "mode: open\n")
	var out, errOut bytes.Buffer
	// An empty answer takes the default, which is to edit again.
	if err := editConfig(strings.NewReader("\n"), &out, &errOut, editor); err != nil {
		t.Fatalf("edit: %v", err)
	}
	if len(*seen) != 2 {
		t.Fatalf("editor opened %d times, want 2", len(*seen))
	}
	if !strings.HasPrefix((*seen)[0], "# lite-sandbox configuration") {
		t.Errorf("a missing config should open the template, got %q", (*seen)[0])
	}
	second := (*seen)[1]
	if !strings.HasPrefix(second, editErrorPrefix) || !strings.Contains(second, "strict") || !strings.HasSuffix(second, "mode: strict\n") {
		t.Errorf("reopened file should carry the error above the rejected edit, got %q", second)
	}
	if got, _ := os.ReadFile(p); string(got) != "mode: open\n" {
		t.Errorf("config = %q, want the error header stripped", got)
	}
}

func TestConfigEdit_NoChanges(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	editor, _ := scriptedEditor(t, editNewConfigTemplate)
	var out bytes.Buffer
	if err := editConfig(strings.NewReader(""), &out, &out, editor); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No changes") {
		t.Errorf("out = %q", out.String())
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("saving the template unchanged should create no config (stat: %v)", err)
	}
}

func TestConfigEdit_RefusesToClobberConcurrentChange(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITE_SANDBOX_CONFIG", p)
	if err := os.WriteFile(p, []byte("mode: allowlist\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	editor := func(path string) error {
		if err := os.WriteFile(p, []byte("audit: true\n"), 0o644); err != nil {
			return err
		}
		return os.WriteFile(path, []byte("mode: open\n"), 0o600)
	}
	var out bytes.Buffer
	err := editConfig(strings.NewReader(""), &out, &out, editor)
	if err == nil || !strings.Contains(err.Error(), "changed while you were editing") {
		t.Fatalf("edit = %v, want a refusal", err)
	}
	if got, _ := os.ReadFile(p); string(got) != "audit: true\n" {
		t.Errorf("config = %q, want the concurrent change kept", got)
	}
}

func TestRunEditorUsesEditorEnv(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "ed.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n[ \"$1\" = --flag ] || exit 3\necho \"mode: open\" > \"$2\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", script+" --flag")
	target := filepath.Join(dir, "c.yaml")
	if err := runEditor(target); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(target); string(got) != "mode: open\n" {
		t.Errorf("file = %q", got)
	}
}

func TestConfigEditRejectsDir(t *testing.T) {
	configDir = t.TempDir()
	t.Cleanup(func() { configDir = "" })
	if err := configEditCmd.RunE(configEditCmd, nil); err == nil || !strings.Contains(err.Error(), "--dir") {
		t.Errorf("edit --dir = %v, want it rejected", err)
	}
}
