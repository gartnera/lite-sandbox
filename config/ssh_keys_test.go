package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// sshHome creates a home directory with a ~/.ssh holding two private keys, their
// public halves, and the non-key files ssh needs, and points HOME at it.
func sshHome(t *testing.T) (home string, keys []string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(filepath.Join(sshDir, "sockets"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id_ed25519", "id_ed25519.pub", "work_key", "work_key.pub", "known_hosts", "known_hosts.old", "config", "authorized_keys", "authorized_keys2"} {
		if err := os.WriteFile(filepath.Join(sshDir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return home, []string{filepath.Join(sshDir, "id_ed25519"), filepath.Join(sshDir, "work_key")}
}

func TestSSHPrivateKeyEntries(t *testing.T) {
	home, keys := sshHome(t)
	got := SSHPrivateKeyEntries(home)
	var paths []string
	for _, e := range got {
		paths = append(paths, e.Path)
		if !e.AllModes || e.Group != filepath.Join(home, ".ssh") || e.Dir || e.Note == "" {
			t.Errorf("key entry %+v should be an every-mode file entry grouped under ~/.ssh with a note", e)
		}
	}
	slices.Sort(paths)
	if !slices.Equal(paths, keys) {
		t.Errorf("private keys = %v, want %v (non-key files, *.pub and subdirectories must be skipped)", paths, keys)
	}
	if SSHPrivateKeyEntries(t.TempDir()) != nil {
		t.Error("a home without ~/.ssh should yield no entries")
	}
}

// TestDeniedDefaults_SSHKeysEveryMode checks the keys are in the built-in read
// deny list and are the every-mode subset of it.
func TestDeniedDefaults_SSHKeysEveryMode(t *testing.T) {
	_, keys := sshHome(t)
	cfg := &Config{}
	all := cfg.EffectiveDeniedReadPaths()
	always := deniedPathStrings(cfg.AlwaysDeniedReadEntries())
	slices.Sort(always)
	if !slices.Equal(always, keys) {
		t.Errorf("always-denied = %v, want exactly the keys %v", always, keys)
	}
	for _, k := range keys {
		if !slices.Contains(all, k) {
			t.Errorf("denylist read list missing key %s: %v", k, all)
		}
	}
	// The rest of the deny list is denylist-only.
	for _, e := range cfg.AlwaysDeniedReadEntries() {
		if !e.AllModes {
			t.Errorf("%s is not an every-mode entry", e.Path)
		}
	}
}

// TestDeniedDefaults_LiftedByGrant checks the merge: a paths grant on ~/.ssh
// lifts every key (the group), a grant on one key lifts that key only, and the
// lifted entries are reported with the granting path. The write denial on
// ~/.ssh is untouched by a read grant.
func TestDeniedDefaults_LiftedByGrant(t *testing.T) {
	home, keys := sshHome(t)
	sshDir := filepath.Join(home, ".ssh")
	yes := true

	// Whole directory, internal: the spawned ssh reads its keys, the agent's
	// own reads stay refused, ~/.ssh stays write-denied.
	cfg := &Config{Paths: []PathEntry{{Path: "~/.ssh", Read: &yes, Internal: true}}}
	if got := cfg.AlwaysDeniedReadEntries(); len(got) != 0 {
		t.Errorf("a read grant on ~/.ssh should lift every key, still masked: %v", deniedPathStrings(got))
	}
	for _, k := range keys {
		if slices.Contains(cfg.EffectiveDeniedReadPaths(), k) {
			t.Errorf("denylist read list still has lifted key %s", k)
		}
	}
	if !slices.Contains(cfg.EffectiveDeniedWritePaths(), sshDir) {
		t.Error("a read grant must not lift the write denial on ~/.ssh")
	}
	read, write := cfg.LiftedDeniedEntries()
	if len(read) != len(keys) || len(write) != 0 {
		t.Fatalf("lifted read=%d write=%d, want %d/0", len(read), len(write), len(keys))
	}
	for _, d := range read {
		if d.LiftedBy != "~/.ssh" {
			t.Errorf("lifted entry %s should name the grant ~/.ssh, got %q", d.Path, d.LiftedBy)
		}
	}
	if got := cfg.DeniedEntriesLiftedBy(sshDir); len(got) != len(keys) {
		t.Errorf("DeniedEntriesLiftedBy(%s) = %d entries, want %d (paths compare expanded)", sshDir, len(got), len(keys))
	}

	// One key only.
	cfg = &Config{Paths: []PathEntry{{Path: keys[0], Read: &yes, Internal: true}}}
	always := deniedPathStrings(cfg.AlwaysDeniedReadEntries())
	if slices.Contains(always, keys[0]) || !slices.Contains(always, keys[1]) {
		t.Errorf("a grant on one key should lift that key only: %v", always)
	}

	// A write grant lifts the write denial too; a legacy list lifts as well.
	cfg = &Config{WritablePaths: []string{"~/.ssh"}}
	if slices.Contains(cfg.EffectiveDeniedWritePaths(), sshDir) {
		t.Error("a write grant on ~/.ssh should lift its write denial")
	}
	if len(cfg.AlwaysDeniedReadEntries()) != 0 {
		t.Error("a write grant implies read and should lift the key masks")
	}

	// Exact match only: a grant on the parent lifts nothing beneath it.
	cfg = &Config{Paths: []PathEntry{{Path: "~", Write: &yes}}}
	if len(cfg.AlwaysDeniedReadEntries()) != len(keys) {
		t.Error("a grant on ~ must not lift the key masks")
	}
	if !slices.Contains(cfg.EffectiveDeniedWritePaths(), filepath.Join(home, ".bashrc")) {
		t.Error("a grant on ~ must not lift the write denial on ~/.bashrc")
	}
	// The nested-only form is not the directory either.
	cfg = &Config{Paths: []PathEntry{{Path: "~/.ssh/*", Read: &yes}}}
	if len(cfg.AlwaysDeniedReadEntries()) != len(keys) {
		t.Error("~/.ssh/* is not a grant on ~/.ssh and must not lift the key masks")
	}

	// A user denial on a default is not a lift, and a denial the user adds
	// still appends.
	no := false
	cfg = &Config{Paths: []PathEntry{{Path: "~/.ssh", Write: &no}, {Path: "~/secrets", Read: &no}}}
	if len(cfg.AlwaysDeniedReadEntries()) != len(keys) {
		t.Error("a write denial on ~/.ssh must leave the key masks in place")
	}
	if !slices.Contains(cfg.EffectiveDeniedReadPaths(), filepath.Join(home, "secrets")) {
		t.Error("user read denial missing")
	}
}

// TestDeniedDefaults_LiftAnyBuiltin checks the merge is generic: a write grant
// on a built-in write-denied file lifts it, and a read grant on a built-in
// hidden directory lifts that.
func TestDeniedDefaults_LiftAnyBuiltin(t *testing.T) {
	home, _ := sshHome(t)
	yes := true
	cfg := &Config{Paths: []PathEntry{
		{Path: "~/.bashrc", Write: &yes},
		{Path: "~/.gnupg", Read: &yes, Internal: true},
		{Path: "~/.local/bin", Read: &yes}, // read grant: the write denial stays
	}}
	if slices.Contains(cfg.EffectiveDeniedWritePaths(), filepath.Join(home, ".bashrc")) {
		t.Error("write grant on ~/.bashrc should lift its write denial")
	}
	if slices.Contains(cfg.EffectiveDeniedReadPaths(), filepath.Join(home, ".gnupg")) {
		t.Error("read grant on ~/.gnupg should lift its read denial")
	}
	if !slices.Contains(cfg.EffectiveDeniedWritePaths(), filepath.Join(home, ".local", "bin")) {
		t.Error("a read grant must not lift a write denial")
	}
	_, write := cfg.LiftedDeniedEntries()
	if len(write) != 1 || write[0].LiftedBy != "~/.bashrc" {
		t.Errorf("lifted write entries = %+v", write)
	}
}
