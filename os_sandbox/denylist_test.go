package os_sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBuildBwrapArgs_DenylistPosture checks the denylist-mode layout: the home
// directory is bound writable, write-denied paths are read-only over
// themselves, read-denied directories are mode-000 tmpfs and read-denied files
// are bound to the mask file — and every mask comes AFTER the home bind, since
// the last overlapping mount wins.
func TestBuildBwrapArgs_DenylistPosture(t *testing.T) {
	home := "/home/user"
	args := buildBwrapArgs(bwrapPlan{
		self:             "/usr/bin/lite-sandbox",
		workDir:          home + "/proj",
		homeDir:          home,
		sshKeyPaths:      []string{home + "/.ssh/id_rsa"},
		deniedReadDirs:   []string{home + "/.aws", home + "/.gnupg"},
		deniedReadFiles:  []string{home + "/.netrc", home + "/.claude.json"},
		deniedWritePaths: []string{home + "/.bashrc", home + "/.ssh"},
		maskFile:         "/cache/lite-sandbox/mask-empty",
	})
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"--bind /home/user /home/user",
		"--ro-bind /home/user/.bashrc /home/user/.bashrc",
		"--ro-bind /home/user/.ssh /home/user/.ssh",
		"--ro-bind /cache/lite-sandbox/mask-empty /home/user/.ssh/id_rsa",
		"--perms 000 --tmpfs /home/user/.aws",
		"--perms 000 --tmpfs /home/user/.gnupg",
		"--ro-bind /cache/lite-sandbox/mask-empty /home/user/.netrc",
		"--ro-bind /cache/lite-sandbox/mask-empty /home/user/.claude.json",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q\nargs: %v", want, args)
		}
	}

	homeIdx := bindTargetIndex(t, args, home)
	workIdx := bindTargetIndex(t, args, home+"/proj")
	if homeIdx < 0 || workIdx < 0 || homeIdx > workIdx {
		t.Errorf("home bind (%d) must precede the workDir bind (%d)", homeIdx, workIdx)
	}
	for _, masked := range []string{home + "/.ssh/id_rsa", home + "/.aws", home + "/.gnupg", home + "/.netrc", home + "/.claude.json", home + "/.bashrc", home + "/.ssh"} {
		idx := bindTargetIndex(t, args, masked)
		if idx < 0 {
			t.Fatalf("%s not found in args: %v", masked, args)
		}
		if idx < homeIdx {
			t.Errorf("%s (index %d) must come after the writable home bind (index %d)", masked, idx, homeIdx)
		}
	}
	// The key inside ~/.ssh must be masked after ~/.ssh is made read-only, or
	// the read-only bind would cover the mask and leave the key readable.
	if bindTargetIndex(t, args, home+"/.ssh/id_rsa") < bindTargetIndex(t, args, home+"/.ssh") {
		t.Error("read-denied key must be masked after the write-denied ~/.ssh bind")
	}
}

// TestBuildBwrapArgs_AllowlistUnchanged checks that without denylist fields the
// layout has no home bind and the SSH mask falls back to /dev/null when no
// mask file is given.
func TestBuildBwrapArgs_AllowlistUnchanged(t *testing.T) {
	args := buildBwrapArgs(bwrapPlan{self: "/usr/bin/lite-sandbox", workDir: "/work", sshKeyPaths: []string{"/home/user/.ssh/id_rsa"}})
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--bind /home/user /home/user") {
		t.Errorf("no home bind expected in allowlist layout: %v", args)
	}
	if !strings.Contains(joined, "--ro-bind /dev/null /home/user/.ssh/id_rsa") {
		t.Errorf("ssh key should be masked with /dev/null when no mask file: %v", args)
	}
	if strings.Contains(joined, "--perms") {
		t.Errorf("no --perms expected without read-denied dirs: %v", args)
	}
}

func TestMaskSourceFile(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	p := maskSourceFile()
	if p == "/dev/null" {
		t.Fatal("expected a mask file to be created")
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() != 0 || fi.Mode().Perm() != 0 {
		t.Errorf("mask file size=%d perm=%o, want empty and 000", fi.Size(), fi.Mode().Perm())
	}
	// Idempotent.
	if again := maskSourceFile(); again != p {
		t.Errorf("second call returned %q, want %q", again, p)
	}
}

// TestGenerateSBPLProfile_Denylist checks the macOS equivalent: home writable
// after the catch-all write deny, write-denied paths denied after the home
// allow (last rule wins), and read-denied paths denied outright.
func TestGenerateSBPLProfile_Denylist(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	tmp := t.TempDir()
	denyDir := filepath.Join(tmp, "secrets")
	denyFile := filepath.Join(tmp, "rc")
	if err := os.Mkdir(denyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denyFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	profile := generateSBPLProfile("/tmp/work", nil, credentialMasks{}, nil, sbplDenylist{
		homeWritable:     true,
		deniedReadPaths:  []string{denyDir},
		deniedWritePaths: []string{denyFile},
	})

	homeAllow := `(allow file-write* (subpath "` + home + `"))`
	catchAll := `(deny file-write* (subpath "/"))`
	fileDeny := `(deny file-write* (literal "` + denyFile + `"))`
	dirDeny := `(deny file-read* (subpath "` + denyDir + `"))`
	// A read-denied path must also be unwritable, and that deny must follow
	// the home allow, or a command could plant a credential_process in
	// ~/.aws/config for the host user to run later.
	dirWriteDeny := `(deny file-write* (subpath "` + denyDir + `"))`
	for _, want := range []string{homeAllow, catchAll, fileDeny, dirDeny, dirWriteDeny} {
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing %q\n%s", want, profile)
		}
	}
	if strings.Index(profile, homeAllow) > strings.Index(profile, dirWriteDeny) {
		t.Error("read-denied write deny must follow the home allow so it wins")
	}
	if strings.Index(profile, catchAll) > strings.Index(profile, homeAllow) {
		t.Error("home allow must follow the catch-all write deny")
	}
	if strings.Index(profile, homeAllow) > strings.Index(profile, fileDeny) {
		t.Error("write-denied path must follow the home allow so it wins")
	}

	// Without the denylist fields none of this appears.
	plain := generateSBPLProfile("/tmp/work", nil, credentialMasks{}, nil, sbplDenylist{})
	if strings.Contains(plain, homeAllow) {
		t.Errorf("allowlist profile must not make home writable:\n%s", plain)
	}
}

// TestGenerateSBPLProfile_MaskPathsUnwritableWithHome checks that broker
// socket masks under $HOME stay unwritable when the home directory is bound
// writable (Docker Desktop / Colima sockets live under ~).
func TestGenerateSBPLProfile_MaskPathsUnwritableWithHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory")
	}
	sock := filepath.Join(home, ".docker", "run", "docker.sock")
	profile := generateSBPLProfile("/tmp/work", nil, credentialMasks{}, []string{sock}, sbplDenylist{homeWritable: true})
	homeAllow := `(allow file-write* (subpath "` + home + `"))`
	sockDeny := `(deny file-write* (literal "` + sock + `"))`
	if strings.LastIndex(profile, sockDeny) < strings.Index(profile, homeAllow) {
		t.Errorf("socket write deny must follow the home allow\n%s", profile)
	}
}

// TestPrepareDenyPaths checks the missing-path policy: missing directories are
// created so they can be masked, missing files are reported and skipped, and
// existing entries are classified by what is actually on disk.
func TestPrepareDenyPaths(t *testing.T) {
	tmp := t.TempDir()
	existingDir := filepath.Join(tmp, "d")
	existingFile := filepath.Join(tmp, "f")
	missingDir := filepath.Join(tmp, "nested", "newdir")
	missingFile := filepath.Join(tmp, ".zshrc")
	if err := os.Mkdir(existingDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existingFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirs, files, missing := prepareDenyPaths([]DenyPath{
		{Path: existingDir, Dir: true},
		{Path: existingFile},
		{Path: missingDir, Dir: true},
		{Path: missingFile},
		{Path: existingFile, Dir: true}, // wrong kind hint: disk wins
	})
	if len(dirs) != 2 || dirs[0] != existingDir || dirs[1] != missingDir {
		t.Errorf("dirs = %v", dirs)
	}
	if fi, err := os.Stat(missingDir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("missing dir should be created 0700: %v %v", fi, err)
	}
	if len(files) != 2 || files[0] != existingFile || files[1] != existingFile {
		t.Errorf("files = %v", files)
	}
	if len(missing) != 1 || missing[0] != missingFile {
		t.Errorf("missing = %v", missing)
	}
	if _, err := os.Stat(missingFile); !os.IsNotExist(err) {
		t.Error("a missing file entry must never be created on the host")
	}
	if got := MissingDenyFiles([]DenyPath{{Path: missingFile}, {Path: existingFile}, {Path: missingDir, Dir: true}}); len(got) != 1 || got[0] != missingFile {
		t.Errorf("MissingDenyFiles = %v", got)
	}
}
