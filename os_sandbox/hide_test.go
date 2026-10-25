package os_sandbox

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestBuildBwrapArgs_HideDirs checks the hidden-directory layout: each hidden
// directory is emptied (a tmpfs) before every bind, so the grants inside it
// are mounted on top, and remounted read-only after every mount, once bwrap
// has created the mount points the binds and masks need in it.
func TestBuildBwrapArgs_HideDirs(t *testing.T) {
	home := "/home/user"
	args := buildBwrapArgs(bwrapPlan{
		self:            "/usr/bin/lite-sandbox",
		workDir:         home + "/proj",
		binds:           []string{home + "/go"},
		roBinds:         []string{home + "/.gitconfig"},
		hideDirs:        []string{home, "/run/user/1000"},
		deniedReadFiles: []string{home + "/.cargo/credentials.toml"},
	})
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--perms 0755 --tmpfs /home/user",
		"--perms 0755 --tmpfs /run/user/1000",
		"--remount-ro /home/user",
		"--remount-ro /run/user/1000",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args missing %q\nargs: %v", want, args)
		}
	}
	hideIdx := bindTargetIndex(t, args, home)
	for _, p := range []string{home + "/proj", home + "/go", home + "/.gitconfig", home + "/.cargo/credentials.toml"} {
		if idx := bindTargetIndex(t, args, p); idx < hideIdx {
			t.Errorf("%s (index %d) must be mounted after the hidden home's tmpfs (index %d)", p, idx, hideIdx)
		}
	}
	remount := slices.Index(args, "--remount-ro")
	last := 0
	for i, a := range args {
		if a == "--bind" || a == "--ro-bind" || a == "--tmpfs" {
			last = i
		}
	}
	if remount < last {
		t.Errorf("--remount-ro (index %d) must follow every mount (last at %d): %v", remount, last, args)
	}
}

// TestBuildBwrapArgs_NoHideDirs pins the layout without hidden directories.
func TestBuildBwrapArgs_NoHideDirs(t *testing.T) {
	args := buildBwrapArgs(bwrapPlan{self: "/usr/bin/lite-sandbox", workDir: "/work"})
	if slices.Contains(args, "--remount-ro") || strings.Contains(strings.Join(args, " "), "--perms 0755") {
		t.Errorf("no hidden-directory mounts expected: %v", args)
	}
}

func TestNewHidePlan(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	proj := filepath.Join(home, "proj")
	other := filepath.Join(root, "other")
	for _, d := range []string{proj, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	p := newHidePlan([]string{home, filepath.Join(root, "missing")}, []string{proj})
	if len(p.dirs) != 1 || p.dirs[0] != home {
		t.Fatalf("dirs = %v, want [%s] (a missing directory is not hidden)", p.dirs, home)
	}
	for path, want := range map[string]bool{
		filepath.Join(home, ".aws"):         true,
		filepath.Join(home, ".ssh/id_rsa"):  true,
		filepath.Join(proj, ".env"):         false,
		proj:                                false,
		filepath.Join(other, "x"):           false,
		filepath.Join(home, "proj2/secret"): true,
	} {
		if got := p.hidden(path); got != want {
			t.Errorf("hidden(%s) = %v, want %v", path, got, want)
		}
	}

	// Exposing the hidden directory itself, or a parent of it, shows all of
	// it: the working directory is $HOME, or a grant on ~.
	for _, exposed := range []string{home, root} {
		if p := newHidePlan([]string{home}, []string{exposed}); len(p.dirs) != 0 {
			t.Errorf("exposing %s: dirs = %v, want none", exposed, p.dirs)
		}
	}

	deny := []DenyPath{{Path: filepath.Join(home, ".aws"), Dir: true}, {Path: filepath.Join(proj, ".env")}}
	if got := p.visibleDeny(deny); len(got) != 1 || got[0].Path != filepath.Join(proj, ".env") {
		t.Errorf("visibleDeny = %v, want only the entry under the exposed project", got)
	}
}

// TestNewHidePlan_Symlink checks that a hidden directory reached through a
// symlink is hidden at its real path, and that exposed paths spelled through
// the link still count as inside it.
func TestNewHidePlan_Symlink(t *testing.T) {
	root := t.TempDir()
	real := filepath.Join(root, "real-home")
	if err := os.MkdirAll(filepath.Join(real, "proj"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	p := newHidePlan([]string{link}, []string{filepath.Join(link, "proj")})
	if len(p.dirs) != 1 || p.dirs[0] != real {
		t.Fatalf("dirs = %v, want [%s]", p.dirs, real)
	}
	if p.hidden(filepath.Join(link, "proj", "x")) {
		t.Error("a path in the exposed project, spelled through the link, should not be hidden")
	}
	if !p.hidden(filepath.Join(link, ".aws")) {
		t.Error("a path in the hidden home, spelled through the link, should be hidden")
	}
}

func TestAncestorsWithin(t *testing.T) {
	got := ancestorsWithin("/Users/me/code/proj", "/Users/me")
	want := []string{"/Users/me", "/Users/me/code"}
	if !slices.Equal(got, want) {
		t.Errorf("ancestorsWithin = %v, want %v", got, want)
	}
	if got := ancestorsWithin("/Users/me", "/Users/me"); got != nil {
		t.Errorf("the directory itself has no ancestors within it, got %v", got)
	}
	if got := ancestorsWithin("/opt/x", "/Users/me"); got != nil {
		t.Errorf("a path outside has none, got %v", got)
	}
}

// TestGenerateSBPLProfile_HideDirs checks the macOS form: reads under the
// hidden directory are denied, the visible paths inside it are allowed back
// with their ancestors' metadata, and the masks and deny lists come after the
// allows (last match wins) so a visible path cannot re-expose them.
func TestGenerateSBPLProfile_HideDirs(t *testing.T) {
	home := "/Users/me"
	profile := generateSBPLProfile(home+"/code/proj", nil, []string{home + "/.colima/docker.sock"}, sbplDenylist{
		deniedReadPaths: []string{home + "/code/proj/.ssh-key"},
		hideDirs:        []string{home},
		visible:         []string{home + "/code/proj", home + "/go", "/usr/local/bin/lite-sandbox"},
	})
	hide := `(deny file-read* (subpath "/Users/me"))`
	allowProj := `(allow file-read* (subpath "/Users/me/code/proj"))`
	for _, want := range []string{
		hide,
		allowProj,
		`(allow file-read* (subpath "/Users/me/go"))`,
		`(allow file-read-metadata (literal "/Users/me"))`,
		`(allow file-read-metadata (literal "/Users/me/code"))`,
	} {
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing %q\n%s", want, profile)
		}
	}
	if strings.Contains(profile, `(subpath "/usr/local/bin/lite-sandbox")`) {
		t.Error("a visible path outside every hidden directory needs no allow rule")
	}
	order := []string{
		hide,
		allowProj,
		`(deny file-read* file-write* (literal "/Users/me/.colima/docker.sock"))`,
		`(deny file-read* (subpath "/Users/me/code/proj/.ssh-key"))`,
	}
	last := -1
	for _, rule := range order {
		idx := strings.Index(profile, rule)
		if idx < 0 {
			t.Fatalf("profile missing %q\n%s", rule, profile)
		}
		if idx < last {
			t.Errorf("%q is out of order\n%s", rule, profile)
		}
		last = idx
	}
	if strings.Contains(profile, "(deny mach-lookup") {
		t.Error("keychain services must stay reachable without denyKeychain")
	}
}

// TestGenerateSBPLProfile_DenyKeychain checks that the keychain daemon's
// lookup is denied after the blanket mach-lookup allow, which would otherwise
// win.
func TestGenerateSBPLProfile_DenyKeychain(t *testing.T) {
	profile := generateSBPLProfile("/work", nil, nil, sbplDenylist{denyKeychain: true})
	allow := strings.Index(profile, "(allow mach-lookup)")
	for _, svc := range KeychainMachServices {
		deny := strings.Index(profile, `(deny mach-lookup (global-name "`+svc+`"))`)
		if deny < 0 {
			t.Fatalf("profile does not deny %s\n%s", svc, profile)
		}
		if deny < allow {
			t.Errorf("deny of %s must follow (allow mach-lookup)\n%s", svc, profile)
		}
	}
}
