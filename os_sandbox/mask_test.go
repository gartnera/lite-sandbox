package os_sandbox

import (
	"strings"
	"testing"
)

// TestGenerateSBPLProfile_MasksPaths verifies that mask paths (e.g. the real
// Docker daemon socket) produce deny rules in the macOS sandbox profile, so a
// sandboxed command cannot reach the underlying socket directly.
func TestGenerateSBPLProfile_MasksPaths(t *testing.T) {
	profile := generateSBPLProfile("/tmp/work", nil, false, []string{"/var/run/docker.sock"})

	for _, want := range []string{
		`(deny file-read* file-write* (literal "/var/run/docker.sock"))`,
		`(deny network-outbound (literal "/var/run/docker.sock"))`,
	} {
		if !strings.Contains(profile, want) {
			t.Errorf("SBPL profile missing mask rule %q\nprofile:\n%s", want, profile)
		}
	}

	// No mask paths → no docker.sock deny rules.
	plain := generateSBPLProfile("/tmp/work", nil, false, nil)
	if strings.Contains(plain, "docker.sock") {
		t.Errorf("unexpected docker.sock rule with no mask paths:\n%s", plain)
	}
}

// TestGenerateSBPLProfile_ConfinesWrites verifies the profile denies writes
// outside the allowed subpaths. The leading "(allow default)" would otherwise
// permit writes everywhere (e.g. the user's home directory); a catch-all
// "(deny file-write* (subpath "/"))" placed before the specific write allows is
// what actually confines writes to the working directory and temp dirs.
func TestGenerateSBPLProfile_ConfinesWrites(t *testing.T) {
	profile := generateSBPLProfile("/tmp/work", nil, false, nil)

	deny := `(deny file-write* (subpath "/"))`
	if !strings.Contains(profile, deny) {
		t.Fatalf("SBPL profile missing write-confinement rule %q\nprofile:\n%s", deny, profile)
	}

	// The catch-all deny must precede the working-directory allow, otherwise
	// (last matching rule wins) it would clobber the allow and make workDir
	// unwritable.
	allow := `(allow file-write* (subpath "/tmp/work"))`
	denyIdx := strings.Index(profile, deny)
	allowIdx := strings.Index(profile, allow)
	if allowIdx < 0 {
		t.Fatalf("SBPL profile missing workDir write allow %q\nprofile:\n%s", allow, profile)
	}
	if denyIdx > allowIdx {
		t.Errorf("write-confinement deny must come before workDir allow (deny at %d, allow at %d)\nprofile:\n%s", denyIdx, allowIdx, profile)
	}
}
