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
