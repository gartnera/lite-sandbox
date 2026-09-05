// Package version reports the build's release version.
//
// Release builds set version, commit, and date through the linker (see
// .goreleaser.yaml). Builds installed with `go install module@version` carry
// the module version in their build info instead, and plain `go build`s of a
// checkout report "dev".
package version

import (
	"fmt"
	"runtime/debug"
	"strings"
)

// Set by the linker at release time:
//
//	-X github.com/gartnera/lite-sandbox/internal/version.version=v1.2.3
var (
	version string
	commit  string
	date    string
)

// Dev is the version reported by a build that carries no version information.
const Dev = "dev"

// Version returns the release version, e.g. "v0.3.0". A `go install
// module@version` build reports its module version (a pseudo-version such as
// "v0.0.0-20260101000000-abcdef123456" when it was not a tag); anything else
// reports Dev.
func Version() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return Dev
}

// Commit returns the short commit hash the binary was built from, or "" when
// unknown.
func Commit() string {
	c := commit
	if c == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" {
					c = s.Value
				}
			}
		}
	}
	if len(c) > 12 {
		c = c[:12]
	}
	return c
}

// Date returns the build (commit) date recorded at release time, or "".
func Date() string {
	return date
}

// String returns a one-line description: "lite-sandbox v0.3.0 (abc123, 2026-01-01)".
func String() string {
	var extra []string
	if c := Commit(); c != "" {
		extra = append(extra, c)
	}
	if d := Date(); d != "" {
		extra = append(extra, d)
	}
	s := "lite-sandbox " + Version()
	if len(extra) > 0 {
		s += fmt.Sprintf(" (%s)", strings.Join(extra, ", "))
	}
	return s
}
