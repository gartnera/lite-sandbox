// Package selfupdate replaces the running lite-sandbox binary with a GitHub
// release build.
//
// Releases are produced by GoReleaser (see .goreleaser.yaml): each carries one
// lite-sandbox_<version>_<os>_<arch>.tar.gz per platform, holding the binary,
// and a checksums.txt with the SHA-256 of every archive. The updater downloads
// the archive for this platform, verifies it against checksums.txt, extracts
// the binary, and swaps it into place atomically.
package selfupdate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/gartnera/lite-sandbox/internal/ghrelease"
)

// Repo is the GitHub repository releases are published to.
const Repo = "gartnera/lite-sandbox"

// Binary is the name of the executable inside a release archive.
const Binary = "lite-sandbox"

// ChecksumsFile is the release asset listing the SHA-256 of every archive.
const ChecksumsFile = "checksums.txt"

// Updater resolves and installs releases. The zero value uses the public
// GitHub endpoints and this binary's platform.
type Updater struct {
	// Client fetches releases (a zero ghrelease.Client when nil).
	Client *ghrelease.Client
	// Repo is the "owner/name" to update from (Repo when empty).
	Repo string
	// GOOS and GOARCH select the release archive (runtime values when empty).
	GOOS, GOARCH string
}

func (u *Updater) client() *ghrelease.Client {
	if u.Client != nil {
		return u.Client
	}
	return &ghrelease.Client{}
}

func (u *Updater) repo() string {
	if u.Repo != "" {
		return u.Repo
	}
	return Repo
}

// Resolve returns the release to install: the one tagged tag, or the latest
// release when tag is "". A tag may be given with or without its "v" prefix.
func (u *Updater) Resolve(ctx context.Context, tag string) (*ghrelease.Release, error) {
	if tag == "" {
		rel, err := u.client().Latest(ctx, u.repo())
		if ghrelease.IsNotFound(err) {
			return nil, fmt.Errorf("%s has no published release yet", u.repo())
		}
		if err != nil {
			return nil, fmt.Errorf("looking up the latest release of %s: %w", u.repo(), err)
		}
		return rel, nil
	}
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	rel, err := u.client().ByTag(ctx, u.repo(), tag)
	if ghrelease.IsNotFound(err) {
		return nil, fmt.Errorf("%s has no release %s", u.repo(), tag)
	}
	if err != nil {
		return nil, fmt.Errorf("looking up release %s of %s: %w", tag, u.repo(), err)
	}
	return rel, nil
}

// AssetName returns the release archive for tag on goos/goarch, following the
// archive name_template in .goreleaser.yaml.
func AssetName(tag, goos, goarch string) string {
	return fmt.Sprintf("%s_%s_%s_%s.tar.gz", Binary, strings.TrimPrefix(tag, "v"), goos, goarch)
}

// Install downloads rel's archive for this platform, verifies its checksum,
// and replaces the executable at dest with the binary inside it. dest is
// replaced atomically (a temp file in the same directory is renamed over it),
// so a running process keeps its old image and the next start picks up the new
// one; on failure dest is left untouched.
func (u *Updater) Install(ctx context.Context, rel *ghrelease.Release, dest string) error {
	goos, goarch := u.GOOS, u.GOARCH
	if goos == "" {
		goos = runtimeGOOS
	}
	if goarch == "" {
		goarch = runtimeGOARCH
	}
	asset := AssetName(rel.Tag, goos, goarch)
	if rel.Asset(asset) == nil {
		return fmt.Errorf("release %s has no build for %s/%s (no asset %s)", rel.Tag, goos, goarch, asset)
	}

	sums, err := u.checksums(ctx, rel)
	if err != nil {
		return err
	}
	want, ok := sums[asset]
	if !ok {
		return fmt.Errorf("release %s: %s does not list %s", rel.Tag, ChecksumsFile, asset)
	}

	body, err := u.client().OpenAsset(ctx, rel, asset)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", asset, err)
	}
	defer body.Close()
	// The archive is small (a few MB); buffer it so the checksum is verified
	// before anything is extracted.
	var archive bytes.Buffer
	sum := sha256.New()
	if _, err := io.Copy(io.MultiWriter(&archive, sum), body); err != nil {
		return fmt.Errorf("downloading %s: %w", asset, err)
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != want {
		return fmt.Errorf("%s: checksum mismatch: got %s, %s says %s", asset, got, ChecksumsFile, want)
	}

	return replaceExecutable(dest, func(w io.Writer) error {
		return ghrelease.ExtractMember(&archive, asset, Binary, w)
	})
}

// checksums downloads and parses rel's checksums file.
func (u *Updater) checksums(ctx context.Context, rel *ghrelease.Release) (map[string]string, error) {
	body, err := u.client().OpenAsset(ctx, rel, ChecksumsFile)
	if err != nil {
		return nil, fmt.Errorf("downloading %s: %w", ChecksumsFile, err)
	}
	defer body.Close()
	sums, err := ParseChecksums(body)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", ChecksumsFile, err)
	}
	return sums, nil
}

// ParseChecksums parses a sha256sum-style listing ("<hex>  <file>" per line)
// into a file → hex digest map.
func ParseChecksums(r io.Reader) (map[string]string, error) {
	sums := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != sha256.Size*2 {
			return nil, fmt.Errorf("malformed line %q", line)
		}
		sums[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
	}
	return sums, sc.Err()
}

// replaceExecutable writes the output of write to a temp file next to dest,
// gives it dest's mode (0755 if dest does not exist or is not executable), and
// renames it over dest.
func replaceExecutable(dest string, write func(io.Writer) error) error {
	mode := os.FileMode(0755)
	if fi, err := os.Stat(dest); err == nil && fi.Mode().Perm()&0111 != 0 {
		mode = fi.Mode().Perm()
	}
	dir := filepath.Dir(dest)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(dest)+".update-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	tmpName := tmp.Name()
	cleanup := func() { os.Remove(tmpName) }
	if err := write(tmp); err != nil {
		tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Chmod(tmpName, mode); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		cleanup()
		return fmt.Errorf("replacing %s: %w", dest, err)
	}
	return nil
}

// ExecutablePath returns the path of the running binary with symlinks
// resolved, so the file that is actually executed is the one replaced.
func ExecutablePath() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

var releaseTagRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)$`)

// IsReleaseVersion reports whether v is a plain release version (vX.Y.Z), as
// opposed to "dev", a pseudo-version, or a pre-release.
func IsReleaseVersion(v string) bool {
	return releaseTagRe.MatchString(v)
}

// CompareVersions orders two release versions (vX.Y.Z, "v" optional): -1 when
// a < b, 0 when equal, 1 when a > b. ok is false when either is not a release
// version, in which case no order is defined.
func CompareVersions(a, b string) (cmp int, ok bool) {
	ma, mb := releaseTagRe.FindStringSubmatch(a), releaseTagRe.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return 0, false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}
