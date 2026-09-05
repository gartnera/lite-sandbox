package mockedserver

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sync/errgroup"
)

// e2eEnv gates the suite: the tests download and run third-party agent
// binaries, so they only run when it is set. Without it every test skips and
// `go test ./...` stays offline.
const e2eEnv = "LITE_SANDBOX_E2E"

// bins holds the binaries TestMain provisions. pathDirs are prepended to PATH
// for every subprocess so `lite-sandbox install` autodetection and the agents'
// own PATH lookups (e.g. `crush --version`) find them.
var bins struct {
	sandbox, crush, codex, claude, opencode string
	pathDirs                                []string
}

func TestMain(m *testing.M) {
	if os.Getenv(e2eEnv) != "" {
		if err := provision(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e: provisioning failed: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// requireE2E skips t unless the suite is enabled.
func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv(e2eEnv) == "" {
		t.Skipf("set %s=1 to run the agent end-to-end tests (downloads pinned agent binaries)", e2eEnv)
	}
}

// provision builds lite-sandbox and installs the pinned agents — all as native
// release binaries, so nothing beyond Go is needed on the host. Everything
// lives under e2e/mockedserver/.bin (override with E2E_BIN_DIR): lite-sandbox is rebuilt
// every run; each agent is installed once into its own versioned directory
// (agents/<agent>/<version>), so switching versions — by editing versions.go or
// setting E2E_CRUSH_VERSION / E2E_CODEX_VERSION / E2E_CLAUDE_CODE_VERSION /
// E2E_OPENCODE_VERSION for one run — never re-downloads a version that is
// already there.
func provision() error {
	binDir := os.Getenv("E2E_BIN_DIR")
	if binDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		binDir = filepath.Join(wd, ".bin")
	}
	agentsDir := filepath.Join(binDir, "agents")

	bins.sandbox = filepath.Join(binDir, "lite-sandbox")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return err
	}
	if out, err := exec.Command("go", "build", "-o", bins.sandbox, "../..").CombinedOutput(); err != nil {
		return fmt.Errorf("go build lite-sandbox: %v\n%s", err, out)
	}

	// The three installs are independent downloads; run them concurrently.
	crushVersion := versionFromEnv("E2E_CRUSH_VERSION", CrushVersion)
	codexVersion := versionFromEnv("E2E_CODEX_VERSION", CodexVersion)
	claudeVersion := versionFromEnv("E2E_CLAUDE_CODE_VERSION", ClaudeCodeVersion)
	opencodeVersion := versionFromEnv("E2E_OPENCODE_VERSION", OpencodeVersion)
	crushDir := filepath.Join(agentsDir, "crush", crushVersion)
	codexDir := filepath.Join(agentsDir, "codex", codexVersion)
	claudeDir := filepath.Join(agentsDir, "claude-code", claudeVersion)
	opencodeDir := filepath.Join(agentsDir, "opencode", opencodeVersion)
	var g errgroup.Group
	bins.crush = filepath.Join(crushDir, "crush")
	bins.codex = filepath.Join(codexDir, "codex")
	bins.claude = filepath.Join(claudeDir, "claude")
	bins.opencode = filepath.Join(opencodeDir, "opencode")
	g.Go(func() error {
		return ensureInstalled(bins.crush, "crush "+crushVersion, func() error { return installCrush(crushDir, crushVersion) })
	})
	g.Go(func() error {
		return ensureInstalled(bins.codex, "codex "+codexVersion, func() error { return installCodex(codexDir, codexVersion) })
	})
	g.Go(func() error {
		return ensureInstalled(bins.claude, "claude-code "+claudeVersion, func() error { return installClaudeCode(claudeDir, claudeVersion) })
	})
	g.Go(func() error {
		return ensureInstalled(bins.opencode, "opencode "+opencodeVersion, func() error { return installOpencode(opencodeDir, opencodeVersion) })
	})
	if err := g.Wait(); err != nil {
		return err
	}

	bins.pathDirs = []string{binDir, filepath.Dir(bins.crush), filepath.Dir(bins.codex), filepath.Dir(bins.claude), filepath.Dir(bins.opencode)}
	for _, b := range []string{bins.sandbox, bins.crush, bins.codex, bins.claude, bins.opencode} {
		if _, err := os.Stat(b); err != nil {
			return fmt.Errorf("provisioned binary missing: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "e2e: crush %s, codex %s, claude-code %s, opencode %s\n", crushVersion, codexVersion, claudeVersion, opencodeVersion)
	return nil
}

// versionFromEnv returns the version pinned in versions.go unless the named
// environment variable overrides it for this run.
func versionFromEnv(name, pinned string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return pinned
}

// ensureInstalled runs install to produce binary (into its directory) unless
// that directory already holds both the binary and a .complete marker. The
// marker is written last, so a failed or interrupted install is retried (from
// a clean directory) next time; checking the binary too means a directory laid
// out by an older provisioning scheme (e.g. restored from a CI cache) is
// rebuilt rather than trusted.
func ensureInstalled(binary, what string, install func() error) error {
	dir := filepath.Dir(binary)
	marker := filepath.Join(dir, ".complete")
	if _, err := os.Stat(marker); err == nil {
		if _, err := os.Stat(binary); err == nil {
			return nil
		}
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "e2e: installing %s into %s\n", what, dir)
	if err := install(); err != nil {
		return fmt.Errorf("installing %s: %w", what, err)
	}
	return os.WriteFile(marker, nil, 0644)
}

// githubRelease locates one agent's release asset for this host on GitHub.
type githubRelease struct {
	repo   string // owner/name
	tag    string // release tag, e.g. "v0.92.0" or "rust-v0.153.4"
	asset  string // attached archive file name (.tar.gz or .zip)
	member string // base name of the binary inside the archive
}

// githubAPI is the REST API base; a test points it at a local server.
var githubAPI = "https://api.github.com"

// githubToken returns the token to authenticate GitHub requests with, from
// GITHUB_TOKEN (what GitHub Actions provides) or GH_TOKEN (the gh CLI's).
func githubToken() string {
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GH_TOKEN")
}

// install downloads the asset and writes its member to dest as an executable.
func (r githubRelease) install(dest string) error {
	body, err := r.open()
	if err != nil {
		return err
	}
	defer body.Close()
	switch {
	case strings.HasSuffix(r.asset, ".tar.gz"):
		return extractTarMember(body, r.member, dest)
	case strings.HasSuffix(r.asset, ".zip"):
		return extractZipMember(body, r.member, dest)
	}
	return fmt.Errorf("%s: unsupported archive type", r.asset)
}

// open returns the asset's bytes. With a GitHub token it goes through the
// authenticated REST API — the release's asset list, then the asset itself as
// application/octet-stream — so downloads count against the token's generous
// rate limit rather than the per-IP one shared by every job on a CI runner.
// Without a token, or if the API path fails (a token without access to the
// repository, an API outage), it falls back to the public browser download URL,
// which needs no authentication.
func (r githubRelease) open() (io.ReadCloser, error) {
	if token := githubToken(); token != "" {
		body, err := r.openViaAPI(token)
		if err == nil {
			return body, nil
		}
		fmt.Fprintf(os.Stderr, "e2e: %s: GitHub API download failed (%v); falling back to the public download URL\n", r.asset, err)
	}
	return fetch(fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", r.repo, r.tag, r.asset))
}

// openViaAPI fetches the asset through the REST API with token.
func (r githubRelease) openViaAPI(token string) (io.ReadCloser, error) {
	auth := map[string]string{
		"Authorization":        "Bearer " + token,
		"X-GitHub-Api-Version": "2022-11-28",
		"Accept":               "application/vnd.github+json",
	}
	body, err := fetchWithHeaders(fmt.Sprintf("%s/repos/%s/releases/tags/%s", githubAPI, r.repo, r.tag), auth)
	if err != nil {
		return nil, err
	}
	var release struct {
		Assets []struct {
			Name string `json:"name"`
			URL  string `json:"url"`
		} `json:"assets"`
	}
	err = json.NewDecoder(body).Decode(&release)
	body.Close()
	if err != nil {
		return nil, fmt.Errorf("decoding release %s: %w", r.tag, err)
	}
	for _, a := range release.Assets {
		if a.Name == r.asset {
			// The asset endpoint redirects to a pre-signed storage URL; Go's client
			// drops the Authorization header on that cross-host redirect, as it must.
			auth["Accept"] = "application/octet-stream"
			return fetchWithHeaders(a.URL, auth)
		}
	}
	return nil, fmt.Errorf("release %s has no asset %s", r.tag, r.asset)
}

// installCrush installs the Crush release for version and this OS/arch into dir.
func installCrush(dir, version string) error {
	goos := map[string]string{"linux": "Linux", "darwin": "Darwin"}[runtime.GOOS]
	arch := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[runtime.GOARCH]
	if goos == "" || arch == "" {
		return fmt.Errorf("no crush release for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	return githubRelease{
		repo: "charmbracelet/crush", tag: "v" + version,
		asset:  fmt.Sprintf("crush_%s_%s_%s.tar.gz", version, goos, arch),
		member: "crush",
	}.install(filepath.Join(dir, "crush"))
}

// installCodex installs the Codex release for version and this OS/arch into
// dir: a single native binary named after the Rust target triple.
func installCodex(dir, version string) error {
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	sys := map[string]string{"linux": "unknown-linux-musl", "darwin": "apple-darwin"}[runtime.GOOS]
	if arch == "" || sys == "" {
		return fmt.Errorf("no codex release for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	triple := arch + "-" + sys
	return githubRelease{
		repo: "openai/codex", tag: "rust-v" + version,
		asset:  "codex-" + triple + ".tar.gz",
		member: "codex-" + triple,
	}.install(filepath.Join(dir, "codex"))
}

// installOpencode installs the opencode release for version and this OS/arch
// into dir: a .tar.gz on Linux, a .zip on macOS. This follows
// https://opencode.ai/install, minus its "-baseline" (no-AVX2) variant, which
// no supported CI runner or developer machine needs.
func installOpencode(dir, version string) error {
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" || (runtime.GOOS != "linux" && runtime.GOOS != "darwin") {
		return fmt.Errorf("no opencode release for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	target := runtime.GOOS + "-" + arch
	if runtime.GOOS == "linux" && isMusl() {
		target += "-musl"
	}
	ext := map[string]string{"linux": ".tar.gz", "darwin": ".zip"}[runtime.GOOS]
	return githubRelease{
		repo: "anomalyco/opencode", tag: "v" + version,
		asset:  "opencode-" + target + ext,
		member: "opencode",
	}.install(filepath.Join(dir, "opencode"))
}

// claudeCodeReleases is the download base of Claude Code's native (non-npm)
// distribution — the one https://claude.ai/install.sh uses. Each version
// publishes a manifest.json with a SHA-256 per platform, and the binary at
// <version>/<platform>/claude.
const claudeCodeReleases = "https://downloads.claude.ai/claude-code-releases"

// installClaudeCode downloads the native Claude Code binary for version and
// this OS/arch into dir, verifying it against the release manifest.
func installClaudeCode(dir, version string) error {
	arch := map[string]string{"amd64": "x64", "arm64": "arm64"}[runtime.GOARCH]
	if arch == "" || (runtime.GOOS != "linux" && runtime.GOOS != "darwin") {
		return fmt.Errorf("no claude-code release for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	platform := runtime.GOOS + "-" + arch
	if runtime.GOOS == "linux" && isMusl() {
		platform += "-musl"
	}

	var manifest struct {
		Platforms map[string]struct {
			Checksum string `json:"checksum"`
		} `json:"platforms"`
	}
	body, err := fetch(claudeCodeReleases + "/" + version + "/manifest.json")
	if err != nil {
		return err
	}
	err = json.NewDecoder(body).Decode(&manifest)
	body.Close()
	if err != nil {
		return fmt.Errorf("decoding claude-code manifest: %w", err)
	}
	want := manifest.Platforms[platform].Checksum
	if want == "" {
		return fmt.Errorf("claude-code %s has no build for %s", version, platform)
	}

	body, err = fetch(claudeCodeReleases + "/" + version + "/" + platform + "/claude")
	if err != nil {
		return err
	}
	defer body.Close()
	sum := sha256.New()
	if err := writeExecutable(filepath.Join(dir, "claude"), io.TeeReader(body, sum)); err != nil {
		return err
	}
	if got := hex.EncodeToString(sum.Sum(nil)); got != want {
		return fmt.Errorf("claude-code %s/%s checksum mismatch: got %s, manifest says %s", version, platform, got, want)
	}
	return nil
}

// isMusl reports whether this Linux host uses musl rather than glibc, the way
// Claude Code's installer detects it.
func isMusl() bool {
	for _, lib := range []string{"/lib/libc.musl-x86_64.so.1", "/lib/libc.musl-aarch64.so.1"} {
		if _, err := os.Stat(lib); err == nil {
			return true
		}
	}
	return false
}

// fetch GETs url and returns the body, failing on a non-200 status.
func fetch(url string) (io.ReadCloser, error) { return fetchWithHeaders(url, nil) }

// fetchWithHeaders GETs url with the given request headers and returns the
// body, failing on a non-200 status.
func fetchWithHeaders(url string, headers map[string]string) (io.ReadCloser, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp.Body, nil
}

// extractTarMember reads a .tar.gz stream and writes the regular file whose
// base name is member to dest as an executable.
func extractTarMember(archive io.Reader, member, dest string) error {
	gz, err := gzip.NewReader(archive)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("no %s in archive", member)
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeReg && filepath.Base(hdr.Name) == member {
			return writeExecutable(dest, tr)
		}
	}
}

// extractZipMember reads a .zip stream and writes the file whose base name is
// member to dest as an executable. Zip needs random access, so the archive is
// spooled to a temp file first.
func extractZipMember(archive io.Reader, member, dest string) error {
	tmp, err := os.CreateTemp("", "e2e-*.zip")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if _, err := io.Copy(tmp, archive); err != nil {
		return err
	}
	zr, err := zip.OpenReader(tmp.Name())
	if err != nil {
		return err
	}
	defer zr.Close()
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || filepath.Base(f.Name) != member {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		defer rc.Close()
		return writeExecutable(dest, rc)
	}
	return fmt.Errorf("no %s in archive", member)
}

// writeExecutable writes r to path with mode 0755.
func writeExecutable(path string, r io.Reader) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, r)
	return errors.Join(err, f.Close())
}
