package selfupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/internal/ghrelease"
)

func tarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// fakeRelease serves a GoReleaser-shaped release: the platform archive plus a
// checksums.txt. checksum lets a test corrupt the listed digest.
func fakeRelease(t *testing.T, tag string, archive []byte, checksum string) (*httptest.Server, *Updater) {
	t.Helper()
	var mux http.ServeMux
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	asset := AssetName(tag, "linux", "amd64")
	if checksum == "" {
		sum := sha256.Sum256(archive)
		checksum = hex.EncodeToString(sum[:])
	}
	sums := fmt.Sprintf("%s  lite-sandbox_%s_darwin_arm64.tar.gz\n%s  %s\n", strings.Repeat("0", 64), strings.TrimPrefix(tag, "v"), checksum, asset)
	release := map[string]any{"tag_name": tag, "assets": []any{
		map[string]any{"name": ChecksumsFile, "browser_download_url": srv.URL + "/dl/" + ChecksumsFile},
		map[string]any{"name": asset, "browser_download_url": srv.URL + "/dl/" + asset},
	}}
	mux.HandleFunc("/repos/acme/ls/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(release)
	})
	mux.HandleFunc("/repos/acme/ls/releases/tags/"+tag, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(release)
	})
	mux.HandleFunc("/dl/"+ChecksumsFile, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(sums)) })
	mux.HandleFunc("/dl/"+asset, func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(archive) })

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	u := &Updater{Client: &ghrelease.Client{APIBase: srv.URL}, Repo: "acme/ls", GOOS: "linux", GOARCH: "amd64"}
	return srv, u
}

func TestInstall(t *testing.T) {
	archive := tarGz(t, "lite-sandbox", []byte("new binary"))
	_, u := fakeRelease(t, "v1.2.3", archive, "")

	dest := filepath.Join(t.TempDir(), "lite-sandbox")
	if err := os.WriteFile(dest, []byte("old binary"), 0700); err != nil {
		t.Fatal(err)
	}
	rel, err := u.Resolve(context.Background(), "")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if rel.Tag != "v1.2.3" {
		t.Errorf("latest tag = %q", rel.Tag)
	}
	if err := u.Install(context.Background(), rel, dest); err != nil {
		t.Fatalf("Install: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "new binary" {
		t.Errorf("installed content = %q", got)
	}
	if fi, _ := os.Stat(dest); fi.Mode().Perm() != 0700 {
		t.Errorf("mode = %v, want the old binary's 0700 preserved", fi.Mode().Perm())
	}
	entries, _ := os.ReadDir(filepath.Dir(dest))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestInstallChecksumMismatch(t *testing.T) {
	archive := tarGz(t, "lite-sandbox", []byte("new binary"))
	_, u := fakeRelease(t, "v1.2.3", archive, strings.Repeat("ab", 32))

	dest := filepath.Join(t.TempDir(), "lite-sandbox")
	if err := os.WriteFile(dest, []byte("old binary"), 0755); err != nil {
		t.Fatal(err)
	}
	rel, err := u.Resolve(context.Background(), "1.2.3") // "v" prefix is optional
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	err = u.Install(context.Background(), rel, dest)
	if err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("expected a checksum mismatch, got %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "old binary" {
		t.Errorf("dest was modified on failure: %q", got)
	}
}

func TestInstallNoBuildForPlatform(t *testing.T) {
	_, u := fakeRelease(t, "v1.2.3", tarGz(t, "lite-sandbox", nil), "")
	u.GOOS, u.GOARCH = "windows", "amd64"
	rel, err := u.Resolve(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	err = u.Install(context.Background(), rel, filepath.Join(t.TempDir(), "x"))
	if err == nil || !strings.Contains(err.Error(), "no build for windows/amd64") {
		t.Fatalf("expected a no-build error, got %v", err)
	}
}

func TestInstallMissingBinaryInArchive(t *testing.T) {
	_, u := fakeRelease(t, "v1.2.3", tarGz(t, "README.md", []byte("hi")), "")
	rel, err := u.Resolve(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "lite-sandbox")
	if err := u.Install(context.Background(), rel, dest); err == nil {
		t.Fatal("expected an error for an archive without the binary")
	}
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Errorf("dest should not exist after a failed install: %v", err)
	}
}

func TestAssetName(t *testing.T) {
	if got := AssetName("v0.4.1", "darwin", "arm64"); got != "lite-sandbox_0.4.1_darwin_arm64.tar.gz" {
		t.Errorf("AssetName = %q", got)
	}
}

func TestParseChecksums(t *testing.T) {
	sums, err := ParseChecksums(strings.NewReader(strings.Repeat("a", 64) + "  one.tar.gz\n\n" + strings.Repeat("B", 64) + " *two.tar.gz\n"))
	if err != nil {
		t.Fatal(err)
	}
	if sums["one.tar.gz"] != strings.Repeat("a", 64) || sums["two.tar.gz"] != strings.Repeat("b", 64) {
		t.Errorf("sums = %v", sums)
	}
	if _, err := ParseChecksums(strings.NewReader("garbage\n")); err == nil {
		t.Error("expected an error for a malformed line")
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		cmp  int
		ok   bool
	}{
		{"v1.2.3", "v1.2.3", 0, true},
		{"1.2.3", "v1.2.3", 0, true},
		{"v1.2.3", "v1.10.0", -1, true},
		{"v2.0.0", "v1.99.99", 1, true},
		{"dev", "v1.0.0", 0, false},
		{"v0.0.0-20260101000000-abcdef123456", "v1.0.0", 0, false},
		{"v1.0.0-rc1", "v1.0.0", 0, false},
	}
	for _, tt := range tests {
		cmp, ok := CompareVersions(tt.a, tt.b)
		if cmp != tt.cmp || ok != tt.ok {
			t.Errorf("CompareVersions(%q, %q) = %d, %v; want %d, %v", tt.a, tt.b, cmp, ok, tt.cmp, tt.ok)
		}
	}
	if IsReleaseVersion("dev") || !IsReleaseVersion("v0.1.0") {
		t.Error("IsReleaseVersion misclassified")
	}
}

func TestResolveNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	u := &Updater{Client: &ghrelease.Client{APIBase: srv.URL}, Repo: "acme/ls"}
	if _, err := u.Resolve(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "no published release yet") {
		t.Errorf("latest: got %v", err)
	}
	if _, err := u.Resolve(context.Background(), "v9.9.9"); err == nil || !strings.Contains(err.Error(), "no release v9.9.9") {
		t.Errorf("by tag: got %v", err)
	}
}
