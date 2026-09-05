package mockedserver

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// These tests cover the provisioning plumbing without touching the network,
// so they run in the offline `go test ./...` too.

func tarGz(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "dir/" + name, Mode: 0755, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
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

func zipArchive(t *testing.T, name string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestGitHubReleaseViaAPI checks the authenticated path: the release is looked
// up by tag through the API with the token, the asset is fetched through its
// API URL as an octet stream, and the archive member lands as an executable.
func TestGitHubReleaseViaAPI(t *testing.T) {
	archive := tarGz(t, "tool", []byte("#!/bin/sh\necho tool\n"))
	var mux http.ServeMux
	srv := httptest.NewServer(&mux)
	defer srv.Close()
	var authSeen []string
	mux.HandleFunc("/repos/acme/tool/releases/tags/v1.2.3", func(w http.ResponseWriter, r *http.Request) {
		authSeen = append(authSeen, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"assets": []any{
			map[string]any{"name": "other.zip", "url": srv.URL + "/assets/1"},
			map[string]any{"name": "tool-linux.tar.gz", "url": srv.URL + "/assets/2"},
		}})
	})
	mux.HandleFunc("/assets/2", func(w http.ResponseWriter, r *http.Request) {
		authSeen = append(authSeen, r.Header.Get("Authorization"))
		if r.Header.Get("Accept") != "application/octet-stream" {
			http.Error(w, "expected octet-stream", http.StatusNotAcceptable)
			return
		}
		_, _ = w.Write(archive)
	})
	githubAPI = srv.URL
	t.Cleanup(func() { githubAPI = "https://api.github.com" })
	t.Setenv("GITHUB_TOKEN", "secret-token")

	dest := filepath.Join(t.TempDir(), "tool")
	rel := githubRelease{repo: "acme/tool", tag: "v1.2.3", asset: "tool-linux.tar.gz", member: "tool"}
	if err := rel.install(dest); err != nil {
		t.Fatalf("install: %v", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "#!/bin/sh\necho tool\n" {
		t.Errorf("extracted content = %q", got)
	}
	if fi, _ := os.Stat(dest); fi.Mode()&0111 == 0 {
		t.Errorf("extracted file is not executable: %v", fi.Mode())
	}
	if len(authSeen) != 2 || authSeen[0] != "Bearer secret-token" || authSeen[1] != "Bearer secret-token" {
		t.Errorf("token not sent on both API requests: %q", authSeen)
	}
}

// TestGitHubReleaseAPIFallback checks that a failing API path (here: a token
// the API rejects) falls back to the public download URL rather than failing
// provisioning.
func TestGitHubReleaseAPIFallback(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad credentials", http.StatusUnauthorized)
	}))
	defer api.Close()
	githubAPI = api.URL
	t.Cleanup(func() { githubAPI = "https://api.github.com" })
	t.Setenv("GITHUB_TOKEN", "rejected")

	// The fallback URL is on github.com, which this offline test cannot reach;
	// an error mentioning that URL proves the fallback was attempted.
	rel := githubRelease{repo: "acme/tool", tag: "v1", asset: "tool.zip", member: "tool"}
	_, err := rel.open()
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("github.com/acme/tool/releases/download/v1/tool.zip")) {
		t.Errorf("expected a fallback to the public download URL, got: %v", err)
	}
}

// TestExtractZipMember covers the zip path (used by opencode on macOS).
func TestExtractZipMember(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "tool")
	if err := extractZipMember(bytes.NewReader(zipArchive(t, "tool", []byte("bin"))), "tool", dest); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "bin" {
		t.Errorf("extracted content = %q", got)
	}
	if err := extractZipMember(bytes.NewReader(zipArchive(t, "other", nil)), "tool", dest); err == nil {
		t.Error("expected an error for a missing member")
	}
}
