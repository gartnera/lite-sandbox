package ghrelease

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

// TestInstallViaAPI checks the authenticated path: the release is looked up by
// tag through the API with the token, the asset is fetched through its API URL
// as an octet stream, and the archive member lands as an executable.
func TestInstallViaAPI(t *testing.T) {
	archive := tarGz(t, "tool", []byte("#!/bin/sh\necho tool\n"))
	var mux http.ServeMux
	srv := httptest.NewServer(&mux)
	defer srv.Close()
	var authSeen []string
	mux.HandleFunc("/repos/acme/tool/releases/tags/v1.2.3", func(w http.ResponseWriter, r *http.Request) {
		authSeen = append(authSeen, r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v1.2.3", "assets": []any{
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
	c := &Client{APIBase: srv.URL, Token: "secret-token"}

	dest := filepath.Join(t.TempDir(), "tool")
	if err := c.Install(context.Background(), "acme/tool", "v1.2.3", "tool-linux.tar.gz", "tool", dest); err != nil {
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

// TestOpenAPIFallback checks that a failing API path (here: a token the API
// rejects) falls back to the public download URL rather than failing.
func TestOpenAPIFallback(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad credentials", http.StatusUnauthorized)
	}))
	defer api.Close()
	var public []string
	dl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		public = append(public, r.URL.Path+"|"+r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("bytes"))
	}))
	defer dl.Close()
	var warned []string
	c := &Client{APIBase: api.URL, DownloadBase: dl.URL, Token: "rejected",
		Warn: func(f string, a ...any) { warned = append(warned, f) }}

	body, err := c.Open(context.Background(), "acme/tool", "v1", "tool.zip")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer body.Close()
	if len(public) != 1 || public[0] != "/acme/tool/releases/download/v1/tool.zip|" {
		t.Errorf("expected one unauthenticated public download, got %q", public)
	}
	if len(warned) != 1 {
		t.Errorf("expected one fallback warning, got %d", len(warned))
	}
}

// TestOpenWithoutToken checks that with no token the public URL is used
// directly, without touching the API.
func TestOpenWithoutToken(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected API request %s", r.URL)
	}))
	defer api.Close()
	dl := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("bytes"))
	}))
	defer dl.Close()
	c := &Client{APIBase: api.URL, DownloadBase: dl.URL}
	body, err := c.Open(context.Background(), "acme/tool", "v1", "tool.zip")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	body.Close()
}

// TestLatestAndOpenAsset covers the releases/latest lookup and downloading an
// asset listed in it.
func TestLatestAndOpenAsset(t *testing.T) {
	var mux http.ServeMux
	srv := httptest.NewServer(&mux)
	defer srv.Close()
	mux.HandleFunc("/repos/acme/tool/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Errorf("Accept = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tag_name": "v2.0.0", "assets": []any{
			map[string]any{"name": "checksums.txt", "url": srv.URL + "/api/1", "browser_download_url": srv.URL + "/public/1"},
		}})
	})
	mux.HandleFunc("/public/1", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("public")) })
	mux.HandleFunc("/api/1", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("api")) })

	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	c := &Client{APIBase: srv.URL}
	rel, err := c.Latest(context.Background(), "acme/tool")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if rel.Tag != "v2.0.0" || rel.Repo != "acme/tool" {
		t.Errorf("release = %+v", rel)
	}
	read := func(c *Client, name string) string {
		body, err := c.OpenAsset(context.Background(), rel, name)
		if err != nil {
			t.Fatalf("OpenAsset(%s): %v", name, err)
		}
		defer body.Close()
		var b strings.Builder
		if _, err := io.Copy(&b, body); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	if got := read(c, "checksums.txt"); got != "public" {
		t.Errorf("without a token OpenAsset read %q, want the public URL", got)
	}
	if got := read(&Client{APIBase: srv.URL, Token: "tok"}, "checksums.txt"); got != "api" {
		t.Errorf("with a token OpenAsset read %q, want the API URL", got)
	}
	if _, err := c.OpenAsset(context.Background(), rel, "missing"); err == nil {
		t.Error("expected an error for a missing asset")
	}
}

// TestExtractMember covers both archive formats and the missing-member error.
func TestExtractMember(t *testing.T) {
	var out bytes.Buffer
	if err := ExtractMember(bytes.NewReader(zipArchive(t, "tool", []byte("bin"))), "tool.zip", "tool", &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "bin" {
		t.Errorf("zip content = %q", out.String())
	}
	out.Reset()
	if err := ExtractMember(bytes.NewReader(tarGz(t, "tool", []byte("tar"))), "tool.tar.gz", "tool", &out); err != nil {
		t.Fatal(err)
	}
	if out.String() != "tar" {
		t.Errorf("tar content = %q", out.String())
	}
	if err := ExtractMember(bytes.NewReader(zipArchive(t, "other", nil)), "x.zip", "tool", &out); err == nil {
		t.Error("expected an error for a missing member")
	}
	if err := ExtractMember(bytes.NewReader(nil), "tool.rar", "tool", &out); err == nil {
		t.Error("expected an error for an unsupported archive type")
	}
}
