// Package ghrelease downloads assets from GitHub releases.
//
// It is shared by the `lite-sandbox update` self-updater and the e2e suite's
// agent provisioning. Downloads go through the authenticated REST API when a
// token is available — so they count against the token's generous rate limit
// rather than the per-IP one shared by every job on a CI runner — and fall back
// to the public browser download URL otherwise.
package ghrelease

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Default endpoints; a test points a Client at a local server instead.
const (
	DefaultAPIBase      = "https://api.github.com"
	DefaultDownloadBase = "https://github.com"
)

// Client fetches GitHub releases. The zero value uses the public endpoints,
// http.DefaultClient, and the token from the environment (see TokenFromEnv).
type Client struct {
	// APIBase is the REST API base URL (DefaultAPIBase when empty).
	APIBase string
	// DownloadBase is the base of the public download URLs,
	// <DownloadBase>/<owner>/<repo>/releases/download/<tag>/<asset>
	// (DefaultDownloadBase when empty).
	DownloadBase string
	// Token authenticates API requests. When empty, TokenFromEnv() is used;
	// when that is empty too, only the public download URLs are used.
	Token string
	// HTTPClient is the client to use (http.DefaultClient when nil).
	HTTPClient *http.Client
	// Warn, when set, receives a note when the authenticated API path fails and
	// the download falls back to the public URL.
	Warn func(format string, args ...any)
}

// Release is a GitHub release and its attached assets.
type Release struct {
	Repo   string  `json:"-"` // owner/name
	Tag    string  `json:"tag_name"`
	Name   string  `json:"name"`
	Assets []Asset `json:"assets"`
}

// Asset is a file attached to a release.
type Asset struct {
	Name string `json:"name"`
	// URL is the API URL of the asset; requested with Accept:
	// application/octet-stream it redirects to the asset's bytes.
	URL string `json:"url"`
	// BrowserDownloadURL is the public, unauthenticated download URL.
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// Asset returns the asset named name, or nil.
func (r *Release) Asset(name string) *Asset {
	for i := range r.Assets {
		if r.Assets[i].Name == name {
			return &r.Assets[i]
		}
	}
	return nil
}

// TokenFromEnv returns the GitHub token from GITHUB_TOKEN (what GitHub Actions
// provides) or GH_TOKEN (the gh CLI's), or "".
func TokenFromEnv() string {
	if t := os.Getenv("GITHUB_TOKEN"); t != "" {
		return t
	}
	return os.Getenv("GH_TOKEN")
}

func (c *Client) apiBase() string {
	if c.APIBase != "" {
		return strings.TrimSuffix(c.APIBase, "/")
	}
	return DefaultAPIBase
}

func (c *Client) downloadBase() string {
	if c.DownloadBase != "" {
		return strings.TrimSuffix(c.DownloadBase, "/")
	}
	return DefaultDownloadBase
}

func (c *Client) token() string {
	if c.Token != "" {
		return c.Token
	}
	return TokenFromEnv()
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	return http.DefaultClient
}

func (c *Client) warn(format string, args ...any) {
	if c.Warn != nil {
		c.Warn(format, args...)
	}
}

// apiHeaders returns the headers for an authenticated API request.
func apiHeaders(token, accept string) map[string]string {
	h := map[string]string{
		"X-GitHub-Api-Version": "2022-11-28",
		"Accept":               accept,
	}
	if token != "" {
		h["Authorization"] = "Bearer " + token
	}
	return h
}

// Latest returns the latest (non-prerelease, non-draft) release of repo
// ("owner/name"), as GitHub's releases/latest endpoint defines it.
func (c *Client) Latest(ctx context.Context, repo string) (*Release, error) {
	return c.getRelease(ctx, repo, fmt.Sprintf("%s/repos/%s/releases/latest", c.apiBase(), repo))
}

// ByTag returns the release of repo ("owner/name") tagged tag.
func (c *Client) ByTag(ctx context.Context, repo, tag string) (*Release, error) {
	return c.getRelease(ctx, repo, fmt.Sprintf("%s/repos/%s/releases/tags/%s", c.apiBase(), repo, tag))
}

// getRelease fetches and decodes a release from the API. Release metadata is
// public for public repositories, so this works without a token too (subject
// to the per-IP rate limit).
func (c *Client) getRelease(ctx context.Context, repo, url string) (*Release, error) {
	body, err := c.get(ctx, url, apiHeaders(c.token(), "application/vnd.github+json"))
	if err != nil {
		return nil, err
	}
	defer body.Close()
	rel := &Release{Repo: repo}
	if err := json.NewDecoder(body).Decode(rel); err != nil {
		return nil, fmt.Errorf("decoding release from %s: %w", url, err)
	}
	if rel.Tag == "" {
		return nil, fmt.Errorf("%s: response has no tag_name", url)
	}
	return rel, nil
}

// Open returns the bytes of the asset named asset in the release of repo
// ("owner/name") tagged tag. With a token it goes through the authenticated
// REST API — the release's asset list, then the asset itself as
// application/octet-stream. Without a token, or if the API path fails (a token
// without access to the repository, an API outage), it falls back to the
// public browser download URL, which needs no authentication.
func (c *Client) Open(ctx context.Context, repo, tag, asset string) (io.ReadCloser, error) {
	if token := c.token(); token != "" {
		body, err := c.openViaAPI(ctx, repo, tag, asset, token)
		if err == nil {
			return body, nil
		}
		c.warn("%s: GitHub API download failed (%v); falling back to the public download URL", asset, err)
	}
	return c.get(ctx, fmt.Sprintf("%s/%s/releases/download/%s/%s", c.downloadBase(), repo, tag, asset), nil)
}

// OpenAsset returns the bytes of an asset already listed in a fetched release.
// It follows the same authenticated-then-public strategy as Open, minus the
// release lookup.
func (c *Client) OpenAsset(ctx context.Context, rel *Release, name string) (io.ReadCloser, error) {
	a := rel.Asset(name)
	if a == nil {
		return nil, fmt.Errorf("release %s has no asset %s", rel.Tag, name)
	}
	if token := c.token(); token != "" && a.URL != "" {
		body, err := c.get(ctx, a.URL, apiHeaders(token, "application/octet-stream"))
		if err == nil {
			return body, nil
		}
		c.warn("%s: GitHub API download failed (%v); falling back to the public download URL", name, err)
	}
	if a.BrowserDownloadURL != "" {
		return c.get(ctx, a.BrowserDownloadURL, nil)
	}
	return c.get(ctx, fmt.Sprintf("%s/%s/releases/download/%s/%s", c.downloadBase(), rel.Repo, rel.Tag, name), nil)
}

// openViaAPI fetches the asset through the REST API with token.
func (c *Client) openViaAPI(ctx context.Context, repo, tag, asset, token string) (io.ReadCloser, error) {
	rel, err := c.ByTag(ctx, repo, tag)
	if err != nil {
		return nil, err
	}
	a := rel.Asset(asset)
	if a == nil {
		return nil, fmt.Errorf("release %s has no asset %s", tag, asset)
	}
	// The asset endpoint redirects to a pre-signed storage URL; Go's client
	// drops the Authorization header on that cross-host redirect, as it must.
	return c.get(ctx, a.URL, apiHeaders(token, "application/octet-stream"))
}

// get GETs url with the given request headers and returns the body, failing
// on a non-200 status.
func (c *Client) get(ctx context.Context, url string, headers map[string]string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, &HTTPError{URL: url, StatusCode: resp.StatusCode, Status: resp.Status}
	}
	return resp.Body, nil
}

// HTTPError is returned for a non-200 response.
type HTTPError struct {
	URL        string
	StatusCode int
	Status     string
}

func (e *HTTPError) Error() string { return fmt.Sprintf("GET %s: %s", e.URL, e.Status) }

// IsNotFound reports whether err is an HTTPError with status 404.
func IsNotFound(err error) bool {
	var he *HTTPError
	return errors.As(err, &he) && he.StatusCode == http.StatusNotFound
}

// Install downloads asset from the release of repo tagged tag and writes the
// archive member whose base name is member to dest as an executable.
func (c *Client) Install(ctx context.Context, repo, tag, asset, member, dest string) error {
	body, err := c.Open(ctx, repo, tag, asset)
	if err != nil {
		return err
	}
	defer body.Close()
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	return errors.Join(ExtractMember(body, asset, member, f), f.Close())
}

// ExtractMember reads the archive named asset (a .tar.gz or a .zip, decided by
// the name's suffix) and copies the regular file whose base name is member to
// w.
func ExtractMember(archive io.Reader, asset, member string, w io.Writer) error {
	switch {
	case strings.HasSuffix(asset, ".tar.gz"), strings.HasSuffix(asset, ".tgz"):
		return extractTarMember(archive, member, w)
	case strings.HasSuffix(asset, ".zip"):
		return extractZipMember(archive, member, w)
	}
	return fmt.Errorf("%s: unsupported archive type", asset)
}

// extractTarMember reads a .tar.gz stream and copies the regular file whose
// base name is member to w.
func extractTarMember(archive io.Reader, member string, w io.Writer) error {
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
			_, err := io.Copy(w, tr)
			return err
		}
	}
}

// extractZipMember reads a .zip stream and copies the file whose base name is
// member to w. Zip needs random access, so the archive is spooled to a temp
// file first.
func extractZipMember(archive io.Reader, member string, w io.Writer) error {
	tmp, err := os.CreateTemp("", "ghrelease-*.zip")
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
		_, err = io.Copy(w, rc)
		return err
	}
	return fmt.Errorf("no %s in archive", member)
}
