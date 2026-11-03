package imds

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestMain keeps every test in the package off the host's AWS config: Start
// pre-warms credentials, so a server for "default" would otherwise fetch the
// developer's real credentials.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "imds-test-")
	if err != nil {
		panic(err)
	}
	os.Setenv("HOME", dir)
	os.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	os.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// isolateAWSConfig points the AWS SDK at an empty config and credentials file
// so a test never reads (or, through the pre-warm in Start, fetches
// credentials for) a same-named profile on the developer's machine.
func isolateAWSConfig(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(dir, "config"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(dir, "credentials"))
	for _, k := range []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
}

// fakeSSO is an AWS SSO portal (GetRoleCredentials) stand-in reached through
// AWS_ENDPOINT_URL_SSO, so the tests exercise the SDK's real sso_session
// provider: the cached token file, its expiry check, and the portal call.
type fakeSSO struct {
	calls        atomic.Int32
	delay        time.Duration
	unauthorized atomic.Bool
}

func (f *fakeSSO) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls.Add(1)
	time.Sleep(f.delay)
	if f.unauthorized.Load() || r.Header.Get("x-amz-sso_bearer_token") == "" {
		w.Header().Set("X-Amzn-Errortype", "UnauthorizedException")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"message":"Session token not found or invalid"}`)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"roleCredentials":{"accessKeyId":"ASIAFAKE","secretAccessKey":"secret","sessionToken":"session","expiration":%d}}`,
		time.Now().Add(time.Hour).UnixMilli())
}

// ssoProfile writes an sso_session profile named "dev" and returns a function
// that writes its cached SSO token with the given expiry, as `aws sso login`
// does.
func ssoProfile(t *testing.T, portal string) (writeToken func(expires time.Time)) {
	t.Helper()
	isolateAWSConfig(t)
	t.Setenv("AWS_ENDPOINT_URL_SSO", portal)
	home := os.Getenv("HOME")
	config := `[profile dev]
sso_session = corp
sso_account_id = 111111111111
sso_role_name = Dev
region = us-west-2

[sso-session corp]
sso_start_url = https://example.awsapps.com/start
sso_region = us-east-1
`
	if err := os.WriteFile(os.Getenv("AWS_CONFIG_FILE"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	cacheDir := filepath.Join(home, ".aws", "sso", "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatal(err)
	}
	sum := sha1.Sum([]byte("corp"))
	tokenFile := filepath.Join(cacheDir, hex.EncodeToString(sum[:])+".json")
	return func(expires time.Time) {
		t.Helper()
		b, _ := json.Marshal(map[string]string{
			"startUrl":    "https://example.awsapps.com/start",
			"region":      "us-east-1",
			"accessToken": "token",
			"expiresAt":   expires.UTC().Format(time.RFC3339),
		})
		if err := os.WriteFile(tokenFile, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// startServer starts an IMDS server for profile and returns a function that
// fetches credentials through it like an SDK client: token, then the role's
// credentials document.
func startServer(t *testing.T, profile string) (srv *Server, fetch func() map[string]string) {
	t.Helper()
	srv, err := NewServer("127.0.0.1:0", profile)
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	t.Cleanup(func() { srv.Shutdown(context.Background()) })
	base := srv.Endpoint()
	return srv, func() map[string]string {
		t.Helper()
		req, _ := http.NewRequest(http.MethodPut, base+"latest/api/token", nil)
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "60")
		var resp *http.Response
		// The server goroutine may not be accepting yet.
		for i := 0; ; i++ {
			resp, err = http.DefaultClient.Do(req)
			if err == nil || i == 50 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err != nil {
			t.Fatal(err)
		}
		tok, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		req, _ = http.NewRequest(http.MethodGet, base+"latest/meta-data/iam/security-credentials/sandboxed-role", nil)
		req.Header.Set("X-aws-ec2-metadata-token", string(tok))
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("credentials status = %d", resp.StatusCode)
		}
		var doc map[string]string
		if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
			t.Fatal(err)
		}
		return doc
	}
}

// TestSSOExpired_ReportedAndRecoversAfterLogin covers the common failure: the
// host's SSO session has expired. The credentials document carries an EC2-style
// error Code instead of a bare 500, the failure is recorded for the sandbox's
// note with a hint naming `aws sso login`, and once the user logs in again on
// the host the next request succeeds without restarting anything.
func TestSSOExpired_ReportedAndRecoversAfterLogin(t *testing.T) {
	portal := &fakeSSO{}
	ts := httptest.NewServer(portal)
	defer ts.Close()
	writeToken := ssoProfile(t, ts.URL)
	writeToken(time.Now().Add(-time.Hour))

	start := time.Now()
	srv, fetch := startServer(t, "dev")
	doc := fetch()
	if doc["Code"] != "SSOSessionExpired" {
		t.Fatalf("Code = %q, want SSOSessionExpired (doc %v)", doc["Code"], doc)
	}
	if !strings.Contains(doc["Message"], "aws sso login --profile dev") {
		t.Errorf("Message should name the fix, got %q", doc["Message"])
	}
	if _, ok := doc["AccessKeyId"]; ok {
		t.Error("error document must not carry credentials")
	}
	if portal.calls.Load() != 0 {
		t.Errorf("an expired cached token should fail before calling the portal, got %d calls", portal.calls.Load())
	}

	err := srv.CredentialErrorSince(start)
	if err == nil || !IsSSOLoginError(err) {
		t.Fatalf("CredentialErrorSince = %v, want an SSO login error", err)
	}
	hint := Hint("dev", err)
	for _, want := range []string{`profile "dev"`, "SSO session has expired", "aws sso login --profile dev", "on the host", "cause:"} {
		if !strings.Contains(hint, want) {
			t.Errorf("hint missing %q:\n%s", want, hint)
		}
	}
	if srv.CredentialErrorSince(time.Now().Add(time.Second)) != nil {
		t.Error("a failure before since must not be reported")
	}

	// `aws sso login` on the host writes a fresh token; no restart needed.
	writeToken(time.Now().Add(8 * time.Hour))
	doc = fetch()
	if doc["Code"] != "Success" || doc["AccessKeyId"] != "ASIAFAKE" {
		t.Fatalf("after login: doc = %v", doc)
	}
	if err := srv.CredentialErrorSince(start); err != nil {
		t.Errorf("a later success should clear the recorded failure, got %v", err)
	}
}

// TestSSONeverLoggedIn: no cached token file at all (the user never ran `aws
// sso login` for this session) is the same fix.
func TestSSONeverLoggedIn(t *testing.T) {
	ts := httptest.NewServer(&fakeSSO{})
	defer ts.Close()
	ssoProfile(t, ts.URL) // token never written

	_, fetch := startServer(t, "dev")
	if doc := fetch(); doc["Code"] != "SSOSessionExpired" {
		t.Fatalf("Code = %q, want SSOSessionExpired", doc["Code"])
	}
}

// TestSSOPortalRejectsToken: the token file looks current but the portal has
// revoked the session (UnauthorizedException), e.g. after a sign-out elsewhere.
func TestSSOPortalRejectsToken(t *testing.T) {
	portal := &fakeSSO{}
	portal.unauthorized.Store(true)
	ts := httptest.NewServer(portal)
	defer ts.Close()
	ssoProfile(t, ts.URL)(time.Now().Add(time.Hour))

	start := time.Now()
	srv, fetch := startServer(t, "dev")
	if doc := fetch(); doc["Code"] != "SSOSessionExpired" {
		t.Fatalf("Code = %q, want SSOSessionExpired", doc["Code"])
	}
	if err := srv.CredentialErrorSince(start); !IsSSOLoginError(err) {
		t.Fatalf("portal 401 should classify as an SSO login error, got %v", err)
	}
}

// TestNonSSOFailure_GenericHint: a failure that `aws sso login` would not fix
// (here, a profile missing from the host config) gets the generic code and
// hint, with the cause.
func TestNonSSOFailure_GenericHint(t *testing.T) {
	isolateAWSConfig(t)
	start := time.Now()
	srv, fetch := startServer(t, "missing")
	doc := fetch()
	if doc["Code"] != "CredentialsUnavailable" {
		t.Fatalf("Code = %q, want CredentialsUnavailable", doc["Code"])
	}
	err := srv.CredentialErrorSince(start)
	if err == nil || IsSSOLoginError(err) {
		t.Fatalf("want a non-SSO error, got %v", err)
	}
	hint := Hint("missing", err)
	if strings.Contains(hint, "sso login") || !strings.Contains(hint, "cause:") {
		t.Errorf("unexpected generic hint:\n%s", hint)
	}
}

// TestStart_PrewarmsCredentials covers the "fails on the first run" report: a
// cold fetch waits on the host's network round trip, longer than botocore's 1s
// IMDS timeout or the Go SDK's 500ms. Start fetches once in the background, so
// the first command's request is served from the cache.
func TestStart_PrewarmsCredentials(t *testing.T) {
	portal := &fakeSSO{delay: 300 * time.Millisecond}
	ts := httptest.NewServer(portal)
	defer ts.Close()
	ssoProfile(t, ts.URL)(time.Now().Add(time.Hour))

	_, fetch := startServer(t, "dev")
	deadline := time.Now().Add(5 * time.Second)
	for portal.calls.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("Start did not pre-warm credentials")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(portal.delay + 100*time.Millisecond) // let the warm fetch land

	t0 := time.Now()
	doc := fetch()
	if d := time.Since(t0); d > 200*time.Millisecond {
		t.Errorf("first request took %v; expected the pre-warmed cache to serve it", d)
	}
	if doc["Code"] != "Success" {
		t.Fatalf("doc = %v", doc)
	}
	if n := portal.calls.Load(); n != 1 {
		t.Errorf("portal calls = %d, want 1 (the pre-warm)", n)
	}
}

func TestIsSSOLoginError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("failed to refresh cached credentials, refresh cached SSO token failed, cached SSO token is expired, or not present, and cannot be refreshed"), true},
		{errors.New("failed to read cached SSO token file, open /x: no such file or directory"), true},
		{errors.New("operation error SSO: GetRoleCredentials, dial tcp: lookup portal.sso.us-east-1.amazonaws.com: no such host"), false},
		{errors.New("failed to get shared config profile, dev"), false},
	} {
		if got := IsSSOLoginError(tc.err); got != tc.want {
			t.Errorf("IsSSOLoginError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
