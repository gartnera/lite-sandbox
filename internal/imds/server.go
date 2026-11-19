package imds

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ssocreds"
	"github.com/aws/smithy-go"
	"github.com/jellydator/ttlcache/v3"
)

// Server implements an IMDSv2-compatible HTTP server that provides AWS credentials
// to sandboxed commands without requiring file access to ~/.aws/credentials.
// Credentials come from the configured profile's provider, wrapped in the AWS
// SDK's own aws.CredentialsCache, which handles concurrency-safe caching,
// singleflight refresh, expiry-window pre-refresh, and (for sso_session
// profiles) SSO token auto-refresh.
type Server struct {
	addr        string
	profile     string
	secretToken string
	sessions    *ttlcache.Cache[string, struct{}]
	server      *http.Server
	listener    net.Listener

	// credsMu guards lazy initialization of creds and region only. It is NOT held
	// across Retrieve(), so a slow/cold credential refresh never serializes
	// concurrent requests that already have valid cached credentials.
	credsMu sync.Mutex
	creds   aws.CredentialsProvider
	// region is the AWS region resolved for the profile during the config load
	// (from the profile's config file, AWS_REGION, etc.). It is captured
	// alongside creds because region resolution reads the shared config and does
	// not require valid credentials — so it is available even for an expired SSO
	// session. Empty when the profile configures no region.
	region string

	// failMu guards the record of the most recent credential fetch outcome, which
	// the sandbox reads (CredentialErrorSince) to tell the agent why an AWS
	// command found no credentials. botocore discards the IMDS error body and
	// reports only "Unable to locate credentials", so without this the real cause
	// (typically an expired SSO session on the host) is only in the server log.
	failMu sync.Mutex
	// lastFailAt is when the most recent fetch failed; zero once a later fetch
	// succeeds.
	lastFailAt time.Time
	lastErr    error
}

// credExpiryWindow tells the SDK CredentialsCache to refresh this far ahead of
// actual expiry, so a request never lands on the moment creds go stale.
const credExpiryWindow = 5 * time.Minute

// NewServer creates a new IMDS server that will listen on the given address
// and use the specified AWS profile for credential lookups.
// The server starts listening immediately but does not serve until Start() is called.
// If addr uses port 0, a random available port is assigned.
func NewServer(addr string, profile string) (*Server, error) {
	// Generate cryptographically secure random token for URL path
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate secret token: %w", err)
	}
	secretToken := base64.URLEncoding.EncodeToString(tokenBytes)

	// Start listening immediately to claim the port
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	// ttlcache evicts entries automatically once their TTL elapses, so the
	// session store stays bounded even under heavy /latest/api/token traffic.
	// Touch-on-hit is disabled — validateSession must not silently extend a
	// token's lifetime past the TTL the AWS SDK negotiated.
	sessions := ttlcache.New[string, struct{}](
		ttlcache.WithDisableTouchOnHit[string, struct{}](),
	)

	return &Server{
		addr:        listener.Addr().String(), // Use actual bound address
		profile:     profile,
		secretToken: secretToken,
		sessions:    sessions,
		listener:    listener,
	}, nil
}

// Endpoint returns the full IMDS endpoint URL to pass to AWS CLI via
// AWS_EC2_METADATA_SERVICE_ENDPOINT environment variable.
// Returns base URL with trailing slash (AWS SDK appends paths like /latest/api/token).
func (s *Server) Endpoint() string {
	return fmt.Sprintf("http://%s/", s.addr)
}

// Start starts the IMDS HTTP server. This blocks until the server is shut down.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// IMDSv2 endpoints at standard paths (no secret token prefix)
	// Security relies on: localhost binding + random port + OS sandbox blocking ~/.aws

	// IMDSv2 token generation endpoint
	mux.HandleFunc("PUT /latest/api/token", s.handleGetToken)

	// Credential endpoints
	mux.HandleFunc("GET /latest/meta-data/iam/security-credentials/", s.handleListRoles)
	mux.HandleFunc("GET /latest/meta-data/iam/security-credentials/{role}", s.handleGetCredentials)

	s.server = &http.Server{
		Handler: mux,
	}

	// Run the background eviction loop so expired session tokens are dropped
	// from memory rather than accumulating until shutdown.
	go s.sessions.Start()

	// Credentials are fetched lazily on the first request and then cached by the
	// SDK CredentialsCache, so there's no pre-warm here (a session that never
	// runs an AWS command makes no AWS calls). A cold first fetch can take
	// seconds; the sandbox raises botocore's IMDS timeout to cover it
	// (AWS_METADATA_SERVICE_TIMEOUT), and the Go SDK retries while the fetch,
	// which is not tied to the request's context, completes.

	slog.Info("starting IMDS server", "addr", s.addr, "profile", s.profile)
	return s.server.Serve(s.listener)
}

// Shutdown gracefully shuts down the IMDS server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.sessions.Stop()
	if s.server != nil {
		err := s.server.Shutdown(ctx)
		// Close listener if server shutdown didn't close it
		if s.listener != nil {
			s.listener.Close()
		}
		return err
	}
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// handleGetToken implements the IMDSv2 token generation endpoint.
// PUT /latest/api/token with X-aws-ec2-metadata-token-ttl-seconds header.
func (s *Server) handleGetToken(w http.ResponseWriter, r *http.Request) {
	ttlHeader := r.Header.Get("X-aws-ec2-metadata-token-ttl-seconds")
	ttl, err := strconv.Atoi(ttlHeader)
	if err != nil || ttl < 1 || ttl > 21600 {
		ttl = 21600 // Default 6 hours
	}

	// Generate secure session token
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		slog.Error("failed to generate session token", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	token := base64.URLEncoding.EncodeToString(tokenBytes)

	// Store session with explicit TTL; ttlcache evicts it once expired.
	s.sessions.Set(token, struct{}{}, time.Duration(ttl)*time.Second)

	slog.Debug("generated IMDSv2 session token", "ttl", ttl)

	// EC2 echoes the granted TTL. The Go SDK requires it: without the header it
	// fails the token request, falls back to IMDSv1, and gets 401 from us.
	w.Header().Set("X-Aws-Ec2-Metadata-Token-Ttl-Seconds", strconv.Itoa(ttl))
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(token))
}

// handleListRoles implements the role listing endpoint.
// GET /latest/meta-data/iam/security-credentials/
func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	if !s.validateSession(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Return single role name (matches EC2 IMDS behavior)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("sandboxed-role"))
}

// handleGetCredentials implements the credential retrieval endpoint.
// GET /latest/meta-data/iam/security-credentials/{role}
func (s *Server) handleGetCredentials(w http.ResponseWriter, r *http.Request) {
	if !s.validateSession(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	role := r.PathValue("role")
	if role != "sandboxed-role" {
		http.Error(w, "Role not found", http.StatusNotFound)
		return
	}

	// Get or refresh credentials
	// Use background context with timeout to avoid request cancellation affecting credential fetch
	credCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	creds, err := s.getCredentials(credCtx)
	if err != nil {
		// Answer like EC2 IMDS does when it cannot vend role credentials: 200
		// with a non-Success Code and a Message. The Go SDK reports Code and
		// Message to the caller; botocore logs it and finds no credentials. The
		// raw error stays on the host (log, and the sandbox's note to the agent)
		// rather than being handed to sandboxed code.
		code, msg := "CredentialsUnavailable", fmt.Sprintf("lite-sandbox could not get AWS credentials for profile %q on the host", s.profile)
		if IsSSOLoginError(err) {
			code = "SSOSessionExpired"
			msg = fmt.Sprintf("the host's AWS SSO session for profile %q has expired or is not logged in; run `aws sso login --profile %s` on the host", s.profile, s.profile)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"Code":        code,
			"Message":     msg,
			"LastUpdated": time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	// Format as IMDSv2 JSON response
	response := map[string]any{
		"Code":            "Success",
		"LastUpdated":     time.Now().Format(time.RFC3339),
		"Type":            "AWS-HMAC",
		"AccessKeyId":     creds.AccessKeyID,
		"SecretAccessKey": creds.SecretAccessKey,
		"Token":           creds.SessionToken,
		"Expiration":      vendedExpiry(creds, time.Now()).UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		slog.Error("failed to encode response", "error", err)
	}
}

// validateSession checks if the request has a valid IMDSv2 session token.
// ttlcache.Has reports presence without extending the entry's lifetime, and
// expired entries are treated as absent regardless of whether the background
// eviction goroutine has run yet.
func (s *Server) validateSession(r *http.Request) bool {
	token := r.Header.Get("X-aws-ec2-metadata-token")
	if token == "" {
		slog.Warn("request missing IMDSv2 session token")
		return false
	}
	if !s.sessions.Has(token) {
		slog.Warn("request with unknown or expired session token")
		return false
	}
	return true
}

// provider returns the credentials provider for the configured profile,
// lazily building it on first use. The returned provider is an
// aws.CredentialsCache (from LoadDefaultConfig), which is safe for concurrent
// use. credsMu is held only for the (network-free) config load, never across a
// credential Retrieve, so concurrent callers don't serialize on it.
//
// Initialization is retried on failure rather than memoized: a transient error
// (e.g. a momentarily unreadable config) must not wedge the server until
// restart.
func (s *Server) provider(ctx context.Context) (aws.CredentialsProvider, error) {
	s.credsMu.Lock()
	defer s.credsMu.Unlock()
	if err := s.ensureLoadedLocked(ctx); err != nil {
		return nil, err
	}
	return s.creds, nil
}

// ensureLoadedLocked lazily loads the profile's AWS config, caching both the
// credential provider and the resolved region. credsMu must be held. On error
// nothing is cached, so the load is retried on the next call rather than
// wedging the server until restart.
func (s *Server) ensureLoadedLocked(ctx context.Context) error {
	if s.creds != nil {
		return nil
	}

	slog.Info("loading AWS credential provider", "profile", s.profile)

	// Load AWS config with the specified profile. The resulting cfg.Credentials
	// is an aws.CredentialsCache wrapping the profile's provider (SSO,
	// assume-role, or IAM user). Setting an expiry window makes it refresh ahead
	// of actual expiry instead of at the last moment. cfg.Region is resolved from
	// the shared config here too, without needing valid credentials.
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(s.profile),
		config.WithCredentialsCacheOptions(func(o *aws.CredentialsCacheOptions) {
			o.ExpiryWindow = credExpiryWindow
		}),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %w", err)
	}

	s.creds = cfg.Credentials
	s.region = cfg.Region
	return nil
}

// Region returns the AWS region resolved for the configured profile, or "" if
// the profile configures none. It shares the lazy config load with credential
// resolution and does not require valid credentials, so it returns the region
// even when the profile's SSO session is expired. The sandbox injects this as
// AWS_REGION so regional AWS commands work without an explicit --region (the
// profile's own config, which holds the region, is masked inside the sandbox).
func (s *Server) Region(ctx context.Context) string {
	s.credsMu.Lock()
	defer s.credsMu.Unlock()
	if err := s.ensureLoadedLocked(ctx); err != nil {
		slog.Warn("could not resolve region for profile", "profile", s.profile, "error", err)
		return ""
	}
	return s.region
}

// getCredentials returns current AWS credentials for the configured profile.
// Caching, singleflight refresh, expiry-window pre-refresh, and SSO token
// auto-refresh are all delegated to the SDK's aws.CredentialsCache, so this
// call is cheap when credentials are valid and triggers exactly one refresh
// (shared across concurrent callers) when they are not.
//
// Every outcome, including a config load failure, is recorded for
// CredentialErrorSince.
func (s *Server) getCredentials(ctx context.Context) (aws.Credentials, error) {
	creds, err := s.retrieve(ctx)
	s.recordResult(err)
	return creds, err
}

func (s *Server) retrieve(ctx context.Context) (aws.Credentials, error) {
	p, err := s.provider(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	creds, err := p.Retrieve(ctx)
	if err != nil {
		s.dropProvider(p)
		return aws.Credentials{}, fmt.Errorf("failed to retrieve credentials: %w", err)
	}
	if !creds.CanExpire {
		// An IAM user's static keys, which the SDK would cache forever: reread
		// them from the host's files on every request (a local file read), so
		// keys rotated after a revocation take effect without a restart.
		s.dropProvider(p)
	}
	return creds, nil
}

// dropProvider discards the cached provider p after a failed fetch, so the
// next request reloads the profile from the host's ~/.aws/config and
// ~/.aws/credentials. The load captures key material (an IAM user's keys, an
// assume-role profile's source keys), so without this, fixing or rotating
// them on the host would not take effect until lite-sandbox restarted. A
// provider that a concurrent reload already replaced is left alone.
func (s *Server) dropProvider(p aws.CredentialsProvider) {
	s.credsMu.Lock()
	defer s.credsMu.Unlock()
	if s.creds == p {
		s.creds = nil
	}
}

// staticCredsLifetime is the Expiration advertised for credentials that do not
// expire (an IAM user's access keys). IMDS clients require an expiry (botocore
// overflows on Go's zero time), and a finite one makes a long-running client
// come back, so keys rotated on the host reach it within this long.
const staticCredsLifetime = time.Hour

// vendedExpiry is the Expiration to advertise for creds at now.
func vendedExpiry(creds aws.Credentials, now time.Time) time.Time {
	if !creds.CanExpire || creds.Expires.IsZero() {
		return now.Add(staticCredsLifetime)
	}
	return creds.Expires
}

// recordResult notes the outcome of a credential fetch for CredentialErrorSince
// and logs failures with the remedy.
func (s *Server) recordResult(err error) {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	if err == nil {
		s.lastFailAt, s.lastErr = time.Time{}, nil
		return
	}
	s.lastFailAt, s.lastErr = time.Now(), err
	if IsSSOLoginError(err) {
		slog.Error("AWS SSO session expired or not logged in; run `aws sso login --profile "+s.profile+"` on the host", "profile", s.profile, "error", err)
		return
	}
	slog.Error("failed to get AWS credentials", "profile", s.profile, "error", err)
}

// CredentialErrorSince returns the error of the most recent failed credential
// fetch if it happened at or after since and no fetch has succeeded since it,
// and nil otherwise. The sandbox calls it after a command to explain a
// credential failure the AWS client itself reports only as missing
// credentials.
func (s *Server) CredentialErrorSince(since time.Time) error {
	s.failMu.Lock()
	defer s.failMu.Unlock()
	if s.lastErr == nil || s.lastFailAt.Before(since) {
		return nil
	}
	return s.lastErr
}

// ssoLoginErrorCodes are the AWS API error codes that mean the SSO session
// behind a profile is no longer usable, so `aws sso login` is the fix: the
// portal rejecting the access token (SSO GetRoleCredentials), and the OIDC
// service rejecting a token refresh (expired refresh token or client
// registration).
var ssoLoginErrorCodes = map[string]bool{
	"UnauthorizedException":       true,
	"InvalidGrantException":       true,
	"ExpiredTokenException":       true,
	"InvalidClientException":      true,
	"UnauthorizedClientException": true,
}

// IsSSOLoginError reports whether err from a credential fetch means the
// profile's AWS SSO session has expired or was never logged in, so that
// running `aws sso login` on the host fixes it.
func IsSSOLoginError(err error) bool {
	if err == nil {
		return false
	}
	var invalid *ssocreds.InvalidTokenError
	if errors.As(err, &invalid) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && ssoLoginErrorCodes[apiErr.ErrorCode()] {
		return true
	}
	// The sso_session token provider returns plain errors for a missing or
	// expired cached token (ssocreds.SSOTokenProvider), with no type to match.
	msg := err.Error()
	return strings.Contains(msg, "cached SSO token is expired") ||
		strings.Contains(msg, "failed to read cached SSO token file")
}

// Hint describes a credential failure for profile to the agent: what went
// wrong and what the user has to do on the host. After a failure the profile is
// reloaded from the host's AWS config on the next request (dropProvider), so
// no restart is needed once the host's credentials are fixed.
func Hint(profile string, err error) string {
	if IsSSOLoginError(err) {
		return fmt.Sprintf("lite-sandbox: AWS credentials for profile %q are unavailable because the host's AWS SSO session has expired or is not logged in. "+
			"This is not a sandbox restriction and retrying will not help: ask the user to run `aws sso login --profile %s` on the host (outside the sandbox), then retry; no restart is needed.\n"+
			"  cause: %v", profile, profile, err)
	}
	return fmt.Sprintf("lite-sandbox: AWS credentials for profile %q could not be obtained on the host, so the command saw no credentials. "+
		"This is not a sandbox restriction: ask the user to fix that profile's credentials on the host (outside the sandbox; e.g. expired, revoked, or rotated keys, or a role it can no longer assume), then retry; no restart is needed.\n"+
		"  cause: %v", profile, err)
}
