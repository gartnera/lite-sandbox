package imds

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
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

	// credsMu guards lazy initialization of creds only. It is NOT held across
	// Retrieve(), so a slow/cold credential refresh never serializes concurrent
	// requests that already have valid cached credentials.
	credsMu sync.Mutex
	creds   aws.CredentialsProvider
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
	// SDK CredentialsCache, so there's no pre-warm here.

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
		// Surface the underlying error: an expired SSO session shows up here and
		// the operator needs to know to run `aws sso login` rather than guess.
		slog.Error("failed to get credentials", "profile", s.profile, "error", err)
		http.Error(w, "Failed to get credentials", http.StatusInternalServerError)
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
		"Expiration":      creds.Expires.Format(time.RFC3339),
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

	if s.creds != nil {
		return s.creds, nil
	}

	slog.Info("loading AWS credential provider", "profile", s.profile)

	// Load AWS config with the specified profile. The resulting cfg.Credentials
	// is an aws.CredentialsCache wrapping the profile's provider (SSO,
	// assume-role, or IAM user). Setting an expiry window makes it refresh ahead
	// of actual expiry instead of at the last moment.
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(s.profile),
		config.WithCredentialsCacheOptions(func(o *aws.CredentialsCacheOptions) {
			o.ExpiryWindow = credExpiryWindow
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	s.creds = cfg.Credentials
	return s.creds, nil
}

// getCredentials returns current AWS credentials for the configured profile.
// Caching, singleflight refresh, expiry-window pre-refresh, and SSO token
// auto-refresh are all delegated to the SDK's aws.CredentialsCache, so this
// call is cheap when credentials are valid and triggers exactly one refresh
// (shared across concurrent callers) when they are not.
func (s *Server) getCredentials(ctx context.Context) (aws.Credentials, error) {
	p, err := s.provider(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	creds, err := p.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("failed to retrieve credentials: %w", err)
	}
	return creds, nil
}
