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
// Credentials are fetched via AWS STS GetSessionToken and cached until expiry.
type Server struct {
	addr        string
	profile     string
	secretToken string
	credCache   *credentialCache
	sessions    *ttlcache.Cache[string, struct{}]
	server      *http.Server
	listener    net.Listener
}

// credentialCache stores AWS credentials and their expiry time.
type credentialCache struct {
	mu        sync.RWMutex
	awsCreds  *aws.Credentials
	expiresAt time.Time
}

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
		credCache:   &credentialCache{},
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
		slog.Error("failed to get credentials", "error", err)
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

// getCredentials fetches or returns cached AWS credentials.
// For SSO/temporary credentials, returns them directly.
// For IAM user credentials, could use STS GetSessionToken but we just pass through for simplicity.
func (s *Server) getCredentials(ctx context.Context) (*aws.Credentials, error) {
	s.credCache.mu.Lock()
	defer s.credCache.mu.Unlock()

	// Check if cached credentials are still valid (refresh 5 min before expiry)
	if s.credCache.awsCreds != nil &&
		time.Now().Before(s.credCache.expiresAt.Add(-5*time.Minute)) {
		slog.Debug("using cached credentials")
		return s.credCache.awsCreds, nil
	}

	slog.Info("fetching credentials from profile", "profile", s.profile)

	// Load AWS config with specified profile
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(s.profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Retrieve credentials from the profile
	// This handles SSO, assume-role, and IAM user credentials automatically
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials: %w", err)
	}

	// Cache credentials
	s.credCache.awsCreds = &creds
	s.credCache.expiresAt = creds.Expires

	slog.Info("fetched credentials",
		"expires", creds.Expires.Format(time.RFC3339),
		"source", creds.Source)

	return &creds, nil
}
