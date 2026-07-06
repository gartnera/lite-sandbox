package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/imds"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

// imdsLifecycle owns the IMDS server on behalf of a long-running command
// (serve-mcp, shell) so startup and config reloads share one reconciliation
// path: apply starts the server when AWS IMDS mode is enabled, stops it when
// disabled, and restarts it when the forced profile changes. The sandbox's
// IMDS endpoint is kept in sync so commands only receive
// AWS_EC2_METADATA_SERVICE_ENDPOINT while a server is actually running.
type imdsLifecycle struct {
	mu      sync.Mutex
	sandbox *bash_sandboxed.Sandbox
	server  *imds.Server
	profile string
}

// apply reconciles the running IMDS server with the AWS config resolved for
// the working directory (see AWSConfig.ForDirectory). It returns an error
// only when a server that should be running could not be created; stopping
// is best-effort.
func (l *imdsLifecycle) apply(awsCfg *config.AWSConfig) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	desired := awsCfg != nil && awsCfg.UsesIMDS()
	profile := ""
	if desired {
		profile = awsCfg.IMDSProfile()
	}

	if l.server != nil && (!desired || profile != l.profile) {
		slog.Info("stopping IMDS server", "profile", l.profile)
		l.stopLocked()
	}
	if l.server == nil && desired {
		// Use port 0 to get a random available port.
		server, err := imds.NewServer("127.0.0.1:0", profile)
		if err != nil {
			return fmt.Errorf("failed to create IMDS server: %w", err)
		}
		go func() {
			slog.Info("IMDS server endpoint", "url", server.Endpoint())
			if err := server.Start(); err != nil && err != http.ErrServerClosed {
				slog.Error("IMDS server failed", "error", err)
			}
		}()
		l.server = server
		l.profile = profile
		l.sandbox.SetIMDSEndpoint(server.Endpoint())
	}
	return nil
}

// endpoint returns the running server's URL, or "" when no server is running.
func (l *imdsLifecycle) endpoint() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.server == nil {
		return ""
	}
	return l.server.Endpoint()
}

// stop shuts down the IMDS server if one is running.
func (l *imdsLifecycle) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.server != nil {
		l.stopLocked()
	}
}

// stopLocked shuts down the running server and clears the sandbox endpoint so
// commands stop receiving AWS_EC2_METADATA_SERVICE_ENDPOINT. l.mu must be held.
func (l *imdsLifecycle) stopLocked() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.server.Shutdown(shutdownCtx); err != nil {
		slog.Error("failed to shutdown IMDS server", "error", err)
	}
	l.server = nil
	l.profile = ""
	l.sandbox.SetIMDSEndpoint("")
}
