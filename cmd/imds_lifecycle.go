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

// imdsLifecycle owns the pool of IMDS servers on behalf of a long-running
// command (serve-mcp, shell) so startup and config reloads share one
// reconciliation path. In IMDS mode it runs one server per brokered profile —
// the default force_profile plus any allowed_profiles — starting and stopping
// servers as the resolved set changes. The sandbox is kept in sync: the default
// profile's endpoint/region drive the base command environment, and the full
// profile→{endpoint,region} table drives per-command AWS_PROFILE routing.
type imdsLifecycle struct {
	mu      sync.Mutex
	sandbox *bash_sandboxed.Sandbox
	// servers maps each brokered profile name to its running server.
	servers map[string]*imds.Server
	// defProfile is the default profile (force_profile) whose endpoint/region
	// seed the base environment for commands that select no AWS_PROFILE.
	defProfile string
}

// apply reconciles the running IMDS servers with the AWS config resolved for the
// working directory (see Config.ForDirectory). It starts a server for every
// desired profile not yet running and stops any running server no longer
// desired, then republishes routing state to the sandbox. It returns an error
// only when a server that should be running could not be created; stopping is
// best-effort.
func (l *imdsLifecycle) apply(awsCfg *config.AWSConfig) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.servers == nil {
		l.servers = map[string]*imds.Server{}
	}
	// Always republish so the sandbox routing table reflects the actual server
	// pool, even if a NewServer below fails partway through reconciliation.
	defer l.publishLocked()

	desired := awsCfg != nil && awsCfg.UsesIMDS()
	var profiles []string
	l.defProfile = ""
	if desired {
		profiles = awsCfg.IMDSProfiles()
		l.defProfile = awsCfg.IMDSProfile()
	}
	want := make(map[string]bool, len(profiles))
	for _, p := range profiles {
		want[p] = true
	}

	// Stop servers for profiles no longer desired.
	for p, srv := range l.servers {
		if !want[p] {
			slog.Info("stopping IMDS server", "profile", p)
			l.shutdown(srv)
			delete(l.servers, p)
		}
	}

	// Start servers for newly desired profiles.
	for _, p := range profiles {
		if l.servers[p] != nil {
			continue
		}
		server, err := imds.NewServer("127.0.0.1:0", p)
		if err != nil {
			return fmt.Errorf("failed to create IMDS server for profile %q: %w", p, err)
		}
		go func(server *imds.Server, profile string) {
			slog.Info("IMDS server endpoint", "profile", profile, "url", server.Endpoint())
			if err := server.Start(); err != nil && err != http.ErrServerClosed {
				slog.Error("IMDS server failed", "profile", profile, "error", err)
			}
		}(server, p)
		l.servers[p] = server
	}

	return nil
}

// publishLocked pushes the current server pool to the sandbox: the default
// profile's endpoint/region (base environment) and the full per-profile routing
// table. l.mu must be held. Each profile's region is resolved on the host (where
// ~/.aws is readable) and cached by the server, so repeated publishes are cheap.
func (l *imdsLifecycle) publishLocked() {
	if len(l.servers) == 0 {
		l.sandbox.SetIMDSEndpoint("")
		l.sandbox.SetIMDSRegion("")
		l.sandbox.SetIMDSProfiles(nil)
		return
	}

	targets := make(map[string]bash_sandboxed.IMDSTarget, len(l.servers))
	for p, srv := range l.servers {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		region := srv.Region(ctx)
		cancel()
		targets[p] = bash_sandboxed.IMDSTarget{Endpoint: srv.Endpoint(), Region: region}
	}

	def := targets[l.defProfile]
	l.sandbox.SetIMDSEndpoint(def.Endpoint)
	l.sandbox.SetIMDSRegion(def.Region)
	l.sandbox.SetIMDSProfiles(targets)
}

// endpoint returns the default profile's server URL, or "" when no server is
// running. Used by the interactive shell to seed its own process environment.
func (l *imdsLifecycle) endpoint() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if srv := l.servers[l.defProfile]; srv != nil {
		return srv.Endpoint()
	}
	return ""
}

// stop shuts down every running IMDS server and clears the sandbox routing state.
func (l *imdsLifecycle) stop() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for p, srv := range l.servers {
		l.shutdown(srv)
		delete(l.servers, p)
	}
	l.defProfile = ""
	l.sandbox.SetIMDSEndpoint("")
	l.sandbox.SetIMDSRegion("")
	l.sandbox.SetIMDSProfiles(nil)
}

// shutdown gracefully stops one server. l.mu must be held.
func (l *imdsLifecycle) shutdown(srv *imds.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		slog.Error("failed to shutdown IMDS server", "error", err)
	}
}
