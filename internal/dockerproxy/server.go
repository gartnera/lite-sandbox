// Package dockerproxy implements a filtering proxy in front of the Docker
// daemon socket, modeled on the IMDS server in internal/imds. Instead of
// exposing the root-equivalent /var/run/docker.sock to sandboxed commands, it
// listens on its own unix socket (handed to the sandbox via DOCKER_HOST) and
// forwards permitted requests to the real daemon. It rejects privileged
// containers and bind mounts whose host source falls outside the sandbox's
// readable/writable path boundary.
package dockerproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
)

// Server is a filtering reverse proxy that forwards a restricted subset of the
// Docker API from a local unix socket to the real Docker daemon socket.
type Server struct {
	socketPath          string
	upstream            string
	workDir             string
	readPaths           []string
	writePaths          []string
	allowPrivileged     bool
	allowHostNamespaces bool

	listener net.Listener
	server   *http.Server
	proxy    *httputil.ReverseProxy
}

// NewServer creates a Docker proxy that listens on a unix socket inside
// socketDir and forwards permitted requests to the upstream daemon socket.
// readPaths/writePaths define the sandbox boundary used to validate bind-mount
// sources; workDir is used to resolve relative sources. allowHostNamespaces
// permits the host PID and network namespaces without allowing full privileged
// mode. The listening socket is created immediately but requests are not served
// until Start() is called.
func NewServer(socketDir, upstream string, readPaths, writePaths []string, workDir string, allowPrivileged, allowHostNamespaces bool) (*Server, error) {
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create docker proxy socket dir: %w", err)
	}
	socketPath := filepath.Join(socketDir, "docker.sock")

	// Remove any stale socket left by a previous run so Listen does not fail
	// with "address already in use".
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove stale socket: %w", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", socketPath, err)
	}

	s := &Server{
		socketPath:          socketPath,
		upstream:            upstream,
		workDir:             workDir,
		readPaths:           readPaths,
		writePaths:          writePaths,
		allowPrivileged:     allowPrivileged,
		allowHostNamespaces: allowHostNamespaces,
		listener:            listener,
	}

	// The reverse proxy dials the real daemon socket regardless of the request
	// URL host; Rewrite normalizes the outbound URL so net/http accepts it.
	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", upstream)
		},
	}
	s.proxy = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = "docker"
		},
	}

	return s, nil
}

// Endpoint returns the DOCKER_HOST value pointing at the proxy socket.
func (s *Server) Endpoint() string {
	return "unix://" + s.socketPath
}

// SocketDir returns the directory containing the proxy socket. It must be made
// visible inside the OS sandbox (bind mount) so the worker can connect.
func (s *Server) SocketDir() string {
	return filepath.Dir(s.socketPath)
}

// Start serves requests until the server is shut down. It blocks.
func (s *Server) Start() error {
	s.server = &http.Server{Handler: http.HandlerFunc(s.handle)}
	slog.Info("starting docker proxy", "socket", s.socketPath, "upstream", s.upstream)
	return s.server.Serve(s.listener)
}

// Shutdown gracefully stops the server and removes the socket file.
func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	if s.server != nil {
		err = s.server.Shutdown(ctx)
	}
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
	return err
}

// handle applies the allowlist and body policy, then forwards permitted
// requests to the daemon via the reverse proxy.
func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if !isAllowed(r.Method, r.URL.Path) {
		slog.Warn("docker proxy denied request", "method", r.Method, "path", r.URL.Path)
		writeDockerError(w, http.StatusForbidden,
			fmt.Sprintf("%s %s is not permitted by the lite-sandbox docker proxy", r.Method, r.URL.Path))
		return
	}

	// Body-inspected endpoints (create container, exec, create volume) share one
	// read-and-restore path; the matched validator enforces the policy.
	if validate := s.bodyInspector(r.Method, r.URL.Path); validate != nil {
		if err := s.inspectBody(r, validate); err != nil {
			slog.Warn("docker proxy rejected request", "method", r.Method, "path", r.URL.Path, "error", err)
			writeDockerError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	// Build requests carry their namespace mode as a query parameter rather than
	// a JSON body, so check it here (mirrors the container-create namespace rule).
	if isBuild(r.Method, r.URL.Path) && !s.allowPrivileged {
		if mode := r.URL.Query().Get("networkmode"); namespaceForbidden(mode, s.allowHostNamespaces) {
			slog.Warn("docker proxy rejected build", "networkmode", mode)
			writeDockerError(w, http.StatusForbidden,
				fmt.Sprintf("build with network namespace mode %q is not allowed in the sandbox", mode))
			return
		}
	}

	s.proxy.ServeHTTP(w, r)
}

// bodyInspector returns the validator for endpoints whose request body must be
// inspected, or nil when the endpoint needs no body inspection.
func (s *Server) bodyInspector(method, path string) func([]byte) error {
	switch {
	case isContainerCreate(method, path):
		return func(b []byte) error {
			return validateCreateBody(b, s.workDir, s.readPaths, s.writePaths, s.allowPrivileged, s.allowHostNamespaces)
		}
	case isExecCreate(method, path):
		return func(b []byte) error { return validateExecBody(b, s.allowPrivileged) }
	case isVolumeCreate(method, path):
		return func(b []byte) error {
			return validateVolumeCreateBody(b, s.workDir, s.readPaths, s.writePaths)
		}
	}
	return nil
}

// inspectBody reads, validates, and restores the request body so it can be
// forwarded unchanged once it passes policy.
func (s *Server) inspectBody(r *http.Request, validate func([]byte) error) error {
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return fmt.Errorf("failed to read request body: %v", err)
	}
	// Restore the body for the downstream proxy regardless of the outcome.
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	return validate(body)
}

// writeDockerError emits an error in the shape the Docker CLI expects so it is
// surfaced cleanly (e.g. "Error response from daemon: <message>").
func writeDockerError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}
