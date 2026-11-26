// Package incusproxy implements a filtering proxy in front of an Incus (or
// LXD) daemon's unix socket, modeled on internal/dockerproxy. The daemon's
// local socket grants full, root-equivalent control of the host, so instead
// of exposing it the proxy listens on its own socket (handed to the incus and
// lxc CLIs via INCUS_SOCKET / LXD_SOCKET) and forwards a restricted subset of
// the REST API:
//
//   - every request is pinned to one project;
//   - only the endpoints in routes.go are reachable;
//   - instance and profile configuration is held to the defaults of an Incus
//     restricted project (no privileged containers, no low-level options, no
//     passthrough devices), and host-path disk devices to the sandbox's path
//     boundary (policy.go);
//   - in tagged-only mode, only instances created through the proxy (tagged
//     user.lite-sandbox=true) can be reached.
package incusproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Options configures a Server.
type Options struct {
	// SocketDir is the directory the proxy's socket is created in.
	SocketDir string
	// Upstream is the daemon's unix socket.
	Upstream string
	// Project is the project every request is pinned to ("default" if empty).
	Project string
	// TagKey, when non-empty, enables tagged-only mode with this config key.
	TagKey string
	Policy Policy
}

// Server is the filtering reverse proxy.
type Server struct {
	opts       Options
	socketPath string
	listener   net.Listener
	server     *http.Server
	proxy      *httputil.ReverseProxy
	client     *http.Client
}

// maxBody bounds the JSON request bodies the proxy reads to inspect.
const maxBody = 8 << 20

// NewServer creates the proxy and its listening socket (incus.sock in
// opts.SocketDir); requests are served once Start is called.
func NewServer(opts Options) (*Server, error) {
	if opts.Project == "" {
		opts.Project = "default"
	}
	if err := os.MkdirAll(opts.SocketDir, 0o700); err != nil {
		return nil, fmt.Errorf("failed to create incus proxy socket dir: %w", err)
	}
	socketPath := filepath.Join(opts.SocketDir, "incus.sock")
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to remove stale socket: %w", err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", socketPath, err)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", opts.Upstream)
		},
	}
	s := &Server{
		opts:       opts,
		socketPath: socketPath,
		listener:   listener,
		client:     &http.Client{Transport: transport},
	}
	s.proxy = &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = "unix.socket"
			pr.Out.Host = "unix.socket"
		},
		// Event streams and operation waits must not be buffered.
		FlushInterval: -1,
	}
	return s, nil
}

// SocketPath returns the proxy's socket (the INCUS_SOCKET / LXD_SOCKET value).
func (s *Server) SocketPath() string { return s.socketPath }

// SocketDir returns the directory holding the socket, which the OS sandbox
// worker must bind to reach it.
func (s *Server) SocketDir() string { return filepath.Dir(s.socketPath) }

// Start serves requests until Shutdown. It blocks.
func (s *Server) Start() error {
	s.server = &http.Server{Handler: http.HandlerFunc(s.handle)}
	slog.Info("starting incus proxy", "socket", s.socketPath, "upstream", s.opts.Upstream, "project", s.opts.Project, "tagged_only", s.opts.TagKey != "")
	return s.server.Serve(s.listener)
}

// Shutdown stops the server and removes the socket file.
func (s *Server) Shutdown(ctx context.Context) error {
	var err error
	if s.server != nil {
		err = s.server.Shutdown(ctx)
	}
	s.listener.Close()
	os.Remove(s.socketPath)
	return err
}

// denied is a policy refusal, reported to the client as 403.
type denied struct{ msg string }

func (d *denied) Error() string { return d.msg }

func deny(format string, args ...any) error { return &denied{fmt.Sprintf(format, args...)} }

func (s *Server) handle(w http.ResponseWriter, req *http.Request) {
	err := s.serve(w, req)
	if err == nil {
		return
	}
	status := http.StatusBadGateway
	var d *denied
	if errors.As(err, &d) {
		status = http.StatusForbidden
		slog.Warn("incus proxy denied request", "method", req.Method, "path", req.URL.Path, "reason", d.msg)
	} else {
		slog.Error("incus proxy request failed", "method", req.Method, "path", req.URL.Path, "error", err)
	}
	writeError(w, status, err.Error())
}

func (s *Server) serve(w http.ResponseWriter, req *http.Request) error {
	segs, err := splitPath(req.URL.EscapedPath())
	if err != nil {
		return err
	}
	if segs == nil { // GET / (the API version list)
		if req.Method != http.MethodGet {
			return deny("%s / is not permitted by the lite-sandbox incus proxy", req.Method)
		}
		s.proxy.ServeHTTP(w, req)
		return nil
	}
	rt, ok := match(req.Method, segs)
	if !ok {
		return deny("%s %s is not permitted by the lite-sandbox incus proxy", req.Method, req.URL.Path)
	}
	if err := s.pinProject(req); err != nil {
		return err
	}

	tagged := s.opts.TagKey != ""
	switch rt.kind {
	case instanceScoped:
		if _, err := s.requireInstance(req.Context(), segs[1]); err != nil {
			return err
		}
	case instanceList:
		if tagged {
			return s.serveInstanceList(w, req)
		}
	case instanceCreate:
		if err := s.checkInstanceCreate(req); err != nil {
			return err
		}
	case instanceUpdate:
		if err := s.checkInstanceUpdate(req, segs[1]); err != nil {
			return err
		}
	case instanceRename:
		if err := s.checkInstanceRename(req, segs[1]); err != nil {
			return err
		}
	case snapshotRename:
		if err := s.checkSnapshotRename(req, segs[1]); err != nil {
			return err
		}
	case instanceRebuild:
		if err := s.checkRebuild(req, segs[1]); err != nil {
			return err
		}
	case imageCreate:
		if err := s.checkImageCreate(req); err != nil {
			return err
		}
	case profileCreate, profileUpdate, profileOther:
		if tagged {
			return deny("profiles are shared with instances the sandbox did not create, so they cannot be changed in tagged-only mode")
		}
		if rt.kind == profileCreate {
			if err := s.checkProfileCreate(req); err != nil {
				return err
			}
		} else if rt.kind == profileUpdate {
			if err := s.checkProfileUpdate(req, segs[1]); err != nil {
				return err
			}
		}
	case volumeCreate:
		if err := s.checkVolumeCreate(req); err != nil {
			return err
		}
	}
	s.proxy.ServeHTTP(w, req)
	return nil
}

// splitPath returns the decoded segments after /1.0 of an escaped request
// path, nil for "/" itself. Paths outside /1.0, and segments that are empty,
// dot-segments, or decode to something containing a slash, are refused, so the
// segments the policy matched are the ones the daemon routes on.
func splitPath(escaped string) ([]string, error) {
	if escaped == "/" || escaped == "" {
		return nil, nil
	}
	rest, ok := strings.CutPrefix(escaped, "/1.0")
	if !ok || (rest != "" && rest[0] != '/') {
		return nil, deny("path %q is not permitted by the lite-sandbox incus proxy", escaped)
	}
	segs := []string{}
	if rest == "" || rest == "/" {
		return segs, nil
	}
	for _, raw := range strings.Split(strings.TrimPrefix(rest, "/"), "/") {
		seg, err := url.PathUnescape(raw)
		if err != nil || seg == "" || seg == "." || seg == ".." || strings.ContainsAny(seg, "/\\") {
			return nil, deny("path %q is not permitted by the lite-sandbox incus proxy", escaped)
		}
		segs = append(segs, seg)
	}
	return segs, nil
}

// pinProject confines the request to the configured project: a request naming
// another project, or every project, is refused, and one naming none is sent
// to the configured project.
func (s *Server) pinProject(req *http.Request) error {
	q := req.URL.Query()
	if v := q.Get("all-projects"); v != "" && !isFalseOrEmpty(v) {
		return deny("requests across all projects are not permitted; the sandbox is confined to project %q", s.opts.Project)
	}
	switch ps := q["project"]; {
	case len(ps) > 1:
		return deny("more than one project parameter")
	case len(ps) == 1 && ps[0] != s.opts.Project:
		return deny("project %q is not permitted; the sandbox is confined to project %q", ps[0], s.opts.Project)
	case len(ps) == 0 && s.opts.Project != "default":
		q.Set("project", s.opts.Project)
		req.URL.RawQuery = q.Encode()
	}
	return nil
}

// checkProject refuses a body field naming a project other than the pinned one.
func (s *Server) checkProject(field, project string) error {
	if project != "" && project != s.opts.Project {
		return deny("%s %q is not permitted; the sandbox is confined to project %q", field, project, s.opts.Project)
	}
	return nil
}

// readJSON reads the request body for inspection, restores it for forwarding,
// and decodes it into v. A body that is not JSON is refused.
func readJSON(req *http.Request, v any) ([]byte, error) {
	if ct := req.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return nil, deny("%s request bodies of type %q are not permitted by the lite-sandbox incus proxy", req.URL.Path, ct)
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
	req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}
	if len(body) > maxBody {
		return nil, deny("request body too large")
	}
	setBody(req, body)
	if err := json.Unmarshal(body, v); err != nil {
		return nil, deny("failed to parse request body: %v", err)
	}
	return body, nil
}

func setBody(req *http.Request, body []byte) {
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.ContentLength = int64(len(body))
	req.Header.Del("Transfer-Encoding")
	req.TransferEncoding = nil
}

// writeError replies in the shape of an Incus error response, which the CLI
// prints as "Error: <message>".
func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type":       "error",
		"error":      msg,
		"error_code": status,
		"metadata":   nil,
	})
}
