package dockerproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// shortSocketDir returns a temp directory with a short path, suitable for unix
// socket files. macOS limits a socket's sun_path to ~104 bytes, and
// t.TempDir() paths under /var/folders/... routinely exceed that (yielding
// "bind: invalid argument"), so sockets must live under a short base like /tmp.
func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dp")
	if err != nil {
		t.Fatalf("create socket dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

// fakeDaemon is a minimal upstream Docker daemon that records the last request
// path and replies 200.
type fakeDaemon struct {
	socket   string
	server   *http.Server
	gotPaths []string
}

func startFakeDaemon(t *testing.T) *fakeDaemon {
	t.Helper()
	socket := filepath.Join(shortSocketDir(t), "d.sock")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	fd := &fakeDaemon{socket: socket}
	fd.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fd.gotPaths = append(fd.gotPaths, r.Method+" "+r.URL.Path)
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"ok":true}`)
	})}
	go fd.server.Serve(ln)
	t.Cleanup(func() { fd.server.Close() })
	return fd
}

// newTestProxy starts a proxy in front of fd whose writable boundary is
// writeDir (read boundary is readDir), and returns the proxy plus an http
// client that dials its socket.
func newTestProxy(t *testing.T, fd *fakeDaemon, readDir, writeDir string, allowPriv bool) (*Server, *http.Client) {
	t.Helper()
	srv, err := NewServer(shortSocketDir(t), fd.socket, []string{readDir}, []string{writeDir}, writeDir, allowPriv)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})

	socketPath := strings.TrimPrefix(srv.Endpoint(), "unix://")
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}}
	// Give the server goroutine a moment to begin serving.
	waitForSocket(t, socketPath)
	return srv, client
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 50; i++ {
		c, err := net.Dial("unix", path)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("proxy socket %s never became ready", path)
}

func do(t *testing.T, client *http.Client, method, path string, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, "http://docker"+path, r)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do %s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestProxy_AllowedRequestForwarded(t *testing.T) {
	fd := startFakeDaemon(t)
	dir := t.TempDir()
	_, client := newTestProxy(t, fd, dir, dir, false)

	status, _ := do(t, client, "GET", "/v1.43/version", "")
	if status != http.StatusOK {
		t.Fatalf("expected 200, got %d", status)
	}
	if len(fd.gotPaths) != 1 || !strings.Contains(fd.gotPaths[0], "/version") {
		t.Fatalf("upstream did not receive forwarded request: %v", fd.gotPaths)
	}
}

func TestProxy_DeniedEndpoint(t *testing.T) {
	fd := startFakeDaemon(t)
	dir := t.TempDir()
	_, client := newTestProxy(t, fd, dir, dir, false)

	// /secret is not in the allowlist.
	status, body := do(t, client, "GET", "/v1.43/secret", "")
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", status)
	}
	if !strings.Contains(body, "not permitted") {
		t.Fatalf("unexpected error body: %s", body)
	}
	if len(fd.gotPaths) != 0 {
		t.Fatalf("denied request should not reach upstream: %v", fd.gotPaths)
	}
}

func TestProxy_BindMountInsideBoundaryForwarded(t *testing.T) {
	fd := startFakeDaemon(t)
	writeDir := t.TempDir()
	_, client := newTestProxy(t, fd, writeDir, writeDir, false)

	body := fmt.Sprintf(`{"Image":"alpine","HostConfig":{"Binds":["%s:/work"]}}`, writeDir)
	status, _ := do(t, client, "POST", "/v1.43/containers/create", body)
	if status != http.StatusOK {
		t.Fatalf("expected 200 (forwarded), got %d", status)
	}
	if len(fd.gotPaths) != 1 {
		t.Fatalf("create should be forwarded once: %v", fd.gotPaths)
	}
}

func TestProxy_BindMountOutsideBoundaryRejected(t *testing.T) {
	fd := startFakeDaemon(t)
	writeDir := t.TempDir()
	_, client := newTestProxy(t, fd, writeDir, writeDir, false)

	body := `{"Image":"alpine","HostConfig":{"Binds":["/etc:/etc"]}}`
	status, msg := do(t, client, "POST", "/v1.43/containers/create", body)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", status, msg)
	}
	if !strings.Contains(msg, "outside the sandbox boundary") {
		t.Fatalf("unexpected message: %s", msg)
	}
	if len(fd.gotPaths) != 0 {
		t.Fatalf("rejected create should not reach upstream: %v", fd.gotPaths)
	}
}

func TestProxy_AnonymousVolumeAllowed(t *testing.T) {
	fd := startFakeDaemon(t)
	dir := t.TempDir()
	_, client := newTestProxy(t, fd, dir, dir, false)

	// Named/anonymous volume (non-absolute source) and a tmpfs/volume Mount.
	body := `{"Image":"alpine","HostConfig":{"Binds":["mydata:/data"],"Mounts":[{"Type":"volume","Target":"/cache"}]}}`
	status, _ := do(t, client, "POST", "/v1.43/containers/create", body)
	if status != http.StatusOK {
		t.Fatalf("expected 200 (forwarded), got %d", status)
	}
}

func TestProxy_PrivilegedRejected(t *testing.T) {
	fd := startFakeDaemon(t)
	dir := t.TempDir()
	_, client := newTestProxy(t, fd, dir, dir, false)

	body := `{"Image":"alpine","HostConfig":{"Privileged":true}}`
	status, msg := do(t, client, "POST", "/v1.43/containers/create", body)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", status)
	}
	if !strings.Contains(msg, "privileged") {
		t.Fatalf("unexpected message: %s", msg)
	}
}

func TestProxy_PrivilegedAllowedWhenConfigured(t *testing.T) {
	fd := startFakeDaemon(t)
	dir := t.TempDir()
	_, client := newTestProxy(t, fd, dir, dir, true)

	body := `{"Image":"alpine","HostConfig":{"Privileged":true}}`
	status, _ := do(t, client, "POST", "/v1.43/containers/create", body)
	if status != http.StatusOK {
		t.Fatalf("expected 200 when allow_privileged is set, got %d", status)
	}
}

func TestValidateCreateBody(t *testing.T) {
	readDir := "/srv/read"
	writeDir := "/srv/write"
	read := []string{readDir, writeDir}
	write := []string{writeDir}

	tests := []struct {
		name    string
		body    string
		wantErr string // substring; "" means allowed
	}{
		{"empty", `{}`, ""},
		{"rw bind in write boundary", fmt.Sprintf(`{"HostConfig":{"Binds":["%s/x:/x"]}}`, writeDir), ""},
		{"rw bind only in read boundary", fmt.Sprintf(`{"HostConfig":{"Binds":["%s/x:/x"]}}`, readDir), "outside the sandbox boundary"},
		{"ro bind in read boundary", fmt.Sprintf(`{"HostConfig":{"Binds":["%s/x:/x:ro"]}}`, readDir), ""},
		{"named volume", `{"HostConfig":{"Binds":["vol:/x"]}}`, ""},
		{"mount bind outside", `{"HostConfig":{"Mounts":[{"Type":"bind","Source":"/etc","Target":"/etc"}]}}`, "outside the sandbox boundary"},
		{"mount volume", `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/x"}]}}`, ""},
		{"privileged", `{"HostConfig":{"Privileged":true}}`, "privileged"},
		{"cap-add", `{"HostConfig":{"CapAdd":["SYS_ADMIN"]}}`, "capabilities"},
		{"device", `{"HostConfig":{"Devices":[{"PathOnHost":"/dev/sda"}]}}`, "devices"},
		{"host pid", `{"HostConfig":{"PidMode":"host"}}`, "PID namespace"},
		{"host network", `{"HostConfig":{"NetworkMode":"host"}}`, "network namespace"},
		{"container pid namespace", `{"HostConfig":{"PidMode":"container:abc123"}}`, "PID namespace"},
		{"container network namespace", `{"HostConfig":{"NetworkMode":"container:abc123"}}`, "network namespace"},
		{"seccomp unconfined", `{"HostConfig":{"SecurityOpt":["seccomp=unconfined"]}}`, "security-opt"},
		{"device requests", `{"HostConfig":{"DeviceRequests":[{"Count":-1}]}}`, "host devices"},
		{"device cgroup rules", `{"HostConfig":{"DeviceCgroupRules":["a *:* rwm"]}}`, "device cgroup"},
		{"ambiguous bind colon in source", `{"HostConfig":{"Binds":["/host:dir:/container"]}}`, "ambiguous"},
		{"ambiguous bind four fields", `{"HostConfig":{"Binds":["/a:/b:/c:ro"]}}`, "ambiguous"},
		{"volume driver bind inside boundary", fmt.Sprintf(`{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/x","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"%s/d"}}}}]}}`, writeDir), ""},
		{"volume driver bind outside boundary", `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/x","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"none","o":"bind","device":"/etc"}}}}]}}`, "outside the sandbox boundary"},
		{"volume driver nfs device allowed", `{"HostConfig":{"Mounts":[{"Type":"volume","Target":"/x","VolumeOptions":{"DriverConfig":{"Name":"local","Options":{"type":"nfs","device":":/exports/data","o":"addr=10.0.0.1"}}}}]}}`, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCreateBody([]byte(tc.body), writeDir, read, write, false)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected allowed, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got: %v", tc.wantErr, err)
			}
		})
	}
}

func TestValidateExecBody(t *testing.T) {
	if err := validateExecBody([]byte(`{"Privileged":true}`), false); err == nil || !strings.Contains(err.Error(), "privileged exec") {
		t.Fatalf("expected privileged exec rejection, got: %v", err)
	}
	if err := validateExecBody([]byte(`{"Privileged":false}`), false); err != nil {
		t.Fatalf("expected non-privileged exec allowed, got: %v", err)
	}
	if err := validateExecBody([]byte(`{"Privileged":true}`), true); err != nil {
		t.Fatalf("expected privileged exec allowed when configured, got: %v", err)
	}
}

func TestValidateVolumeCreateBody(t *testing.T) {
	writeDir := "/srv/write"
	read := []string{writeDir}
	write := []string{writeDir}

	// local driver binding a host path outside the boundary must be rejected.
	out := `{"Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/etc"}}`
	if err := validateVolumeCreateBody([]byte(out), writeDir, read, write); err == nil || !strings.Contains(err.Error(), "outside the sandbox boundary") {
		t.Fatalf("expected out-of-boundary volume device rejected, got: %v", err)
	}
	// inside the boundary is allowed.
	in := fmt.Sprintf(`{"Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"%s/d"}}`, writeDir)
	if err := validateVolumeCreateBody([]byte(in), writeDir, read, write); err != nil {
		t.Fatalf("expected in-boundary volume device allowed, got: %v", err)
	}
	// ordinary named volume (no device) is allowed.
	if err := validateVolumeCreateBody([]byte(`{"Name":"data"}`), writeDir, read, write); err != nil {
		t.Fatalf("expected plain named volume allowed, got: %v", err)
	}
}

func TestProxy_ExecPrivilegedRejected(t *testing.T) {
	fd := startFakeDaemon(t)
	dir := t.TempDir()
	_, client := newTestProxy(t, fd, dir, dir, false)

	status, msg := do(t, client, "POST", "/v1.43/containers/abc123/exec", `{"Privileged":true,"Cmd":["sh"]}`)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", status, msg)
	}
	if len(fd.gotPaths) != 0 {
		t.Fatalf("rejected exec should not reach upstream: %v", fd.gotPaths)
	}
}

func TestProxy_VolumeDriverBindOutsideRejected(t *testing.T) {
	fd := startFakeDaemon(t)
	dir := t.TempDir()
	_, client := newTestProxy(t, fd, dir, dir, false)

	body := `{"Driver":"local","DriverOpts":{"type":"none","o":"bind","device":"/etc"}}`
	status, msg := do(t, client, "POST", "/v1.43/volumes/create", body)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", status, msg)
	}
	if len(fd.gotPaths) != 0 {
		t.Fatalf("rejected volume create should not reach upstream: %v", fd.gotPaths)
	}
}

func TestProxy_BuildHostNetworkRejected(t *testing.T) {
	fd := startFakeDaemon(t)
	dir := t.TempDir()
	_, client := newTestProxy(t, fd, dir, dir, false)

	status, msg := do(t, client, "POST", "/v1.43/build?networkmode=host", "")
	if status != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", status, msg)
	}
	if !strings.Contains(msg, "network namespace mode") {
		t.Fatalf("unexpected message: %s", msg)
	}
	if len(fd.gotPaths) != 0 {
		t.Fatalf("rejected build should not reach upstream: %v", fd.gotPaths)
	}
}

func TestProxy_BuildDefaultNetworkForwarded(t *testing.T) {
	fd := startFakeDaemon(t)
	dir := t.TempDir()
	_, client := newTestProxy(t, fd, dir, dir, false)

	status, _ := do(t, client, "POST", "/v1.43/build", "")
	if status != http.StatusOK {
		t.Fatalf("expected build to be forwarded, got %d", status)
	}
	if len(fd.gotPaths) != 1 {
		t.Fatalf("build should reach upstream once: %v", fd.gotPaths)
	}
}

func TestIsAllowed(t *testing.T) {
	allowed := [][2]string{
		{"GET", "/v1.43/version"},
		{"GET", "/version"},
		{"POST", "/v1.43/containers/create"},
		{"POST", "/v1.43/containers/abc123/start"},
		{"DELETE", "/v1.43/containers/abc123"},
		{"GET", "/v1.43/containers/json"},
		{"HEAD", "/_ping"},
		{"POST", "/v1.43/build"},
		{"POST", "/session"},
		{"POST", "/v1.43/grpc"},
	}
	for _, a := range allowed {
		if !isAllowed(a[0], a[1]) {
			t.Errorf("expected allowed: %s %s", a[0], a[1])
		}
	}

	denied := [][2]string{
		{"GET", "/v1.43/secret"},
		{"POST", "/v1.43/containers/abc/commit"},
		{"GET", "/v1.43/containers/abc/json/extra"},
		{"POST", "/swarm/init"},
	}
	for _, d := range denied {
		if isAllowed(d[0], d[1]) {
			t.Errorf("expected denied: %s %s", d[0], d[1])
		}
	}
}

func TestEndpointAndSocketDir(t *testing.T) {
	dir := shortSocketDir(t)
	srv, err := NewServer(dir, "/var/run/docker.sock", nil, nil, dir, false)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Shutdown(context.Background())

	if want := "unix://" + filepath.Join(dir, "docker.sock"); srv.Endpoint() != want {
		t.Errorf("Endpoint() = %q, want %q", srv.Endpoint(), want)
	}
	if srv.SocketDir() != dir {
		t.Errorf("SocketDir() = %q, want %q", srv.SocketDir(), dir)
	}
}

// jsonMessage is a small helper to assert error bodies are valid Docker error
// JSON.
func decodeMessage(t *testing.T, body string) string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("error body is not JSON: %s", body)
	}
	return m["message"]
}

func TestDeniedErrorIsDockerJSON(t *testing.T) {
	fd := startFakeDaemon(t)
	dir := t.TempDir()
	_, client := newTestProxy(t, fd, dir, dir, false)
	_, body := do(t, client, "GET", "/v1.43/secret", "")
	if msg := decodeMessage(t, body); msg == "" {
		t.Fatalf("expected non-empty docker error message, got: %s", body)
	}
}
