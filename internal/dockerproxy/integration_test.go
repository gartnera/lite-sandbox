package dockerproxy

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// These tests exercise the proxy against a real Docker daemon by driving the
// actual `docker` CLI through it (CLI -> proxy -> dockerd), exactly as a
// sandboxed command would. They compile always but only run on Linux when
// OS_SANDBOX_TESTS is set — the same gate the OS-sandbox tests use, which CI
// sets on the Linux job (the runner ships a Docker daemon). The Linux guard
// matters because the macOS CI job also sets OS_SANDBOX_TESTS but has no
// daemon. Run locally with:
//
//	OS_SANDBOX_TESTS=1 go test ./internal/dockerproxy/
const integrationImage = "alpine:3"

func requireDockerIntegration(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("docker integration tests run on Linux only")
	}
	if os.Getenv("OS_SANDBOX_TESTS") == "" {
		t.Skip("requires a real Docker daemon; set OS_SANDBOX_TESTS=1 to run (enabled in CI)")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker CLI not found in PATH")
	}
	if _, err := os.Stat("/var/run/docker.sock"); err != nil {
		t.Skipf("docker socket not available: %v", err)
	}
}

// startProxyForCLI starts a proxy in front of the real daemon whose read/write
// boundary is workDir, and returns the DOCKER_HOST value pointing at it.
func startProxyForCLI(t *testing.T, workDir string, allowPriv bool) string {
	t.Helper()
	srv, err := NewServer(t.TempDir(), "/var/run/docker.sock",
		[]string{workDir}, []string{workDir}, workDir, allowPriv)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go srv.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	})
	waitForSocket(t, strings.TrimPrefix(srv.Endpoint(), "unix://"))
	return srv.Endpoint()
}

// dockerCLI runs `docker <args>` against the proxy and returns combined output.
func dockerCLI(t *testing.T, host string, args ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = append(os.Environ(), "DOCKER_HOST="+host)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestIntegration_VersionForwarded(t *testing.T) {
	requireDockerIntegration(t)
	host := startProxyForCLI(t, t.TempDir(), false)

	out, err := dockerCLI(t, host, "version")
	if err != nil {
		t.Fatalf("docker version failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Server:") {
		t.Fatalf("expected server section (daemon reached through proxy), got:\n%s", out)
	}
}

func TestIntegration_RunBindInsideBoundary(t *testing.T) {
	requireDockerIntegration(t)
	workDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(workDir, "marker.txt"), []byte("sandboxed-ok"), 0o644); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	host := startProxyForCLI(t, workDir, false)

	// Bind source == workDir, which is inside the writable boundary, so the
	// proxy must let the create through and the container reads the marker.
	out, err := dockerCLI(t, host, "run", "--rm", "-v", workDir+":/work", integrationImage, "cat", "/work/marker.txt")
	if err != nil {
		t.Fatalf("docker run with in-boundary bind failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "sandboxed-ok") {
		t.Fatalf("expected marker contents in output, got:\n%s", out)
	}
}

func TestIntegration_RunBindOutsideBoundaryRejected(t *testing.T) {
	requireDockerIntegration(t)
	host := startProxyForCLI(t, t.TempDir(), false)

	// /etc is outside the sandbox boundary; the proxy must reject the create
	// before it ever reaches the daemon.
	out, err := dockerCLI(t, host, "run", "--rm", "-v", "/etc:/host", integrationImage, "true")
	if err == nil {
		t.Fatalf("expected docker run to fail for out-of-boundary bind, got success:\n%s", out)
	}
	if !strings.Contains(out, "outside the sandbox boundary") {
		t.Fatalf("expected boundary error, got:\n%s", out)
	}
}

func TestIntegration_RunPrivilegedRejected(t *testing.T) {
	requireDockerIntegration(t)
	host := startProxyForCLI(t, t.TempDir(), false)

	out, err := dockerCLI(t, host, "run", "--rm", "--privileged", integrationImage, "true")
	if err == nil {
		t.Fatalf("expected docker run --privileged to fail, got success:\n%s", out)
	}
	if !strings.Contains(out, "privileged") {
		t.Fatalf("expected privileged error, got:\n%s", out)
	}
}

func TestIntegration_DeniedEndpoint(t *testing.T) {
	requireDockerIntegration(t)
	host := startProxyForCLI(t, t.TempDir(), false)

	// `docker swarm init` hits POST /swarm/init, which is not in the allowlist.
	out, err := dockerCLI(t, host, "swarm", "init")
	if err == nil {
		t.Fatalf("expected docker swarm init to be denied, got success:\n%s", out)
	}
	if !strings.Contains(out, "not permitted") {
		t.Fatalf("expected allowlist denial, got:\n%s", out)
	}
}
