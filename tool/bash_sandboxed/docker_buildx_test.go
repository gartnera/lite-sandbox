package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// TestWorkerOptions_BuildxDir: with the docker proxy running, the worker binds
// the buildx state directory writable but keeps the builder definitions
// read-only, in both modes; without the proxy it binds neither.
func TestWorkerOptions_BuildxDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BUILDX_CONFIG", "")
	t.Setenv("DOCKER_CONFIG", "")
	buildx := filepath.Join(home, ".docker", "buildx")
	yes := true

	for _, mode := range []string{"allowlist", "denylist"} {
		t.Run(mode, func(t *testing.T) {
			s := NewSandbox()
			s.updateConfig(&config.Config{Mode: mode, OSSandbox: &yes}, t.TempDir())

			opts := s.workerOptions(s.getConfig())
			if slices.Contains(opts.ExtraBinds, buildx) {
				t.Errorf("buildx dir bound without the docker proxy: %v", opts.ExtraBinds)
			}

			s.SetDockerHost("unix:///tmp/x/docker.sock", "/tmp/x", "/var/run/docker.sock")
			opts = s.workerOptions(s.getConfig())
			if !slices.Contains(opts.ExtraBinds, buildx) {
				t.Errorf("buildx dir not bound: %v", opts.ExtraBinds)
			}
			if info, err := os.Stat(buildx); err != nil || !info.IsDir() {
				t.Errorf("buildx dir not created: %v", err)
			}
			for _, name := range []string{"instances", "defaults", "current"} {
				if !denyHas(opts.DeniedWritePaths, filepath.Join(buildx, name)) {
					t.Errorf("%s not write-denied: %v", name, opts.DeniedWritePaths)
				}
			}
		})
	}
}

// TestOSSandboxBuildxDir: a build's buildx writes (the last-activity stamp)
// reach the host, while a builder definition cannot be planted.
func TestOSSandboxBuildxDir(t *testing.T) {
	requireOSSandbox(t)
	home := newFakeHome(t)
	t.Setenv("BUILDX_CONFIG", "")
	t.Setenv("DOCKER_CONFIG", "")
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(home, ".config", "lite-sandbox", "config.yaml"))
	buildx := filepath.Join(home, ".docker", "buildx")
	workDir := filepath.Join(home, "proj")
	if err := os.Mkdir(workDir, 0o755); err != nil {
		t.Fatal(err)
	}

	yes := true
	s := NewSandbox()
	// perl is allowed past validation so only the OS sandbox decides.
	s.updateConfig(&config.Config{
		OSSandbox: &yes,
		Commands:  []config.CommandEntry{{Command: "perl", Allow: &yes}},
	}, workDir)
	defer s.Close()
	socketDir := filepath.Join(home, "docker-proxy")
	s.SetDockerHost("unix://"+filepath.Join(socketDir, "docker.sock"), socketDir)
	// bwrap can only mask a socket that exists, and a host without docker has
	// no /var/run/docker.sock; the masks are not what is tested here.
	s.dockerMaskPaths = nil
	paths := []string{workDir}
	write := func(rel string) string {
		out, err := s.Execute(context.Background(),
			`perl -e 'use File::Path; my $p="`+filepath.Join(buildx, rel)+`"; (my $d=$p) =~ s{/[^/]*$}{}; mkpath($d); open(F,">$p") or die "denied: $!"; print F "x"; close F; print "wrote"'`,
			workDir, paths, paths)
		if err != nil {
			out += err.Error()
		}
		return out
	}

	if out := write("activity/default"); !strings.Contains(out, "wrote") {
		t.Fatalf("activity write should succeed: %q", out)
	}
	if _, err := os.Stat(filepath.Join(buildx, "activity", "default")); err != nil {
		t.Errorf("activity write did not reach the host: %v", err)
	}
	for _, rel := range []string{"instances/evil", "defaults/evil"} {
		if out := write(rel); !osDenied(out) || strings.Contains(out, "wrote") {
			t.Errorf("%s should not be writable, got %q", rel, out)
		}
		if _, err := os.Stat(filepath.Join(buildx, rel)); err == nil {
			t.Errorf("%s was planted through the sandbox", rel)
		}
	}
}
