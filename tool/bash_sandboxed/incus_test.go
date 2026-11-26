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

func TestValidate_IncusRequiresProxy(t *testing.T) {
	yes := true
	for _, cmd := range []string{"incus list", "lxc list"} {
		s := NewSandbox()
		f, err := ParseBash(cmd)
		if err != nil {
			t.Fatal(err)
		}
		s.updateConfig(&config.Config{}, "")
		if err := s.validate(f); err == nil {
			t.Fatalf("%s: allowed with incus disabled", cmd)
		}
		s.updateConfig(&config.Config{Incus: &config.IncusConfig{Enabled: &yes}}, "")
		if err := s.validate(f); err == nil || !strings.Contains(err.Error(), "without the OS sandbox") {
			t.Fatalf("%s: expected OS-sandbox requirement, got %v", cmd, err)
		}
		s.updateConfig(&config.Config{OSSandbox: &yes, Incus: &config.IncusConfig{Enabled: &yes}}, "")
		if err := s.validate(f); err == nil || !strings.Contains(err.Error(), "incus proxy is not running") {
			t.Fatalf("%s: expected proxy-not-running rejection, got %v", cmd, err)
		}
		s.SetIncusSocket("/tmp/x/incus.sock", "/tmp/x", IncusMasks{})
		if err := s.validate(f); err != nil {
			t.Fatalf("%s: expected allowed once the proxy runs, got %v", cmd, err)
		}
		s.updateConfig(&config.Config{Incus: &config.IncusConfig{Enabled: &yes, AllowUnsandboxed: &yes}}, "")
		if err := s.validate(f); err != nil {
			t.Fatalf("%s: expected allowed with allow_unsandboxed, got %v", cmd, err)
		}
	}
}

func TestIncusEnvInjection(t *testing.T) {
	t.Setenv("INCUS_DIR", "/var/lib/incus")
	tmpDir := t.TempDir()
	const sock = "/tmp/ls-incus-test/incus.sock"

	s := NewSandbox()
	s.updateConfig(&config.Config{ExtraCommands: []string{"printenv"}}, tmpDir)
	s.SetIncusSocket(sock, "/tmp/ls-incus-test", IncusMasks{})
	// One name per printenv: BSD printenv (macOS) prints only its first operand.
	for name, want := range map[string]string{
		"INCUS_SOCKET": sock,
		"LXD_SOCKET":   sock,
		"INCUS_CONF":   "/tmp/ls-incus-test/incus-conf",
		"LXD_CONF":     "/tmp/ls-incus-test/lxc-conf",
	} {
		out, _ := s.Execute(context.Background(), "true && printenv "+name, tmpDir, []string{tmpDir}, []string{tmpDir})
		if strings.TrimSpace(out) != want {
			t.Errorf("sandboxed command env: %s = %q, want %q", name, strings.TrimSpace(out), want)
		}
	}
	out, _ := s.Execute(context.Background(), `true && printenv INCUS_DIR || echo no-dir`, tmpDir, []string{tmpDir}, []string{tmpDir})
	if !strings.Contains(out, "no-dir") {
		t.Errorf("INCUS_DIR should be removed, got %q", out)
	}

	// Commands allowed with no_sandbox reach the host's own daemon.
	u := NewSandbox()
	u.updateConfig(&config.Config{UnsandboxedCommands: []string{"printenv"}}, tmpDir)
	u.SetIncusSocket(sock, "/tmp/ls-incus-test", IncusMasks{})
	out, _ = u.Execute(context.Background(), `true && printenv INCUS_SOCKET`, tmpDir, []string{tmpDir}, []string{tmpDir})
	if strings.Contains(out, sock) {
		t.Errorf("unsandboxed command saw the proxy socket: %q", out)
	}
}

func TestIncusWorkerOptions(t *testing.T) {
	base := t.TempDir()
	daemonDir := filepath.Join(base, "var-lib-incus")
	clientDir := filepath.Join(base, "config-incus")
	socketDir := filepath.Join(base, "proxy")
	inDir := filepath.Join(daemonDir, "unix.socket") // the default layout
	outside := filepath.Join(base, "colima.sock")
	for _, d := range []string{daemonDir, clientDir, socketDir} {
		os.MkdirAll(d, 0o700)
	}
	os.WriteFile(inDir, nil, 0o600)
	os.WriteFile(outside, nil, 0o600)

	s := NewSandbox()
	s.updateConfig(&config.Config{}, base)
	s.SetIncusSocket(filepath.Join(socketDir, "incus.sock"), socketDir, IncusMasks{
		Sockets: []string{inDir, outside, filepath.Join(base, "missing.sock")},
		Dirs:    []string{daemonDir, clientDir, filepath.Join(base, "missing-dir")},
	})
	opts := s.workerOptions(s.getConfig())
	if !slices.Contains(opts.ExtraBinds, socketDir) {
		t.Errorf("socket dir not bound: %v", opts.ExtraBinds)
	}
	// A socket inside a masked directory is masked with it: bubblewrap
	// cannot bind over a path inside the directory's masking tmpfs.
	if slices.Contains(opts.MaskPaths, inDir) {
		t.Errorf("socket inside a masked directory also masked on its own: %v", opts.MaskPaths)
	}
	if !slices.Contains(opts.MaskPaths, outside) || slices.Contains(opts.MaskPaths, filepath.Join(base, "missing.sock")) {
		t.Errorf("mask paths %v: want the existing socket outside the masked directories only", opts.MaskPaths)
	}
	if !slices.Contains(opts.MaskDirs, daemonDir) || !slices.Contains(opts.MaskDirs, clientDir) {
		t.Errorf("daemon and client config dirs not masked: %v", opts.MaskDirs)
	}

	// Without the proxy nothing incus-related is added.
	s.SetIncusSocket("", "", IncusMasks{})
	opts = s.workerOptions(s.getConfig())
	if slices.Contains(opts.MaskDirs, daemonDir) || slices.Contains(opts.ExtraBinds, socketDir) {
		t.Errorf("incus masks applied without the proxy: %+v", opts)
	}
}

func TestIncusArgRoles(t *testing.T) {
	for _, c := range []struct {
		argv            []string
		nonPath, writes []int
	}{
		{[]string{"incus", "exec", "c1", "--cwd", "/root", "--", "cat", "/etc/hostname"}, []int{1, 2, 3, 4, 5, 6, 7}, nil},
		{[]string{"incus", "file", "pull", "c1/etc/hostname", "c1/etc/hosts", "out"}, []int{3, 4}, []int{5}},
		{[]string{"incus", "file", "pull", "-r", "c1/etc", "/tmp/x"}, []int{4}, []int{5}},
		{[]string{"incus", "file", "push", "/etc/hosts", "c1/etc/hosts"}, []int{4}, nil},
		{[]string{"lxc", "export", "c1", "--compression", "none", "b.tar"}, []int{2}, []int{5}},
		{[]string{"incus", "image", "export", "img", "dir"}, []int{3}, []int{4}},
		{[]string{"incus", "list", "/etc"}, nil, nil},
	} {
		nonPath, writes := incusRoles(c.argv)
		for _, i := range c.nonPath {
			if !nonPath[i] {
				t.Errorf("%q: word %d (%q) should be a non-path", c.argv, i, c.argv[i])
			}
		}
		if len(nonPath) != len(c.nonPath) {
			t.Errorf("%q: non-paths %v, want %v", c.argv, nonPath, c.nonPath)
		}
		if !slices.Equal(writes, c.writes) {
			t.Errorf("%q: writes %v, want %v", c.argv, writes, c.writes)
		}
	}
}

func TestIncusPathChecks(t *testing.T) {
	yes := true
	tmpDir := t.TempDir()
	proxyDir := t.TempDir() // the CLI, where installed, creates its config dirs here
	s := NewSandbox()
	s.updateConfig(&config.Config{Incus: &config.IncusConfig{Enabled: &yes, AllowUnsandboxed: &yes}}, tmpDir)
	s.SetIncusSocket(filepath.Join(proxyDir, "incus.sock"), proxyDir, IncusMasks{})
	for cmd, wantRefused := range map[string]bool{
		"incus exec c1 -- cat /etc/hostname":          false,
		"incus exec c1 --cwd /etc -- ls":              false,
		"incus file pull c1/etc/hostname out.txt":     false,
		"incus file pull c1/etc/hostname /etc/passwd": true,
		"lxc export c1 /etc/backup.tar":               true,
	} {
		out, err := s.Execute(context.Background(), cmd, tmpDir, []string{tmpDir}, []string{tmpDir})
		if err != nil {
			out += err.Error()
		}
		refused := strings.Contains(out, "outside allowed") || strings.Contains(out, "not allowed")
		if refused != wantRefused {
			t.Errorf("%s: refused=%v, want %v (%q)", cmd, refused, wantRefused, out)
		}
	}
}
