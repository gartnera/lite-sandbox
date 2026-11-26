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
	out, _ := s.Execute(context.Background(), `true && printenv INCUS_SOCKET LXD_SOCKET INCUS_CONF LXD_CONF; printenv INCUS_DIR || echo no-dir`, tmpDir, []string{tmpDir}, []string{tmpDir})
	for _, want := range []string{sock, "/tmp/ls-incus-test/incus-conf", "/tmp/ls-incus-test/lxc-conf", "no-dir"} {
		if !strings.Contains(out, want) {
			t.Errorf("sandboxed command env: want %q in %q", want, out)
		}
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
	socketDir := filepath.Join(base, "proxy")
	key := filepath.Join(base, "client.key")
	upstream := filepath.Join(base, "upstream.sock")
	for _, d := range []string{daemonDir, socketDir} {
		os.MkdirAll(d, 0o700)
	}
	os.WriteFile(key, []byte("k"), 0o600)
	os.WriteFile(upstream, nil, 0o600)

	s := NewSandbox()
	cfg := &config.Config{}
	s.updateConfig(cfg, base)
	s.SetIncusSocket(filepath.Join(socketDir, "incus.sock"), socketDir, IncusMasks{
		Sockets:  []string{upstream, filepath.Join(base, "missing.sock")},
		Dirs:     []string{daemonDir},
		ReadDeny: []string{key, filepath.Join(base, "missing.key")},
	})
	opts := s.workerOptions(s.getConfig())
	if !slices.Contains(opts.ExtraBinds, socketDir) {
		t.Errorf("socket dir not bound: %v", opts.ExtraBinds)
	}
	if !slices.Contains(opts.MaskPaths, upstream) || slices.Contains(opts.MaskPaths, filepath.Join(base, "missing.sock")) {
		t.Errorf("mask paths %v: want the existing upstream socket only", opts.MaskPaths)
	}
	if !slices.Contains(opts.MaskDirs, daemonDir) {
		t.Errorf("daemon dir not masked: %v", opts.MaskDirs)
	}
	var denied []string
	for _, d := range opts.DeniedReadPaths {
		denied = append(denied, d.Path)
	}
	if !slices.Contains(denied, key) || slices.Contains(denied, filepath.Join(base, "missing.key")) {
		t.Errorf("denied reads %v: want the existing client key only", denied)
	}

	// Without the proxy nothing incus-related is added.
	s.SetIncusSocket("", "", IncusMasks{})
	opts = s.workerOptions(s.getConfig())
	if slices.Contains(opts.MaskDirs, daemonDir) || slices.Contains(opts.ExtraBinds, socketDir) {
		t.Errorf("incus masks applied without the proxy: %+v", opts)
	}
}
