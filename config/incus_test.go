package config

import (
	"path/filepath"
	"testing"
)

func TestIncusDefaults(t *testing.T) {
	var nilCfg *IncusConfig
	if nilCfg.IncusEnabled() || nilCfg.AllowsPrivileged() || nilCfg.AllowsNesting() || nilCfg.AllowsUnsandboxed() {
		t.Error("nil incus config enables something")
	}
	c := &IncusConfig{}
	if !c.RequiresTag() {
		t.Error("tagged_only should default to true")
	}
	if c.ProjectName() != "default" {
		t.Errorf("project = %q, want default", c.ProjectName())
	}
	f := false
	c.TaggedOnly = &f
	if c.RequiresTag() {
		t.Error("tagged_only: false not honored")
	}
}

func TestDetectIncusSocket(t *testing.T) {
	for _, v := range []string{"INCUS_SOCKET", "INCUS_DIR", "LXD_SOCKET", "LXD_DIR"} {
		t.Setenv(v, "")
	}
	t.Setenv("LXD_DIR", "/lxd")
	if got := DetectIncusSocket(); got != filepath.Join("/lxd", "unix.socket") {
		t.Errorf("LXD_DIR: got %q", got)
	}
	t.Setenv("INCUS_DIR", "/incus")
	if got := DetectIncusSocket(); got != "/incus/unix.socket" {
		t.Errorf("INCUS_DIR wins over LXD_DIR: got %q", got)
	}
	t.Setenv("INCUS_SOCKET", "/x.sock")
	if got := DetectIncusSocket(); got != "/x.sock" {
		t.Errorf("INCUS_SOCKET: got %q", got)
	}
	if got := (&IncusConfig{SocketPath: "/explicit.sock"}).UpstreamSocket(); got != "/explicit.sock" {
		t.Errorf("socket_path: got %q", got)
	}
}
