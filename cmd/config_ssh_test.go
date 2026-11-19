package cmd

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

func TestSSHConfigCommands(t *testing.T) {
	t.Setenv("LITE_SANDBOX_CONFIG", filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { configDir = "" })

	captureStdout(t, func() {
		if err := sshHostsAddCmd.RunE(sshHostsAddCmd, []string{"build-box", "10.0.0.12"}); err != nil {
			t.Fatal(err)
		}
		if err := sshAgentUnrestrictCmd.RunE(sshAgentUnrestrictCmd, nil); err != nil {
			t.Fatal(err)
		}
		if err := sshGitSigningEnableCmd.RunE(sshGitSigningEnableCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if err := sshHostsAddCmd.RunE(sshHostsAddCmd, []string{"me@box"}); err == nil {
		t.Error("user@host accepted")
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SSH.AllowsHost("build-box") || !cfg.SSH.AllowsHost("10.0.0.12") || !cfg.SSH.AgentUnrestricted() {
		t.Fatalf("saved %+v", cfg.SSH)
	}
	out := captureStdout(t, func() {
		if err := sshShowCmd.RunE(sshShowCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "build-box: read-only remote commands") || !strings.Contains(out, "10.0.0.12: read-only remote commands") || !strings.Contains(out, "Agent: unrestricted") || !strings.Contains(out, "Git signing: on") {
		t.Errorf("show: %s", out)
	}

	// --command and --write widen a host's entry, and add to a listed one.
	t.Cleanup(func() { sshHostsAddWrite, sshHostsAddCommands = false, nil })
	captureStdout(t, func() {
		sshHostsAddCommands = []string{"systemctl restart"}
		if err := sshHostsAddCmd.RunE(sshHostsAddCmd, []string{"deploy-box", "10.0.0.12"}); err != nil {
			t.Fatal(err)
		}
		sshHostsAddWrite, sshHostsAddCommands = true, nil
		if err := sshHostsAddCmd.RunE(sshHostsAddCmd, []string{"scratch-vm"}); err != nil {
			t.Fatal(err)
		}
		sshHostsAddWrite = false
	})
	cfg, _ = config.Load()
	if h := cfg.SSH.Host("deploy-box"); h == nil || h.Writes() || len(h.Commands) != 1 || h.Commands[0] != "systemctl restart" {
		t.Errorf("deploy-box: %+v", h)
	}
	if h := cfg.SSH.Host("10.0.0.12"); h == nil || len(h.Commands) != 1 {
		t.Errorf("10.0.0.12 did not take the command: %+v", h)
	}
	if h := cfg.SSH.Host("scratch-vm"); h == nil || !h.Writes() {
		t.Errorf("scratch-vm: %+v", h)
	}
	out = captureStdout(t, func() {
		if err := sshShowCmd.RunE(sshShowCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "deploy-box: read-only remote commands, and systemctl restart") || !strings.Contains(out, "scratch-vm: any remote command; scp and rsync; port forwarding and connection sharing") || !strings.Contains(out, "for ssh, sshpass, scp, rsync, and git's remote commands") {
		t.Errorf("show: %s", out)
	}

	captureStdout(t, func() {
		if err := sshHostsRemoveCmd.RunE(sshHostsRemoveCmd, []string{"build-box"}); err != nil {
			t.Fatal(err)
		}
		if err := sshAgentRestrictCmd.RunE(sshAgentRestrictCmd, nil); err != nil {
			t.Fatal(err)
		}
		if err := sshAgentDisableCmd.RunE(sshAgentDisableCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	cfg, _ = config.Load()
	if cfg.SSH.AllowsHost("build-box") || cfg.SSH.AgentUnrestricted() || cfg.SSH.AgentEnabled() {
		t.Fatalf("saved %+v", cfg.SSH)
	}

	// A scope.
	configDir = "/work/acme"
	captureStdout(t, func() {
		if err := sshHostsAddCmd.RunE(sshHostsAddCmd, []string{"acme-box"}); err != nil {
			t.Fatal(err)
		}
	})
	configDir = ""
	cfg, _ = config.Load()
	if cfg.SSH.AllowsHost("acme-box") || !cfg.ForDirectory("/work/acme").SSH.AllowsHost("acme-box") {
		t.Errorf("scope not scoped: base %+v", cfg.SSH)
	}

	captureStdout(t, func() {
		if err := sshDisableCmd.RunE(sshDisableCmd, nil); err != nil {
			t.Fatal(err)
		}
	})
	if cfg, _ = config.Load(); cfg.SSH != nil {
		t.Errorf("disable left %+v", cfg.SSH)
	}
}
