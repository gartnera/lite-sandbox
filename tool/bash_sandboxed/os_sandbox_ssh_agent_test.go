package bash_sandboxed

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/sshagent"
)

// TestOSSandboxSSHAgent: with an ssh section, ssh and git's remote commands
// reach the agent, through the restricted proxy, in a worker of their own;
// local git and every other program reach neither the proxy nor the real
// agent, in allowlist mode (home hidden) and denylist mode (home visible,
// sockets masked).
func TestOSSandboxSSHAgent(t *testing.T) {
	requireOSSandbox(t)
	if runtime.GOOS != "linux" {
		t.Skip("checked on the bubblewrap backend")
	}
	for _, bin := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	for _, mode := range []config.Mode{config.ModeAllowlist, config.ModeDenylist} {
		t.Run(string(mode), func(t *testing.T) { testOSSandboxSSHAgent(t, mode) })
	}
}

func testOSSandboxSSHAgent(t *testing.T, mode config.Mode) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	// The sockets live under $HOME, which denylist mode leaves visible, so
	// only the masks keep them from the shared worker there.
	root, err := os.MkdirTemp(home, "ls-ssh-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	agentSock := filepath.Join(root, "agent.sock")
	agent := exec.Command("ssh-agent", "-D", "-a", agentSock)
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agent.Process.Kill(); agent.Wait() })
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(agentSock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	key := filepath.Join(root, "id")
	for _, c := range [][]string{
		{"ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sandbox-test-key", "-f", key},
		{"ssh-add", "-q", key},
	} {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+agentSock)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", c, err, out)
		}
	}
	os.Remove(key)

	proxy, err := sshagent.Start(root, agentSock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.Close() })

	// Stand-ins for ssh and git, outside anything sandboxed commands can
	// write: they show which agent they reach, and try to empty it.
	bin := t.TempDir()
	script := "#!/bin/sh\necho \"sock=$SSH_AUTH_SOCK\"\nssh-add -l\nssh-add -D >/dev/null 2>&1 && echo EMPTIED\nexit 0\n"
	for _, name := range []string{"ssh", "git"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("SSH_AUTH_SOCK", agentSock)

	work := t.TempDir()
	yes := true
	s := NewSandbox()
	s.SetSSHAgent(proxy, agentSock)
	s.updateConfig(&config.Config{
		Mode:      string(mode),
		OSSandbox: &yes,
		SSH:       &config.SSHConfig{Hosts: []string{"box"}},
		Commands:  []config.CommandEntry{{Command: "bash", Allow: &yes}}, // stands in for a program the agent runs
		// The stand-ins' directory, which the worker's own /tmp would hide.
		Paths: []config.PathEntry{{Path: bin, Read: &yes, Internal: true}},
	}, work)
	defer s.Close()
	paths := []string{work}
	run := func(cmd string) string {
		out, err := s.Execute(context.Background(), cmd, work, paths, paths)
		if err != nil {
			out += "\nerror: " + err.Error()
		}
		return out
	}

	for _, cmd := range []string{"ssh box", "git fetch origin"} {
		out := run(cmd)
		if !strings.Contains(out, "sock="+proxy.Socket()) || !strings.Contains(out, "sandbox-test-key") {
			t.Errorf("%s did not reach the agent through the proxy: %q", cmd, out)
		}
		if strings.Contains(out, "EMPTIED") {
			t.Errorf("%s emptied the agent through the proxy", cmd)
		}
	}
	for _, cmd := range []string{
		"git status",
		"bash -c 'ssh-add -l'",
		"bash -c 'SSH_AUTH_SOCK=" + proxy.Socket() + " ssh-add -l'",
		"bash -c 'SSH_AUTH_SOCK=" + agentSock + " ssh-add -l'",
		"bash -c 'ssh box'", // not a direct invocation: runs in the shared worker
	} {
		if out := run(cmd); strings.Contains(out, "sandbox-test-key") || strings.Contains(out, "EMPTIED") {
			t.Errorf("%s reached the agent from the shared worker: %q", cmd, out)
		}
	}
	list := exec.Command("ssh-add", "-l")
	list.Env = append(os.Environ(), "SSH_AUTH_SOCK="+agentSock)
	if out, err := list.CombinedOutput(); err != nil || !strings.Contains(string(out), "sandbox-test-key") {
		t.Errorf("the agent lost its key: %v %s", err, out)
	}
}

// startTestAgent runs a real ssh-agent under root holding one fresh ed25519
// key, and returns its socket and the key's public half.
func startTestAgent(t *testing.T, root string) (sock, pub string) {
	t.Helper()
	sock = filepath.Join(root, "agent.sock")
	agent := exec.Command("ssh-agent", "-D", "-a", sock)
	if err := agent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { agent.Process.Kill(); agent.Wait() })
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	key := filepath.Join(root, "id")
	for _, c := range [][]string{
		{"ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "sandbox-test-key", "-f", key},
		{"ssh-add", "-q", key},
	} {
		cmd := exec.Command(c[0], c[1:]...)
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", c, err, out)
		}
	}
	os.Remove(key)
	return sock, key + ".pub"
}

// TestOSSandboxGitSigning: with git_signing, git commit signs with the agent
// through the proxy, with the signing program pinned to the user's own, so a
// gpg.ssh.program planted in .git/config does not run; without it, the
// commit cannot reach the agent.
func TestOSSandboxGitSigning(t *testing.T) {
	requireOSSandbox(t)
	if runtime.GOOS != "linux" {
		t.Skip("checked on the bubblewrap backend")
	}
	for _, bin := range []string{"ssh-agent", "ssh-add", "ssh-keygen", "git"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(home, "ls-sign-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	agentSock, pub := startTestAgent(t, root)
	proxy, err := sshagent.Start(root, agentSock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { proxy.Close() })

	global := filepath.Join(root, "gitconfig")
	if err := os.WriteFile(global, []byte("[user]\n\tname = T\n\temail = t@example.com\n\tsigningkey = "+pub+
		"\n[gpg]\n\tformat = ssh\n[commit]\n\tgpgsign = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", global)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("SSH_AUTH_SOCK", agentSock)

	work := t.TempDir()
	if out, err := exec.Command("git", "-C", work, "init", "-q").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, out)
	}
	// A planted signing program, which must not run.
	planted := filepath.Join(work, "planted.sh")
	os.WriteFile(planted, []byte("#!/bin/sh\ntouch "+filepath.Join(work, "PWNED")+"\nexit 1\n"), 0o755)
	if out, err := exec.Command("git", "-C", work, "config", "gpg.ssh.program", planted).CombinedOutput(); err != nil {
		t.Fatalf("git config: %v\n%s", err, out)
	}

	yes := true
	newSandbox := func(signing bool) *Sandbox {
		s := NewSandbox()
		s.SetSSHAgent(proxy, agentSock)
		ssh := &config.SSHConfig{}
		if signing {
			ssh.GitSigning = &yes
		}
		s.updateConfig(&config.Config{
			OSSandbox: &yes,
			SSH:       ssh,
			// The global config and the key's public half, which the
			// hidden home would hide.
			Paths: []config.PathEntry{{Path: root, Read: &yes, Internal: true}},
		}, work)
		t.Cleanup(func() { s.Close() })
		return s
	}
	paths := []string{work}

	off := newSandbox(false)
	if out, err := off.Execute(context.Background(), "git commit -q --allow-empty -m unsigned", work, paths, paths); err == nil {
		t.Errorf("a signing commit without git_signing succeeded: %s", out)
	}

	// The shared worker runs the planted program, as it runs any program the
	// project's .git names, but without the agent. Not the signing worker:
	os.Remove(filepath.Join(work, "PWNED"))
	on := newSandbox(true)
	if out, err := on.Execute(context.Background(), "git commit -q --allow-empty -m signed", work, paths, paths); err != nil {
		t.Fatalf("git commit with git_signing: %v\n%s", err, out)
	}
	commit, err := exec.Command("git", "-C", work, "cat-file", "commit", "HEAD").CombinedOutput()
	if err != nil || !strings.Contains(string(commit), "-----BEGIN SSH SIGNATURE-----") {
		t.Errorf("HEAD is not ssh-signed: %v\n%s", err, commit)
	}
	if _, err := os.Stat(filepath.Join(work, "PWNED")); err == nil {
		t.Error("the planted gpg.ssh.program ran")
	}
}
