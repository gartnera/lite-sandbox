package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

func newTestSandboxWithSSH(hosts ...string) *Sandbox {
	return newTestSandboxWithConfig(&config.Config{SSH: &config.SSHConfig{Hosts: hosts}})
}

func TestValidateSSHCommand(t *testing.T) {
	dir := t.TempDir()
	paths := []string{dir}
	s := newTestSandboxWithSSH("box", "10.0.0.12", "jump", "::1")
	tests := []struct {
		command   string
		errSubstr string // "" when allowed
	}{
		{command: "ssh box"},
		{command: "ssh box uptime"},
		{command: "ssh me@box"},
		{command: "ssh -l me -p 2222 box"},
		{command: "ssh -p2222 BOX"},
		{command: "ssh ssh://me@box:2222"},
		{command: "ssh 10.0.0.12 cat /etc/hostname"},
		{command: "ssh box ls -la /var/log"},
		{command: "ssh box -- ls -A"},
		{command: "ssh -- box ls"},
		{command: "ssh box -p 22 -o BatchMode=yes uptime"},
		{command: "ssh -T -n -q -v -C -4 box true"},
		{command: "ssh -o ConnectTimeout=5 -o 'StrictHostKeyChecking accept-new' box"},
		{command: "ssh -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no box"},
		{command: "ssh -o ForwardAgent=no -o ControlMaster=no -S none -F none box"},
		{command: "ssh -J jump box"},
		{command: "ssh -J me@jump:22,ssh://10.0.0.12 box"},
		{command: "ssh -o ProxyJump=jump box"},
		{command: "ssh ::1"},
		{command: "ssh me@[::1]"},
		{command: "ssh -V"},
		{command: "ssh -Q cipher"},
		{command: "ssh -G box"},
		{command: "ssh -i ./id_test box"},

		{command: "ssh evil", errSubstr: `ssh to "evil" is not allowed`},
		{command: "ssh me@evil uptime", errSubstr: `"evil"`},
		{command: "ssh box.example.com", errSubstr: `"box.example.com"`},
		{command: "ssh ssh://evil:22", errSubstr: `"evil"`},
		{command: "ssh -J evil box", errSubstr: `"evil"`},
		{command: "ssh -J jump,evil box", errSubstr: `"evil"`},
		{command: "ssh -o ProxyJump=evil box", errSubstr: `"evil"`},
		{command: "ssh", errSubstr: "needs a destination"},
		{command: "ssh -p 22", errSubstr: "needs a destination"},
		{command: "ssh -A box", errSubstr: "-A is not allowed"},
		{command: "ssh -tA box", errSubstr: "-A is not allowed"},
		{command: "ssh box -A", errSubstr: "-A is not allowed"},
		{command: "ssh -X box", errSubstr: "-X is not allowed"},
		{command: "ssh -L 8080:internal:80 box", errSubstr: "-L is not allowed"},
		{command: "ssh -R 9000:localhost:22 box", errSubstr: "-R is not allowed"},
		{command: "ssh -D 1080 box", errSubstr: "-D is not allowed"},
		{command: "ssh -W evil:22 box", errSubstr: "-W is not allowed"},
		{command: "ssh -f box sleep 100", errSubstr: "-f is not allowed"},
		{command: "ssh -M box", errSubstr: "-M is not allowed"},
		{command: "ssh -O exit box", errSubstr: "-O is not allowed"},
		{command: "ssh -I /tmp/lib.so box", errSubstr: "-I is not allowed"},
		{command: "ssh -E log box", errSubstr: "-E is not allowed"},
		{command: "ssh -F ./cfg box", errSubstr: "-F ./cfg is not allowed"},
		{command: "ssh -S ./ctl box", errSubstr: "-S ./ctl is not allowed"},
		{command: "ssh -Z box", errSubstr: "unknown option"},
		{command: "ssh -o ProxyCommand='nc evil 22' box", errSubstr: "-o ProxyCommand=nc evil 22 is not allowed"},
		{command: "ssh -oProxyCommand=sh box", errSubstr: "ProxyCommand"},
		{command: "ssh -o 'LocalCommand touch x' -o PermitLocalCommand=yes box", errSubstr: "LocalCommand"},
		{command: "ssh -o PermitLocalCommand=yes box", errSubstr: "PermitLocalCommand=yes is not allowed"},
		{command: "ssh -o KnownHostsCommand=id box", errSubstr: "KnownHostsCommand"},
		{command: "ssh -o Hostname=evil box", errSubstr: "Hostname"},
		{command: "ssh -o IdentityAgent=/tmp/other.sock box", errSubstr: "IdentityAgent=/tmp/other.sock"},
		{command: "ssh -o SendEnv=GITHUB_TOKEN box", errSubstr: "SendEnv"},
		{command: "ssh -o ForwardAgent=yes box", errSubstr: "ForwardAgent=yes"},
		{command: "ssh -o LocalForward='8080 internal:80' box", errSubstr: "LocalForward"},
		{command: "ssh -o IdentityFile=./k box", errSubstr: "pass the key with -i"},
		{command: "ssh -o UserKnownHostsFile=./kh box", errSubstr: "UserKnownHostsFile=./kh"},
		{command: "ssh -o PKCS11Provider=/x.so box", errSubstr: "PKCS11Provider"},
		{command: "ssh -o Include=/x box", errSubstr: "Include"},
		{command: "ssh -qi./id box", errSubstr: "must not be bundled"},
		{command: "ssh -i /etc/passwd box", errSubstr: "outside allowed directories"},
		{command: "xargs ssh box uptime"},
		{command: "xargs ssh box --"},
		// With a replace string, xargs's input replaces words in place: as
		// the first word after the destination, ssh would read
		// -oProxyCommand=... from it.
		{command: "xargs -I{} ssh box {}", errSubstr: "with its input replacing"},
		{command: "xargs -I {} ssh box {}", errSubstr: "with its input replacing"},
		{command: "xargs -0I@ ssh box @", errSubstr: "with its input replacing"},
		{command: "xargs -i ssh box {}", errSubstr: "with its input replacing"},
		{command: "xargs --replace=X ssh -o User=X box uptime", errSubstr: "with its input replacing"},
		{command: "xargs -I{} ssh {} uptime", errSubstr: "is not allowed"},
		{command: "xargs -I{} ssh box cat {}"},
		{command: "xargs -I{} ssh box -- {}"},
		{command: "xargs -I{} sshpass -e ssh box echo {}"},
		{command: "xargs -I{} ssh box"},
		{command: "xargs ssh box", errSubstr: "xargs ssh without a remote command"},
		{command: "xargs -n1 ssh -p 22 box", errSubstr: "xargs ssh without a remote command"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			err := s.ValidateCommand(tt.command, dir, paths, paths)
			if tt.errSubstr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("error = %v, want one containing %q", err, tt.errSubstr)
			}
		})
	}
}

func TestValidateSSHPassCommand(t *testing.T) {
	dir := t.TempDir()
	paths := []string{dir}
	s := newTestSandboxWithSSH("box")
	tests := []struct {
		command   string
		errSubstr string
	}{
		{command: "sshpass -e ssh box uptime"},
		{command: "export SSHPASS=$(cat pw.txt); sshpass -e ssh me@box"},
		{command: "sshpass -v -e -P 'Passcode:' ssh box cat /etc/hostname"},
		{command: "sshpass -ve ssh -o PubkeyAuthentication=no box"},
		{command: "sshpass -h"},
		{command: "sshpass -V"},

		{command: "sshpass -p hunter2 ssh box", errSubstr: "export SSHPASS=$(cat <file>)"},
		{command: "sshpass -phunter2 ssh box", errSubstr: "-p is not allowed"},
		{command: "sshpass -e -p x ssh box", errSubstr: "-p is not allowed"},
		{command: "sshpass -f ./pw ssh box", errSubstr: "-f is not allowed"},
		{command: "sshpass -d 3 ssh box", errSubstr: "-d is not allowed"},
		{command: "sshpass ssh box", errSubstr: "without -e is not allowed"},
		{command: "sshpass -e ssh evil", errSubstr: `ssh to "evil" is not allowed`},
		{command: "sshpass -e ssh -A box", errSubstr: "-A is not allowed"},
		{command: "sshpass -e scp f box:", errSubstr: `sshpass may only run ssh, not "scp"`},
		{command: "sshpass -e bash -c id", errSubstr: "sshpass may only run ssh"},
		{command: "sshpass -x ssh box", errSubstr: "unknown option"},
		{command: "sshpass -eh bash -c id", errSubstr: "-e must be written on its own"},
		{command: "sshpass -eV bash -c id", errSubstr: "-e must be written on its own"},
		{command: "xargs sshpass -e ssh box uptime"},
		{command: "xargs sshpass -e", errSubstr: "xargs sshpass without a command"},
		{command: "xargs sshpass -e ssh box", errSubstr: "xargs sshpass without a remote command"},
		{command: "cat /etc/passwd > /dev/null; export SSHPASS=$(cat /etc/passwd)", errSubstr: "outside allowed directories"},
	}
	for _, tt := range tests {
		t.Run(tt.command, func(t *testing.T) {
			err := s.ValidateCommand(tt.command, dir, paths, paths)
			if tt.errSubstr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.errSubstr) {
				t.Fatalf("error = %v, want one containing %q", err, tt.errSubstr)
			}
		})
	}
}

// TestSSHPassEnv: $SSHPASS reaches sshpass alone, and is a credential the
// worker's environment leaves out.
func TestSSHPassEnv(t *testing.T) {
	if !config.CredentialEnvVar("SSHPASS") {
		t.Error("SSHPASS is not treated as a credential")
	}
	for _, args := range [][]string{{"ssh", "box"}, {"env"}, {"git", "push"}} {
		env := map[string]string{"SSHPASS": "pw", "HOME": "/h"}
		stripSSHPass(args, env)
		if _, ok := env["SSHPASS"]; ok || env["HOME"] != "/h" {
			t.Errorf("%v kept %v", args, env)
		}
	}
	env := map[string]string{"SSHPASS": "pw"}
	stripSSHPass([]string{"sshpass", "-e", "ssh", "box"}, env)
	if env["SSHPASS"] != "pw" {
		t.Error("sshpass lost SSHPASS")
	}
}

// TestSSHWithoutHosts: with no hosts listed, ssh is not on the whitelist
// (allowlist mode names the remedy), and denylist mode runs it as before.
func TestSSHWithoutHosts(t *testing.T) {
	dir := t.TempDir()
	paths := []string{dir}
	for _, cmd := range []string{"ssh box", "sshpass -e ssh box"} {
		err := newTestSandbox().ValidateCommand(cmd, dir, paths, paths)
		if err == nil || !strings.Contains(err.Error(), "config ssh hosts add") {
			t.Errorf("%s without hosts: %v", cmd, err)
		}
	}
	deny := newTestSandboxWithConfig(&config.Config{Mode: string(config.ModeDenylist)})
	if err := deny.ValidateCommand("ssh -A anyhost cat /etc/hostname", dir, paths, paths); err != nil {
		t.Errorf("denylist mode without an ssh section: %v", err)
	}
	// An invocation the ssh parse refuses keeps the path checks of the
	// options that name a local file there: ssh -F prints the lines of a file
	// it cannot parse as config.
	// The file must exist: an absolute read path that doesn't is let through
	// (/etc/hostname is missing on macOS).
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"ssh -F " + outside + " anyhost", "ssh -A -F" + outside + " anyhost", "ssh anyhost -F " + outside} {
		if err := deny.ValidateCommand(cmd, dir, paths, paths); err == nil {
			t.Errorf("denylist mode: %s allowed", cmd)
		}
	}
	// Listing hosts holds denylist mode to them too.
	denyHosts := newTestSandboxWithConfig(&config.Config{Mode: string(config.ModeDenylist), SSH: &config.SSHConfig{Hosts: []string{"box"}}})
	if err := denyHosts.ValidateCommand("ssh anyhost", dir, paths, paths); err == nil {
		t.Error("denylist mode with hosts listed allowed an unlisted host")
	}
}

// TestSSHRuntimeValidation: a destination known only after expansion is
// checked on the expanded argv, before anything runs.
func TestSSHRuntimeValidation(t *testing.T) {
	dir := t.TempDir()
	paths := []string{dir}
	s := newTestSandboxWithSSH("box")
	for _, cmd := range []string{`H=evil; ssh "$H" true`, `O=-A; ssh $O box true`, `timeout 5 ssh evil true`} {
		_, err := s.Execute(context.Background(), cmd, dir, paths, paths)
		if err == nil || !strings.Contains(err.Error(), "not allowed") {
			t.Errorf("%s: %v", cmd, err)
		}
	}
}

func TestGitContactsRemote(t *testing.T) {
	remote := []string{
		"git fetch", "git pull --rebase", "git push origin main", "git clone git@host:x/y",
		"git ls-remote origin", "git -C sub fetch", "git -c user.name=x push",
		"git remote show origin", "git remote", "git archive --remote=origin HEAD",
		"git submodule update --init", "git fetch-pack x",
	}
	local := []string{
		"git status", "git commit -m x", "git log", "git remote add o url",
		"git remote set-url o url", "git archive HEAD", "git", "git --version", "git frobnicate",
	}
	for _, c := range remote {
		if !gitContactsRemote(strings.Fields(c)) {
			t.Errorf("%s: not classified as remote", c)
		}
	}
	for _, c := range local {
		if gitContactsRemote(strings.Fields(c)) {
			t.Errorf("%s: classified as remote", c)
		}
	}
}

// fakeAgentProxy stands in for the restricted agent the server serves.
type fakeAgentProxy struct {
	socket     string
	gitSigning bool
}

func (p *fakeAgentProxy) Socket() string          { return p.socket }
func (p *fakeAgentProxy) AllowGitSigning(on bool) { p.gitSigning = on }

// routed reports whether args run in the ssh agent's worker.
func (s *Sandbox) routedToAgent(args []string) bool {
	scope, _, ok := s.workerScope(args)
	return ok && s.isSSHAgentScope(scope)
}

// TestSSHAgentScope: with an agent socket, ssh, sshpass, and git's remote
// commands go to the agent's worker; local git and everything else do not;
// every other worker masks the sockets.
func TestSSHAgentScope(t *testing.T) {
	s := newTestSandboxWithSSH("box")
	proxy := &fakeAgentProxy{socket: "/run/proxy.sock"}
	s.SetSSHAgent(proxy, "/run/agent.sock")
	for _, args := range [][]string{{"ssh", "box"}, {"sshpass", "-e", "ssh", "box"}, {"git", "push"}, {"git", "fetch"}} {
		if !s.routedToAgent(args) {
			t.Errorf("%v not routed to the agent's worker", args)
		}
	}
	for _, args := range [][]string{{"git", "status"}, {"git", "commit", "-m", "x"}, {"ls"}, {"ssh-add", "-l"}} {
		if _, _, ok := s.workerScope(args); ok {
			t.Errorf("%v routed to a scoped worker", args)
		}
	}
	if proxy.gitSigning {
		t.Error("git signing allowed without git_signing")
	}
	cfg := s.getConfig()
	shared := s.sshAgentMasks(cfg)
	if len(shared) != 2 {
		t.Errorf("shared worker masks %v, want both sockets", shared)
	}
	scope, _, _ := s.commandScope("ssh")
	own := s.sshAgentMasks(cfg.ForScope(scope))
	if len(own) != 1 || own[0] != "/run/agent.sock" {
		t.Errorf("the agent's worker masks %v, want only the real agent", own)
	}
	env := map[string]string{"SSH_AUTH_SOCK": "/run/agent.sock"}
	s.sshAgentHostEnv(env)
	if env["SSH_AUTH_SOCK"] != "/run/proxy.sock" {
		t.Errorf("host commands get SSH_AUTH_SOCK=%s, want the proxy", env["SSH_AUTH_SOCK"])
	}

	// git_signing sends the signing git commands there too, and tells the
	// proxy to sign them.
	yes := true
	s.updateConfig(&config.Config{SSH: &config.SSHConfig{Hosts: []string{"box"}, GitSigning: &yes}}, "")
	if !proxy.gitSigning {
		t.Error("git_signing did not reach the proxy")
	}
	for _, args := range [][]string{{"git", "commit", "-m", "x"}, {"git", "tag", "-s", "v1"}, {"git", "-c", "x=y", "rebase", "main"}} {
		if !s.routedToAgent(args) {
			t.Errorf("%v not routed to the agent's worker with git_signing", args)
		}
	}
	if s.routedToAgent([]string{"git", "status"}) {
		t.Error("git status routed to the agent's worker")
	}

	// unrestricted_agent hands over the real socket.
	s.updateConfig(&config.Config{SSH: &config.SSHConfig{Hosts: []string{"box"}, UnrestrictedAgent: &yes}}, "")
	scope, _, _ = s.commandScope("ssh")
	if !s.isSSHAgentScope(scope) || s.sshAgentSocket != "/run/agent.sock" {
		t.Errorf("unrestricted agent grants %q", s.sshAgentSocket)
	}
	if own := s.sshAgentMasks(s.getConfig().ForScope(scope)); len(own) != 1 || own[0] != "/run/proxy.sock" {
		t.Errorf("the agent's worker masks %v, want only the proxy", own)
	}

	// agent: false: nothing gets it, and host commands lose SSH_AUTH_SOCK.
	no := false
	s.updateConfig(&config.Config{SSH: &config.SSHConfig{Hosts: []string{"box"}, Agent: &no}}, "")
	if s.routedToAgent([]string{"ssh", "box"}) || s.routedToAgent([]string{"git", "push"}) {
		t.Error("agent: false still routes to an agent worker")
	}
	// sshpass still gets a worker of its own, without the agent.
	if scope, _, ok := s.workerScope([]string{"sshpass", "-e", "ssh", "box"}); !ok || scope.Key != "sshpass" {
		t.Errorf("sshpass with agent: false runs in %+v, %v", scope, ok)
	}
	env = map[string]string{"SSH_AUTH_SOCK": "/run/agent.sock"}
	s.sshAgentHostEnv(env)
	if _, ok := env["SSH_AUTH_SOCK"]; ok {
		t.Error("agent: false kept SSH_AUTH_SOCK for host commands")
	}

	// No ssh section: git keeps running where it did, the real agent is not
	// masked, and the proxy (which serves nobody) is.
	s.updateConfig(&config.Config{}, "")
	if _, _, ok := s.workerScope([]string{"git", "push"}); ok {
		t.Error("git routed to a scoped worker without an ssh section")
	}
	if m := s.sshAgentMasks(s.getConfig()); len(m) != 1 || m[0] != "/run/proxy.sock" {
		t.Errorf("without an ssh section the worker masks %v", m)
	}
	env = map[string]string{"SSH_AUTH_SOCK": "/run/agent.sock"}
	s.sshAgentHostEnv(env)
	if env["SSH_AUTH_SOCK"] != "/run/agent.sock" {
		t.Error("without an ssh section SSH_AUTH_SOCK changed")
	}
}
