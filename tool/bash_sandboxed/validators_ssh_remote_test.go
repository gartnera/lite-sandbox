package bash_sandboxed

import (
	"strings"
	"testing"

	"github.com/gartnera/lite-sandbox/config"
)

func TestSSHRemoteCommand(t *testing.T) {
	dir := t.TempDir()
	paths := []string{dir}
	yes := true
	s := newTestSandboxWithConfig(&config.Config{SSH: &config.SSHConfig{Hosts: []config.SSHHost{
		{Host: "box"},
		{Host: "deploy", Commands: []string{"systemctl restart", "docker compose up", "make"}},
		{Host: "scratch", Write: &yes},
		{Host: "::1"},
	}}})
	tests := []struct {
		command   string
		errSubstr string // "" when allowed
	}{
		// Read-only commands, and the shell around them.
		{command: "ssh box uptime"},
		{command: "ssh box 'cat /var/log/app.log | tail -n 50'"},
		{command: "ssh box 'tail -n 100 /var/log/*.log'"},
		{command: "ssh box tail -n 100 /var/log/*.log", errSubstr: "expands on this machine"},
		{command: "ssh box cat {a,b}", errSubstr: "expands on this machine"},
		{command: "F=x; ssh box cat $F", errSubstr: "write them out"},
		{command: "ssh me@[::1] uptime"},
		{command: "ssh box \"cat '\\$HOME'\""},
		{command: `ssh box "cd /srv/app && git log --oneline -5 && git status"`},
		{command: "ssh box 'ls -la ~ 2>/dev/null || echo none'"},
		{command: "ssh box 'grep -c ERROR /var/log/syslog > /dev/null; echo $?'", errSubstr: "variables"},
		{command: "ssh box 'if test -f /etc/os-release; then cat /etc/os-release; fi'"},
		{command: "ssh box 'df -h; free -m; ps aux --sort=-%mem | head'"},
		{command: "ssh box 'LC_ALL=C sort /etc/passwd | uniq -c'"},
		{command: "ssh box sudo -n journalctl -u nginx --since today --no-pager"},
		{command: "ssh box 'sudo -u www-data cat /srv/app/.env'"},
		{command: "ssh box 'sudo tail -n 5 /var/log/*.log'"},
		{command: "ssh box 'sudo find /var/log/*' ", errSubstr: "only allowed in the arguments of plain readers"},
		{command: "ssh box 'nice -n 5 timeout 10 sh -c \"cat /etc/hostname\"'"},
		{command: "ssh box 'bash -lc \"journalctl -k | tail\"'"},
		{command: "ssh box 'env GIT_CONFIG_COUNT=1 git status'", errSubstr: "setting GIT_CONFIG_COUNT is not allowed"},
		{command: "ssh box 'timeout 5 rm x'", errSubstr: "rm is not one of the read-only commands"},
		{command: "ssh box 'find . -exec sh -c \"cat {}\" \\;'", errSubstr: "find puts the file names into the script"},
		{command: "ssh box 'sudo find . -execdir bash -c id \\;'", errSubstr: "find puts the file names into the script"},
		{command: "ssh box 'find . -exec cat {} \\;'"},
		{command: "ssh box \"find . -exec cat {} ';' -delete\"", errSubstr: `find flag "-delete" is not allowed`},
		{command: "ssh box systemctl status nginx"},
		{command: "ssh box systemctl --no-pager -t service list-units"},
		{command: "ssh box systemctl"},
		{command: "ssh box 'timeout 5 env TZ=UTC date +%s'"},
		{command: "ssh box date -Iseconds"},
		{command: "ssh box hostname -I"},
		{command: "ssh box \"sed -n '10,20p;/x/{p;q}' /etc/hosts\""},
		{command: `ssh box "sed -e 's/a/b/g' -e '1d' /etc/hosts"`},
		{command: `ssh box "find /var/log -name '*.gz' -mtime +7 -exec ls -l {} +"`},
		{command: "ssh box ip -br addr show"},
		{command: "ssh box ip route get 1.1.1.1"},
		{command: "ssh box docker ps -a"},
		{command: "ssh box docker compose -f /srv/app/compose.yml logs --tail 50 web"},
		{command: "ssh box docker container inspect web"},
		{command: `ssh box "bash -lc 'journalctl -k | tail'"`},
		{command: "ssh box 'command -v rm'"},
		{command: "ssh box 'cat <<EOF\nhello\nEOF'"},
		{command: "ssh box 'cat < /etc/hosts'"},
		{command: "ssh box 'git -C /srv/app diff --stat HEAD~1'"},
		{command: "ssh -n box"},
		{command: "ssh -N box"},
		{command: "ssh -G box"},
		{command: "ssh -tt -n box uptime"},

		// Write commands and the ways around the list.
		{command: "ssh box", errSubstr: "without a command the remote shell runs whatever reaches its stdin"},
		{command: "ssh box rm -rf /tmp/x", errSubstr: "rm is not one of the read-only commands"},
		{command: "ssh box 'cat x; rm -rf /'", errSubstr: "rm is not one of"},
		{command: "ssh box 'cat x && touch y'", errSubstr: "touch is not one of"},
		{command: "ssh box 'echo x > /tmp/f'", errSubstr: `output redirection to "/tmp/f"`},
		{command: "ssh box 'echo x >> ~/.bashrc'", errSubstr: "output redirection"},
		{command: "ssh box 'echo x >&file'", errSubstr: "target must be a file descriptor number"},
		{command: "ssh box 'cat $(rm -rf /)'", errSubstr: "command substitution"},
		{command: "ssh box 'cat `rm x`'", errSubstr: "command substitution"},
		{command: "ssh box 'X=rm; $X -rf /'", errSubstr: "variables"},
		{command: "ssh box 'find . $HOME'", errSubstr: "variables"},
		{command: "ssh box 'cat \"$HOME/x\"'", errSubstr: "variables"},
		{command: "ssh box 'for f in -delete; do find . $f; done'", errSubstr: "for loops"},
		{command: "ssh box 'for f in a; do cat a; done'", errSubstr: "for loops"},
		{command: "ssh box 'f() { rm x; }; f'", errSubstr: "function definitions"},
		{command: "ssh box 'echo $((1+1))'", errSubstr: "arithmetic"},
		{command: "ssh box 'export X=1'", errSubstr: "sets shell variables"},
		{command: "ssh box 'X=1'", errSubstr: "assigning shell variables"},
		{command: "ssh box 'LD_PRELOAD=/tmp/x.so cat /etc/hosts'", errSubstr: "setting LD_PRELOAD"},
		{command: "ssh box 'PATH=/tmp cat'", errSubstr: "setting PATH"},
		{command: "ssh box 'LANG=a[1] cat'", errSubstr: "the value may only hold"},
		{command: "ssh box /tmp/evil", errSubstr: "run commands by a bare name"},
		{command: "ssh box ./cat", errSubstr: "bare name"},
		{command: "ssh box 'r\\m -rf x'", errSubstr: "rm is not one of"},
		{command: `ssh box "find . -dele\\te"`, errSubstr: `find flag "-delete" is not allowed`},
		{command: "ssh box find . -delete", errSubstr: `find flag "-delete" is not allowed`},
		{command: "ssh box find . -exec rm {} +", errSubstr: "find -exec: rm is not one of"},
		{command: "ssh box find . -exec {} ';'", errSubstr: "bare name"},
		{command: "ssh box 'find . -name *.log'", errSubstr: "unquoted globs"},
		{command: "ssh box 'uniq /var/log/*'", errSubstr: "unquoted globs"},
		{command: "ssh box 'sort {-o,x} y'", errSubstr: "unquoted globs"},
		{command: "ssh box sort -o /etc/passwd /tmp/x", errSubstr: "sort -o is not allowed"},
		{command: "ssh box sort -ro/etc/passwd x", errSubstr: "sort -o is not allowed"},
		{command: "ssh box sort --outp=/etc/passwd x", errSubstr: "is not allowed"},
		{command: "ssh box sort --compress-program=sh x", errSubstr: "runs a program"},
		{command: "ssh box uniq a b", errSubstr: "writes it"},
		{command: "ssh box date -s now", errSubstr: "sets the clock"},
		{command: "ssh box date --se now", errSubstr: "sets the clock"},
		{command: "ssh box date 010100002030", errSubstr: "sets the clock"},
		{command: "ssh box hostname evil", errSubstr: "sets the host name"},
		{command: "ssh box hostname -F /tmp/n", errSubstr: "sets the host name"},
		{command: "ssh box dmesg -C", errSubstr: "clears the kernel log"},
		{command: "ssh box dmesg --read-c", errSubstr: "clears the kernel log"},
		{command: "ssh box journalctl --vacuum-time=1d", errSubstr: "journal files"},
		{command: "ssh box journalctl --rot", errSubstr: "journal files"},
		{command: "ssh box systemctl restart nginx", errSubstr: "systemctl restart is not a read-only verb"},
		{command: "ssh box systemctl -p status restart nginx", errSubstr: "restart is not a read-only verb"},
		{command: "ssh box systemctl -H other status", errSubstr: "reaches another host"},
		{command: "ssh box git push", errSubstr: "git push is not a read-only subcommand"},
		{command: "ssh box git -c core.pager=sh log", errSubstr: "git -c is not allowed"},
		{command: "ssh box git log --output=/tmp/x", errSubstr: "is not allowed"},
		{command: "ssh box git grep -O foo", errSubstr: "is not allowed"},
		{command: "ssh box git st", errSubstr: "git st is not a read-only subcommand"},
		{command: "ssh box docker rm web", errSubstr: "docker rm is not read-only"},
		{command: "ssh box docker -H tcp://x ps", errSubstr: "docker -H is not read-only"},
		{command: "ssh box docker compose up -d", errSubstr: "docker compose up is not read-only"},
		{command: "ssh box docker container prune", errSubstr: "not read-only"},
		{command: "ssh box sed -i s/a/b/ f", errSubstr: "sed -i is not allowed"},
		{command: "ssh box sed -ni p f", errSubstr: "sed -i is not allowed"},
		{command: "ssh box sed --in p f", errSubstr: "is not allowed"},
		{command: "ssh box sed -f script f", errSubstr: "is not allowed"},
		{command: `ssh box "sed 's/a/b/w /etc/x' f"`, errSubstr: "s///w"},
		{command: `ssh box "sed 's/a/b/ge' f"`, errSubstr: "s///w"},
		{command: `ssh box "sed '1w /etc/x' f"`, errSubstr: "s///w"},
		{command: `ssh box "sed -e p -e '\$e id' f"`, errSubstr: "s///w"},
		{command: `ssh box "sed '/x/{e id' f"`, errSubstr: "s///w"},
		{command: `ssh box "sed 's|a|b|;W /x' f"`, errSubstr: "s///w"},
		{command: "ssh box ip link set eth0 down", errSubstr: "only show, list, and get"},
		{command: "ssh box ip l s eth0 down", errSubstr: "only show, list, and get"},
		{command: "ssh box ip -batch /tmp/cmds", errSubstr: "is not allowed"},
		{command: "ssh box ip netns exec x rm", errSubstr: "only show, list, and get"},
		{command: "ssh box ss -K dst 1.2.3.4", errSubstr: "closes sockets"},
		{command: "ssh box rg --pre sh x", errSubstr: "runs a program"},
		{command: "ssh box sudo rm x", errSubstr: "rm is not one of"},
		{command: "ssh box sudo -s", errSubstr: "starts a shell"},
		{command: "ssh box sudo -i cat x", errSubstr: "starts a shell"},
		{command: "ssh box sudo -e /etc/hosts", errSubstr: "edits files"},
		{command: "ssh box sudo LD_PRELOAD=x cat", errSubstr: "sets the command's environment"},
		{command: "ssh box sudo -u root -- rm x", errSubstr: "rm is not one of"},
		{command: "ssh box env rm x", errSubstr: "rm is not one of"},
		{command: "ssh box env --uns cat rm -rf x", errSubstr: "rm is not one of"},
		{command: "ssh box env -S 'rm x'", errSubstr: "split-string"},
		{command: "ssh box env PATH=/tmp cat", errSubstr: "setting PATH"},
		{command: "ssh box timeout -s KILL 5 rm x", errSubstr: "rm is not one of"},
		{command: "ssh box nice -n 5 rm x", errSubstr: "rm is not one of"},
		{command: "ssh box command rm x", errSubstr: "rm is not one of"},
		{command: "ssh box xargs rm", errSubstr: "xargs is not one of"},
		{command: "ssh box sh", errSubstr: "only allowed as sh -c"},
		{command: "ssh box bash -s", errSubstr: "reading commands from stdin"},
		{command: "ssh box bash script.sh", errSubstr: "only allowed as bash -c"},
		{command: `ssh box "sh -c 'rm -rf x'"`, errSubstr: "rm is not one of"},
		{command: `ssh box "bash -c \"sh -c 'touch x'\""`, errSubstr: "touch is not one of"},
		{command: "ssh box eval rm x", errSubstr: "eval is not one of"},
		{command: "ssh box 'exec rm x'", errSubstr: "exec is not one of"},
		{command: "ssh box '. /tmp/x'", errSubstr: "bare name"},
		{command: "ssh box source /tmp/x", errSubstr: "source is not one of"},
		{command: "ssh box trap 'rm x' EXIT", errSubstr: "trap is not one of"},
		{command: "ssh box less /etc/hosts", errSubstr: "less is not one of"},
		{command: `ssh box "awk 'BEGIN{system(1)}'"`, errSubstr: "awk is not one of"},
		{command: "ssh box \"echo $'\\x72m'\"", errSubstr: "$'...' quoting"},
		{command: "ssh box 'cat <(rm x)'", errSubstr: "process substitution"},
		{command: "ssh box 'cat x |'", errSubstr: "does not parse"},
		{command: "ssh box -s sftp", errSubstr: "subsystem"},
		{command: "ssh -o SessionType=subsystem box sftp", errSubstr: "subsystem"},
		{command: "ssh -o RemoteCommand=uptime box", errSubstr: "RemoteCommand"},
		{command: "ssh -o SetEnv=FOO=1 box uptime", errSubstr: "SetEnv"},
		{command: "ssh -t box systemctl status x", errSubstr: "a terminal"},
		{command: "ssh -o RequestTTY=force box uptime", errSubstr: "a terminal"},
		{command: "ssh box rm x", errSubstr: "config ssh hosts add box --command"},

		// A hosts entry's commands, with any arguments.
		{command: "ssh deploy systemctl restart nginx"},
		{command: "ssh deploy 'sudo systemctl restart nginx && systemctl status nginx'"},
		{command: "ssh deploy docker compose up -d --build"},
		{command: "ssh deploy make -C /srv/app deploy"},
		{command: "ssh deploy systemctl stop nginx", errSubstr: "systemctl stop is not a read-only verb"},
		{command: "ssh deploy docker compose down", errSubstr: "docker compose down is not read-only"},
		{command: "ssh deploy 'make $(rm x)'", errSubstr: "command substitution"},

		// write: true runs anything.
		{command: "ssh scratch 'rm -rf /tmp/x; X=1; echo $X > /tmp/y'"},
		{command: "ssh scratch"},
		{command: "ssh -t scratch"},

		// Through sshpass, and as a jump host.
		{command: "sshpass -e ssh box uptime"},
		{command: "sshpass -e ssh box rm x", errSubstr: "rm is not one of"},
		{command: "ssh -J box scratch rm x"},
		{command: "ssh -J scratch box rm x", errSubstr: "rm is not one of"},
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

func TestSedScriptReadOnly(t *testing.T) {
	for _, ok := range []string{
		"p", "10,20p", "/re/d", `\%a/b%p`, "$!N;P;D", "1~2p", "0,/x/s//y/", "s/a\\/b/c/gI2",
		"y/abc/xyz/", "/x/{p;q}", ":a;N;ba", "a hello; w /x", "1i\\\ntext w x", "l 40", "r /etc/hosts", "#n\np",
		"s/x/y/;  s/a/b/p", "/a/,+3!d",
	} {
		if err := sedScriptReadOnly(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"w /x", "1W /x", "e id", "s/a/b/w /x", "s/a/b/gw /x", "s/a/b/e", "s/a/b/ge", "s|a|b|pe",
		"/x/e", "$ e", "p;w x", "/x/!w y", "{p\nw x\n}", "s/a/b", "k", "s/a/b/ w x", ":a w x",
	} {
		if err := sedScriptReadOnly(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
