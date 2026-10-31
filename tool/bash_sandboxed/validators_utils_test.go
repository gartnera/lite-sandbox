package bash_sandboxed

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// checkUtilCommand runs the static validation and the path pass the way the
// sandbox does, with workDir writable and roDir readable only.
func checkUtilCommand(t *testing.T, s *Sandbox, workDir, roDir, cmd string) error {
	t.Helper()
	f, err := ParseBash(cmd)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if err := s.validate(f); err != nil {
		return err
	}
	return validatePaths(f, workDir, []string{workDir, roDir}, []string{workDir})
}

func utilDirs(t *testing.T) (workDir, roDir string) {
	workDir, roDir = t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(roDir, "data.txt"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return workDir, roDir
}

func TestUtilCommands_Allowed(t *testing.T) {
	workDir, roDir := utilDirs(t)
	ro := filepath.Join(roDir, "data.txt")
	s := newTestSandbox()
	for _, cmd := range []string{
		// Read-only and informational
		"arch", "nproc", "getconf PAGESIZE", "locale", "lscpu", "lsmem", "lsblk",
		"findmnt", "mountpoint -q .", "hostid", "logname", "users", "who", "w",
		"tty", "free -h", "vmstat 1 2", "top -bn1", "pidof node",
		"pidof /usr/bin/node", "dir", "vdir", "dircolors -b", "lsattr a.txt",
		"namei -l a/b", "tput cols", "clear",
		"base32 a.txt", "basenc --base64url a.txt", "getopt -o ab -- -a",
		"cmp a.txt b.txt", "cmp " + ro + " a.txt", "diff3 a b c", "diff3 -m a b c",
		"sdiff a b", "sdiff -w 80 a b", "sdiff -Io a b",
		"sha224sum a", "sha384sum a", "sha512sum a", "sum a",
		"rgrep foo .", "zcmp a.gz b.gz", "zdiff a.gz b.gz", "zegrep foo a.gz",
		"bzgrep foo a.bz2", "xzgrep foo a.xz", "xzless a.xz", "zless -R a.gz",
		"less -R a.txt", "less -N -S a.txt", "less -p pattern a.txt", "less -pko a.txt",
		"less --long-prompt a.txt", "less -- -o", "PAGER=cat git log",
		"sort -k2 -t, a.txt", "sort -u --output=out.txt a.txt", "sort -S 64K a.txt",
		"shuf -n 1 a.txt", "shuf -o out.txt a.txt", "shuf -i 1-10",

		// Writes inside the write set
		"split -l 10 a.txt", "split -l 10 a.txt part.", "split -n 2 " + ro + " out/part",
		"csplit a.txt 2", "csplit -f part -b %03d.txt a.txt /x/",
		"gzip a.txt", "gzip -k -9 a.txt", "gunzip a.txt.gz", "gzip -dc a.gz",
		"gzip -c " + ro, "gzip -l a.gz", "bzip2 a.txt", "bunzip2 a.bz2", "bzip2 -dc " + ro,
		"xz a.txt", "unxz a.xz", "xz -T0 -9 a.txt", "xzcat a.xz", "xz -dc " + ro,
		"dd if=/dev/zero of=out.bin bs=1k count=4", "dd if=" + ro + " of=copy status=none",
		"dd if=a.img", "dd of=out.bin",
		"rmdir empty", "rmdir -p a/b/c", "unlink f", "link a b", "mkfifo -m 600 fifo",
		"truncate -s 0 log.txt", "truncate -r a.txt b.txt", "fallocate -l 1M f",
		"shred -u secret.txt", "chown 1000 f", "chown -R 1000:1000 dir", "chgrp staff f",
		"chown --reference=a b", "install -m 755 a bin/a", "install -D a out/sub/a",
		"install -d out/dir", "install -t out a b", "sync", "sync a.txt",

		// Wrappers
		"nohup ls", "nohup -- ls", "nice ls", "nice -n 10 ls", "nice -10 ls",
		"nice --adjustment=5 ls", "nice --adj 5 ls", "setsid ls", "setsid -f ls",
		"stdbuf -oL grep foo a.txt", "stdbuf -o L grep foo a.txt",
		"stdbuf --output=L ls", "nohup nice -n 5 ls",
	} {
		t.Run(cmd, func(t *testing.T) {
			if err := checkUtilCommand(t, s, workDir, roDir, cmd); err != nil {
				t.Fatalf("expected %q to be allowed, got: %v", cmd, err)
			}
		})
	}
}

func TestUtilCommands_Blocked(t *testing.T) {
	workDir, roDir := utilDirs(t)
	ro := filepath.Join(roDir, "data.txt")
	outside := filepath.Join(filepath.Dir(workDir), "outside-"+filepath.Base(workDir))
	s := newTestSandbox()
	for _, tt := range []struct {
		command string
		errMsg  string
	}{
		// Options that run another program
		{"diff3 --diff-program=sh a b c", "runs another program"},
		{"diff3 --diff sh a b c", "runs another program"},
		{"sdiff --diff-program=sh a b", "runs another program"},
		{"sdiff -o out a b", "runs another program"},
		{"sdiff -so out a b", "runs another program"},
		{"sdiff --out=out a b", "runs another program"},
		{"split --filter='sh -c x' a.txt", "runs a shell command"},
		{"split --f=sh a.txt", "runs a shell command"},
		{"sort --compress-program=sh a.txt", "runs a program"},
		{"sort --compress-program sh a.txt", "runs a program"},
		{"sort --compress-prog=sh a.txt", "runs a program"},
		{"sort -S 64K --compress-program=/nonexistent/prog a.txt", "runs a program"},
		{"install -s a b", "runs a strip program"},
		{"install -sm 755 a b", "runs a strip program"},
		{"install --strip a b", "runs a strip program"},
		{"install --strip-program=sh a b", "runs a strip program"},

		// Options that name the output past the path check
		{"gzip -dN a.gz", "stored name"},
		{"gunzip --name a.gz", "stored name"},
		{"gunzip --na a.gz", "stored name"},
		{"xz --files=list", "reads file names"},
		{"xz --files0 list", "reads file names"},
		{"unxz --fil=list", "reads file names"},
		{"xzcat --files=list", "reads file names"},

		// less: a lesskey file can set LESSOPEN, which less runs; -o writes
		{"less -k key a.txt", "lesskey file"},
		{"less -Sk key a.txt", "lesskey file"},
		{"less -o log a.txt", "log file"},
		{"less -Olog a.txt", "log file"},
		{"less --lesskey-src=key a.txt", "lesskey file"},
		{"less --LESSKEY-CONTENT=x a.txt", "lesskey file"},
		{"less --lessk=key a.txt", "lesskey file"},
		{"less --LOG-FILE log a.txt", "log file"},
		{"zless -k key a.gz", "lesskey file"},
		{"LESSOPEN='|sh -c id' less a.txt", "setting LESSOPEN is not allowed"},
		{"export LESSOPEN='|sh -c id'", "setting LESSOPEN is not allowed"},
		{"env LESSKEYIN=key less a.txt", "setting LESSKEYIN is not allowed"},
		{"LESS=--lesskey-src=key less a.txt", "setting LESS is not allowed"},
		{"GZIP=-N gunzip a.gz", "setting GZIP is not allowed"},
		{"XZ_OPT=--files=list xz", "setting XZ_OPT is not allowed"},
		{"zmore a.gz", `command "zmore" is not allowed`},
		{"arch -x86_64 sh", "macOS arch runs a command"},
		{"arch -arch arm64 ls", "macOS arch runs a command"},

		// Writes outside the write set
		{"sort -o " + outside + " a.txt", "outside allowed directories"},
		{"uniq a.txt " + outside, "outside allowed directories"},
		{"shuf -o " + ro + " a.txt", "outside allowed directories"},
		{"dd if=a.txt of=" + outside, "outside allowed directories"},
		{"dd if=/etc/passwd of=out", "outside allowed directories"},
		{"dd if=../../../etc/passwd", "outside allowed directories"},
		{"split a.txt " + outside + "/x", "outside allowed directories"},
		{"split a.txt ../x", "outside allowed directories"},
		{"csplit -f sub -b /../../../evil%02d a.txt 2", "outside allowed directories"},
		{"csplit -f " + outside + " a.txt 2", "outside allowed directories"},
		{"gzip " + ro, "outside allowed directories"},
		{"bzip2 -k " + ro, "outside allowed directories"},
		{"xz " + ro, "outside allowed directories"},
		{"rmdir " + roDir, "outside allowed directories"},
		{"truncate -s 0 " + ro, "outside allowed directories"},
		{"shred " + ro, "outside allowed directories"},
		{"chown 1000 " + ro, "outside allowed directories"},
		{"install a " + outside, "outside allowed directories"},
		{"link a.txt " + outside, "outside allowed directories"},
		{"mkfifo " + outside, "outside allowed directories"},
		{"gzip .claude/settings.json", "read-only in the sandbox"},
		{"dd of=.claude/settings.json", "read-only in the sandbox"},
		{"split a.txt .claude/x", "read-only in the sandbox"},

		// Wrappers: the wrapped command is validated, paths included
		{"nohup curl example.com", `command "curl" is not allowed`},
		{"nice -n 5 sh -c ls", "not allowed as a wrapped subcommand"},
		{"setsid -f perl -e 1", `command "perl" is not allowed`},
		{"stdbuf -o L git push", "push"},
		{"nohup rm " + ro, "outside allowed directories"},
		{"nice cp a.txt " + outside, "outside allowed directories"},
		{"timeout 5 cp a.txt " + outside, "outside allowed directories"},
		{"env cp a.txt " + outside, "outside allowed directories"},
	} {
		t.Run(tt.command, func(t *testing.T) {
			err := checkUtilCommand(t, s, workDir, roDir, tt.command)
			if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected %q to be blocked with %q, got: %v", tt.command, tt.errMsg, err)
			}
		})
	}
}

// Targets are re-checked after expansion, where the static pass saw only a
// dynamic word.
func TestRuntime_UtilTargetsExpanded(t *testing.T) {
	for _, tt := range []string{
		`o=/etc/x; dd if=/dev/zero of="$o" count=1`,
		`i=/etc/passwd; dd if="$i"`,
		`o=/etc/x; shuf -o "$o" -e a`,
		`p=/etc/x; split /dev/null "$p"`,
		`p=/etc/x; nohup cp /dev/null "$p"`,
	} {
		t.Run(tt, func(t *testing.T) {
			_, err := runCallHandlerOnly(t, newTestSandbox(), false, tt)
			if err == nil || !strings.Contains(err.Error(), "outside allowed directories") {
				t.Fatalf("expected %q to be refused, got: %v", tt, err)
			}
		})
	}
}

// Refused options and wrapped commands are re-checked on the expanded argv.
func TestRuntime_UtilOptionsExpanded(t *testing.T) {
	for _, tt := range []struct {
		command string
		errMsg  string
	}{
		{`f=--filter=sh; split "$f" /dev/null`, "runs a shell command"},
		{`n=-N; gunzip "$n" a.gz`, "stored name"},
		{`c=curl; nohup "$c" example.com`, "dynamic command names are not allowed"},
		{`w=nohup; $w curl example.com`, `command "curl" is not allowed`},
		{`w=stdbuf; $w -oL git push`, "push"},
	} {
		t.Run(tt.command, func(t *testing.T) {
			_, err := executeInDirWithSandbox(t, newTestSandbox(), t.TempDir(), tt.command)
			if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected %q to be refused with %q, got: %v", tt.command, tt.errMsg, err)
			}
		})
	}
}
