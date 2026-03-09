package bash_sandboxed

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gartnera/lite-sandbox/config"
)

func TestParseBash_Valid(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"simple echo", "echo hello"},
		{"pipe", "echo hello | grep hello"},
		{"variable", "FOO=bar echo $FOO"},
		{"subshell", "(echo hello)"},
		{"multiline", "echo hello\necho world"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("expected valid bash, got error: %v", err)
			}
			if f == nil {
				t.Fatal("expected non-nil AST")
			}
		})
	}
}

func TestParseBash_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"unclosed quote", "echo 'hello"},
		{"unclosed paren", "(echo hello"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseBash(tt.command)
			if err == nil {
				t.Fatal("expected error for invalid bash")
			}
		})
	}
}

func TestBashSandboxed_Executes(t *testing.T) {
	workDir := t.TempDir()
	out, err := NewSandbox().Execute(context.Background(), "echo hello", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "hello\n" {
		t.Fatalf("expected 'hello\\n', got %q", out)
	}
}

func TestBashSandboxed_FailingCommand(t *testing.T) {
	workDir := t.TempDir()
	_, err := NewSandbox().Execute(context.Background(), "false", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected error for failing command")
	}
}

func TestBashSandboxed_InvalidSyntax(t *testing.T) {
	workDir := t.TempDir()
	_, err := NewSandbox().Execute(context.Background(), "echo 'hello", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected error for invalid syntax")
	}
}

func TestValidate_AllowedCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"echo", "echo hello"},
		{"ls", "ls -la"},
		{"grep pipe", "echo foo | grep foo"},
		{"cat", "cat /etc/hostname"},
		{"variable assignment", "FOO=bar"},
		{"variable with command", "FOO=bar echo $FOO"},
		{"if statement", "if true; then echo yes; fi"},
		{"for loop", "for i in 1 2 3; do echo $i; done"},
		{"while loop", "while true; do echo loop; break; done"},
		{"case statement", "case $x in foo) echo foo;; esac"},
		{"subshell", "(echo hello)"},
		{"block", "{ echo hello; }"},
		{"and operator", "true && echo yes"},
		{"or operator", "false || echo no"},
		{"test bracket", "[ -f /etc/passwd ]"},
		{"bash test", "[[ -f /etc/passwd ]]"},
		{"command substitution", "echo $(whoami)"},
		{"backtick substitution", "echo `whoami`"},
		{"arithmetic", "echo $((1 + 2))"},
		{"function declaration", "foo() { echo hello; }"},
		{"negation", "! false"},
		{"background", "sleep 1 &"},
		{"multiline", "echo hello\necho world"},
		{"jq", "echo '{}' | jq ."},
		{"find", "find . -name '*.go'"},
		{"sort uniq", "echo hello | sort | uniq"},
		{"declare", "declare -a arr"},
		{"export", "export FOO=bar"},
		{"cd", "cd subdir"},
		{"mkdir", "mkdir newdir"},
		{"mkdir -p", "mkdir -p a/b/c"},
		{"pwd", "pwd"},
		{"date", "date"},
		{"head", "head -5 /etc/hostname"},
		{"tail", "tail -5 /etc/hostname"},
		{"wc", "echo hello | wc -l"},
		{"cut", "echo hello | cut -c1-3"},
		{"tr", "echo hello | tr a-z A-Z"},
		{"diff", "diff /dev/null /dev/null"},
		{"seq", "seq 1 10"},
		{"bc", "echo '1+1' | bc"},
		{"zcat", "zcat --help"},
		{"strings", "strings /bin/ls"},
		{"stat", "stat /etc/hostname"},
		{"file", "file /etc/hostname"},
		{"du", "du -sh /tmp"},
		{"df", "df -h"},
		{"basename", "basename /etc/hostname"},
		{"dirname", "dirname /etc/hostname"},
		{"id", "id"},
		{"uname", "uname -a"},
		{"timeout", "timeout 1 echo hello"},
		{"command", "command -v echo"},
		{"tar list", "tar -tf archive.tar"},
		{"tar list verbose", "tar -tvf archive.tar"},
		{"tar list gz", "tar -tzf archive.tar.gz"},
		{"tar list bz2", "tar -tjf archive.tar.bz2"},
		{"tar list xz", "tar -tJf archive.tar.xz"},
		{"tar list long", "tar --list -f archive.tar"},
		{"tar old style list", "tar tf archive.tar"},
		{"tar old style list gz", "tar tzf archive.tar.gz"},
		{"unzip list", "unzip -l archive.zip"},
		{"unzip test", "unzip -t archive.zip"},
		{"unzip zipinfo mode", "unzip -Z archive.zip"},
		{"zipinfo", "zipinfo archive.zip"},
		{"ar list", "ar t archive.a"},
		{"ar print", "ar p archive.a"},
		{"ar list with dash", "ar -t archive.a"},
		{"ar print verbose", "ar tv archive.a"},
		// New commands: output/display
		{"col", "man ls | col -b"},
		{"colrm", "echo abcdefgh | colrm 3 5"},
		{"vis", "vis file.txt"},
		{"unvis", "unvis file.txt"},
		{"fmt", "fmt -w 72 file.txt"},
		// New commands: search
		{"rg", "rg pattern ."},
		{"rg with flags", "rg -n --type go pattern"},
		{"look", "look prefix file.txt"},
		// New commands: file info
		{"shasum", "shasum -a 256 file.txt"},
		{"pathchk", "pathchk -p file.txt"},
		// New commands: text processing
		{"tsort", "tsort deps.txt"},
		{"iconv", "iconv -f UTF-8 -t ASCII file.txt"},
		{"base64 encode", "echo hello | base64"},
		{"base64 decode", "echo aGVsbG8= | base64 -d"},
		{"base64 with file", "base64 -i input.txt -o output.txt"},
		// New commands: computation
		{"uuidgen", "uuidgen"},
		// Shell sourcing
		{"source file", "source ./lib.sh"},
		{"dot source file", ". ./lib.sh"},
		{"source absolute", "source /tmp/lib.sh"},
		{"dot source absolute", ". /tmp/lib.sh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidate_BlockedCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"chown", "chown root file", `command "chown" is not allowed`},
		{"rmdir", "rmdir dir", `command "rmdir" is not allowed`},
		{"dd", "dd if=/dev/zero of=file", `command "dd" is not allowed`},
		{"mkfs", "mkfs /dev/sda", `command "mkfs" is not allowed`},
		{"mount", "mount /dev/sda /mnt", `command "mount" is not allowed`},
		{"umount", "umount /mnt", `command "umount" is not allowed`},
		{"kill", "kill 1234", `command "kill" is not allowed`},
		{"killall", "killall nginx", `command "killall" is not allowed`},
		{"reboot", "reboot", `command "reboot" is not allowed`},
		{"shutdown", "shutdown now", `command "shutdown" is not allowed`},
		{"systemctl", "systemctl stop nginx", `command "systemctl" is not allowed`},
		{"useradd", "useradd user", `command "useradd" is not allowed`},
		{"userdel", "userdel user", `command "userdel" is not allowed`},
		{"passwd", "passwd", `command "passwd" is not allowed`},
		{"su", "su root", `command "su" is not allowed`},
		{"sudo", "sudo echo hi", `command "sudo" is not allowed`},
		{"iptables", "iptables -F", `command "iptables" is not allowed`},
		{"crontab", "crontab -l", `command "crontab" is not allowed`},

		// Code execution (trivial sandbox bypass)
		{"python", "python -c 'import os; os.system(\"rm -rf /\")'", `command "python" is not allowed`},
		{"python3", "python3 -c 'print(1)'", `command "python3" is not allowed`},
		{"node", "node -e 'console.log(1)'", `command "node" is not allowed`},
		{"ruby", "ruby -e 'puts 1'", `command "ruby" is not allowed`},
		{"perl", "perl -e 'print 1'", `command "perl" is not allowed`},
		{"go", "go run main.go", `command "go" is not allowed`},
		{"java", "java Main", `command "java" is not allowed`},
		{"javac", "javac Main.java", `command "javac" is not allowed`},
		{"gcc", "gcc -o a a.c", `command "gcc" is not allowed`},
		{"g++", "g++ -o a a.cpp", `command "g++" is not allowed`},
		{"rustc", "rustc main.rs", `command "rustc" is not allowed (runtimes.rust.enabled is disabled)`},
		{"make", "make all", `command "make" is not allowed`},

		// Package managers (arbitrary code execution via install scripts)
		{"npm", "npm install", `command "npm" is not allowed`},
		{"npx", "npx something", `command "npx" is not allowed`},
		{"yarn", "yarn install", `command "yarn" is not allowed`},
		{"pip", "pip install requests", `command "pip" is not allowed`},
		{"pip3", "pip3 install requests", `command "pip3" is not allowed`},
		{"cargo", "cargo build", `command "cargo" is not allowed (runtimes.rust.enabled is disabled)`},

		// Networking (data exfiltration / remote code fetch)
		{"curl", "curl https://example.com", `command "curl" is not allowed`},
		{"wget", "wget https://example.com", `command "wget" is not allowed`},
		{"ping", "ping example.com", `command "ping" is not allowed`},
		{"nmap", "nmap localhost", `command "nmap" is not allowed`},
		{"dig", "dig example.com", `command "dig" is not allowed`},
		{"nslookup", "nslookup example.com", `command "nslookup" is not allowed`},
		{"host", "host example.com", `command "host" is not allowed`},
		{"ip", "ip addr", `command "ip" is not allowed`},
		{"ifconfig", "ifconfig", `command "ifconfig" is not allowed`},
		{"netstat", "netstat -tulpn", `command "netstat" is not allowed`},
		{"ss", "ss -tulpn", `command "ss" is not allowed`},
		{"traceroute", "traceroute example.com", `command "traceroute" is not allowed`},

		// Archive processing (arbitrary file writes)
		{"gzip", "gzip file", `command "gzip" is not allowed`},
		{"gunzip", "gunzip file.gz", `command "gunzip" is not allowed`},

		// Version control (hook execution, remote code fetch)
		{"gh", "gh pr list", `command "gh" is not allowed`},
		{"svn", "svn checkout https://example.com/repo", `command "svn" is not allowed`},

		// Shell escape commands (bypass whitelist)
		{"eval", "eval echo hello", `command "eval" is not allowed`},
		{"exec", "exec echo hello", `command "exec" is not allowed`},
		{"bare source", "source", `bare "source"`},
		{"bare dot source", ".", `bare "."`},
		{"xargs with blocked command", "echo hello | xargs python", `command "python" is not allowed`},

		// Text processing with write capability
		{"tee", "echo hello | tee file", `command "tee" is not allowed`},
		{"csplit", "csplit file /pattern/", `command "csplit" is not allowed`},

		// Interactive / potentially disruptive
		{"top", "top", `command "top" is not allowed`},
		{"htop", "htop", `command "htop" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_AllowedProcSubst(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"input substitution with allowed commands", "diff <(echo a) <(echo b)"},
		{"output substitution with allowed command", "echo hello > >(cat)"},
		{"sort with two process substitutions", "comm <(sort file1) <(sort file2)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected process substitution to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidate_BlockedProcSubst(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"blocked command inside input substitution", `diff <(python3 script.py) <(echo b)`, `command "python3" is not allowed`},
		{"blocked command inside output substitution", `echo hello > >(python3 script.py)`, `command "python3" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked command in process substitution")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_BlockedInPipeline(t *testing.T) {
	f, err := ParseBash("echo hello | python script.py")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = newTestSandbox().validate(f)
	if err == nil {
		t.Fatal("expected validation error for blocked command in pipeline")
	}
	if !strings.Contains(err.Error(), `"python"`) {
		t.Fatalf("expected python error, got %q", err.Error())
	}
}

func TestValidate_BlockedInSubshell(t *testing.T) {
	f, err := ParseBash("(python script.py)")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = newTestSandbox().validate(f)
	if err == nil {
		t.Fatal("expected validation error for blocked command in subshell")
	}
}

func TestValidate_BlockedInIfBody(t *testing.T) {
	f, err := ParseBash("if true; then python script.py; fi")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = newTestSandbox().validate(f)
	if err == nil {
		t.Fatal("expected validation error for blocked command in if body")
	}
}

func TestValidate_BlockedInForLoop(t *testing.T) {
	f, err := ParseBash("for i in 1 2 3; do python $i; done")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = newTestSandbox().validate(f)
	if err == nil {
		t.Fatal("expected validation error for blocked command in for loop")
	}
}

func TestValidate_BlockedInCommandSubstitution(t *testing.T) {
	f, err := ParseBash("echo $(python script.py)")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = newTestSandbox().validate(f)
	if err == nil {
		t.Fatal("expected validation error for blocked command in command substitution")
	}
}

func TestValidate_DynamicCommandBlocked(t *testing.T) {
	// Commands that can't be statically determined should be blocked
	f, err := ParseBash("$CMD arg1 arg2")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	err = newTestSandbox().validate(f)
	if err == nil {
		t.Fatal("expected validation error for dynamic command name")
	}
}

func TestValidate_BlockedEnvVars(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		// Bare assignments
		{"PATH assignment", "PATH=/tmp/evil:$PATH", "setting PATH is not allowed"},
		{"LD_PRELOAD assignment", "LD_PRELOAD=/tmp/evil.so", "setting LD_PRELOAD is not allowed"},
		{"LD_LIBRARY_PATH assignment", "LD_LIBRARY_PATH=/tmp/evil", "setting LD_LIBRARY_PATH is not allowed"},
		{"BASH_ENV assignment", "BASH_ENV=/tmp/evil.sh", "setting BASH_ENV is not allowed"},
		{"ENV assignment", "ENV=/tmp/evil.sh", "setting ENV is not allowed"},
		{"CDPATH assignment", "CDPATH=/tmp", "setting CDPATH is not allowed"},
		{"PROMPT_COMMAND assignment", "PROMPT_COMMAND=evil", "setting PROMPT_COMMAND is not allowed"},
		// Inline assignments with command
		{"PATH inline", "PATH=/tmp/evil echo hello", "setting PATH is not allowed"},
		// export/declare
		{"export PATH", "export PATH=/tmp/evil", "setting PATH is not allowed"},
		{"declare PATH", "declare PATH=/tmp/evil", "setting PATH is not allowed"},
		{"export LD_PRELOAD", "export LD_PRELOAD=/tmp/evil.so", "setting LD_PRELOAD is not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked env var")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_AllowedEnvVars(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"FOO assignment", "FOO=bar"},
		{"FOO with command", "FOO=bar echo $FOO"},
		{"export FOO", "export FOO=bar"},
		{"declare FOO", "declare -a arr"},
		{"HOME assignment", "HOME=/tmp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected command to be allowed, got: %v", err)
			}
		})
	}
}

func TestValidate_ExtraCommands(t *testing.T) {
	s := NewSandbox()

	// curl should be blocked by default
	f, err := ParseBash("curl https://example.com")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if err := s.validate(f); err == nil {
		t.Fatal("expected curl to be blocked by default")
	}

	// After adding curl as an extra command, it should be allowed
	s.UpdateConfig(&config.Config{ExtraCommands: []string{"curl"}}, "")
	if err := s.validate(f); err != nil {
		t.Fatalf("expected curl to be allowed with extra commands, got: %v", err)
	}

	// After clearing extra commands, curl should be blocked again
	s.UpdateConfig(&config.Config{}, "")
	if err := s.validate(f); err == nil {
		t.Fatal("expected curl to be blocked after clearing extra commands")
	}
}

func TestValidate_ExtraCommandsSubcommand(t *testing.T) {
	tests := []struct {
		name        string
		extraCmds   []string
		command     string
		wantErr     bool
		errSubstr   string
	}{
		{
			name:      "pnpx allowed when exact entry matches",
			extraCmds: []string{"pnpx prettier"},
			command:   "pnpx prettier --check .",
			wantErr:   false,
		},
		{
			name:      "pnpx blocked when package not in list",
			extraCmds: []string{"pnpx prettier"},
			command:   "pnpx cowsay hello",
			wantErr:   true,
			errSubstr: `"pnpx" is not allowed`,
		},
		{
			name:      "pnpx allowed with multiple entries",
			extraCmds: []string{"pnpx prettier", "pnpx eslint"},
			command:   "pnpx eslint .",
			wantErr:   false,
		},
		{
			name:      "pnpx second package blocked when not in list",
			extraCmds: []string{"pnpx prettier", "pnpx eslint"},
			command:   "pnpx cowsay hello",
			wantErr:   true,
			errSubstr: `"pnpx" is not allowed`,
		},
		{
			name:      "bare pnpx entry allows any package",
			extraCmds: []string{"pnpx"},
			command:   "pnpx cowsay hello",
			wantErr:   false,
		},
		{
			name:      "pnpx no args allowed (prints help)",
			extraCmds: []string{"pnpx prettier"},
			command:   "pnpx",
			wantErr:   false,
		},
		{
			name:      "pnpx only flags allowed (prints help)",
			extraCmds: []string{"pnpx prettier"},
			command:   "pnpx --version",
			wantErr:   false,
		},
		{
			name:      "subcommand restriction applies to any command not just pnpx",
			extraCmds: []string{"curl https://example.com"},
			command:   "curl https://example.com",
			wantErr:   false,
		},
		{
			name:      "subcommand restriction blocks different first arg",
			extraCmds: []string{"curl https://example.com"},
			command:   "curl https://evil.com",
			wantErr:   true,
			errSubstr: `"curl" is not allowed`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSandbox()
			s.UpdateConfig(&config.Config{ExtraCommands: tt.extraCmds}, "")
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = s.validate(f)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("expected error containing %q, got %q", tt.errSubstr, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestValidate_ExtraCommandsSkipsValidators(t *testing.T) {
	// pnpm dlx is blocked by validatePnpmCommand when pnpm is enabled.
	// Adding "pnpm dlx" to extra_commands should bypass that validator entirely.
	pnpmEnabled := &config.RuntimesConfig{
		Pnpm: &config.PnpmConfig{Enabled: boolPtr(true)},
	}
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		Runtimes:      pnpmEnabled,
		ExtraCommands: []string{"pnpm dlx"},
	}, "")

	f, err := ParseBash("pnpm dlx cowsay hello")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if err := s.validate(f); err != nil {
		t.Fatalf("expected pnpm dlx to be allowed via extra_commands, got: %v", err)
	}
}

func TestValidate_ExtraCommandsSubcommandStillValidatesOtherSubcommands(t *testing.T) {
	// "git push" in extra_commands bypasses the git validator for push,
	// but other git subcommands must still be validated normally.
	// Use remote_read=false so git fetch is blocked by the validator.
	remoteFalse := false
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		Git:           &config.GitConfig{RemoteRead: &remoteFalse},
		ExtraCommands: []string{"git push"},
	}, "")

	// git push is allowed (validator skipped via extra_commands).
	f, err := ParseBash("git push origin main")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if err := s.validate(f); err != nil {
		t.Fatalf("expected git push to be allowed via extra_commands, got: %v", err)
	}

	// git fetch still goes through validateGitCommand and is blocked.
	f, err = ParseBash("git fetch origin")
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if err := s.validate(f); err == nil {
		t.Fatal("expected git fetch to be blocked by git validator")
	} else if !strings.Contains(err.Error(), "remote") {
		t.Fatalf("expected remote-related error, got: %v", err)
	}
}

func TestFirstCommandWord(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"fvm flutter test", "fvm"},
		{"  fvm flutter test", "fvm"},
		{"echo hello", "echo"},
		{"fvm", "fvm"},
		{"", ""},
		{"echo hello | grep x", "echo"},
		{"fvm && rm -rf /", "fvm"},
		{"(subshell)", ""},
		{"$CMD arg", ""},
	}
	for _, tt := range tests {
		got := firstCommandWord(tt.input)
		if got != tt.want {
			t.Errorf("firstCommandWord(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestIsExtraCommandInvocation(t *testing.T) {
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		ExtraCommands: []string{"fvm", "fvm flutter test", "pnpx prettier"},
	}, "")

	tests := []struct {
		command string
		want    bool
	}{
		// "fvm" has a bare entry → bypass
		{"fvm flutter test test/foo_test.dart", true},
		{"fvm --version", true},
		{"fvm", true},
		// "pnpx" only has a restricted entry → no bypass
		{"pnpx prettier --check .", false},
		// unknown command → no bypass
		{"curl https://example.com", false},
		{"echo hello", false},
	}
	for _, tt := range tests {
		got := s.isExtraCommandInvocation(tt.command)
		if got != tt.want {
			t.Errorf("isExtraCommandInvocation(%q) = %v, want %v", tt.command, got, tt.want)
		}
	}
}

func TestExecute_ExtraCommandBypassesParsing(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		ExtraCommands: []string{"echo"},
	}, "")

	// "echo" is in allowedCommands, but add it as extra to test bare-entry bypass path
	// Use a real bare extra command: just verify it executes without validation error
	out, err := s.Execute(context.Background(), "echo bypassed", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "bypassed") {
		t.Fatalf("expected 'bypassed' in output, got %q", out)
	}
}

func TestValidateCommand_ExtraCommandBypass(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		ExtraCommands: []string{"fvm"},
	}, "")

	// fvm is not a real command but ValidateCommand should pass for bare extra entries
	err := s.ValidateCommand("fvm flutter test test/foo_test.dart", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("expected bypass for bare extra command, got: %v", err)
	}
}

func TestConfigPaths(t *testing.T) {
	s := NewSandbox()

	// Initially empty
	if got := s.ConfigReadPaths(); got != nil {
		t.Fatalf("expected nil config read paths, got %v", got)
	}
	if got := s.ConfigWritePaths(); got != nil {
		t.Fatalf("expected nil config write paths, got %v", got)
	}

	// After UpdateConfig with paths
	s.UpdateConfig(&config.Config{
		ReadablePaths: []string{"/tmp/readable"},
		WritablePaths: []string{"/tmp/writable"},
	}, "")
	if got := s.ConfigReadPaths(); len(got) != 1 || got[0] != "/tmp/readable" {
		t.Fatalf("expected [/tmp/readable], got %v", got)
	}
	if got := s.ConfigWritePaths(); len(got) != 1 || got[0] != "/tmp/writable" {
		t.Fatalf("expected [/tmp/writable], got %v", got)
	}

	// After clearing config
	s.UpdateConfig(&config.Config{}, "")
	if got := s.ConfigReadPaths(); got != nil {
		t.Fatalf("expected nil after clearing, got %v", got)
	}
	if got := s.ConfigWritePaths(); got != nil {
		t.Fatalf("expected nil after clearing, got %v", got)
	}
}

func TestValidateCommand(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()

	// Valid command should pass
	err := s.ValidateCommand("echo hello", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("expected valid command to pass, got: %v", err)
	}

	// Piped valid commands should pass
	err = s.ValidateCommand("ls -la | grep foo", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("expected valid piped command to pass, got: %v", err)
	}

	// Blocked command should fail
	err = s.ValidateCommand("python script.py", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected blocked command to fail validation")
	}

	// Invalid syntax should fail
	err = s.ValidateCommand("echo 'hello", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected invalid syntax to fail validation")
	}

	// Path outside allowed paths should fail
	err = s.ValidateCommand("cat /etc/passwd", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected path outside allowed dirs to fail validation")
	}
}

func TestValidateCommand_ScriptWithBlockedCommand(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		LocalBinaryExecution: &config.LocalBinaryExecutionConfig{
			Enabled: boolPtr(true),
		},
	}, "")

	// Create a script that uses a blocked command (curl)
	scriptPath := filepath.Join(workDir, "bad-script.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/bash\ncurl http://evil.com\necho hello\n"), 0755)

	// Direct script invocation should fail validation
	err := s.ValidateCommand("./bad-script.sh", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected validation to fail for script containing 'curl'")
	}
	if !strings.Contains(err.Error(), "curl") {
		t.Fatalf("expected error about 'curl', got: %v", err)
	}

	// bash with script file should also fail
	err = s.ValidateCommand("bash ./bad-script.sh", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected validation to fail for bash with script containing 'curl'")
	}
	if !strings.Contains(err.Error(), "curl") {
		t.Fatalf("expected error about 'curl', got: %v", err)
	}
}

func TestValidateCommand_ScriptWithAllowedCommands(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		LocalBinaryExecution: &config.LocalBinaryExecutionConfig{
			Enabled: boolPtr(true),
		},
	}, "")

	// Create a script with only allowed commands
	scriptPath := filepath.Join(workDir, "good-script.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/bash\necho hello\nls -la\n"), 0755)

	err := s.ValidateCommand("./good-script.sh", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("expected validation to pass for script with allowed commands, got: %v", err)
	}

	err = s.ValidateCommand("bash ./good-script.sh", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("expected validation to pass for bash with allowed script, got: %v", err)
	}
}

func TestValidateCommand_ScriptNotFound(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		LocalBinaryExecution: &config.LocalBinaryExecutionConfig{
			Enabled: boolPtr(true),
		},
	}, "")

	// Script doesn't exist — should fail-open (no error)
	err := s.ValidateCommand("./nonexistent.sh", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("expected fail-open for nonexistent script, got: %v", err)
	}
}

func TestValidateCommand_NestedScriptWithBlockedCommand(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		LocalBinaryExecution: &config.LocalBinaryExecutionConfig{
			Enabled: boolPtr(true),
		},
	}, "")

	// Create inner script with blocked command
	innerPath := filepath.Join(workDir, "inner.sh")
	os.WriteFile(innerPath, []byte("#!/bin/bash\ncurl http://example.com\n"), 0755)

	// Create outer script that calls inner
	outerPath := filepath.Join(workDir, "outer.sh")
	os.WriteFile(outerPath, []byte("#!/bin/bash\n./inner.sh\n"), 0755)

	err := s.ValidateCommand("./outer.sh", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected validation to fail for nested script with blocked command")
	}
	if !strings.Contains(err.Error(), "curl") {
		t.Fatalf("expected error about 'curl', got: %v", err)
	}
}

func TestValidateCommand_BashWithFlags(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()
	s.UpdateConfig(&config.Config{
		LocalBinaryExecution: &config.LocalBinaryExecutionConfig{
			Enabled: boolPtr(true),
		},
	}, "")

	// Create a script with blocked command
	scriptPath := filepath.Join(workDir, "script.sh")
	os.WriteFile(scriptPath, []byte("#!/bin/bash\npython -c 'print(1)'\n"), 0755)

	// bash -e ./script.sh should fail
	err := s.ValidateCommand("bash -e ./script.sh", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected validation to fail for bash -e with script containing blocked command")
	}
}

func TestExecute_Timeout(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()

	// Create a context with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Command that sleeps longer than the timeout
	_, err := s.Execute(ctx, "sleep 10", workDir, []string{workDir}, []string{workDir})
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatalf("expected context deadline exceeded error, got: %v", err)
	}
}

func TestExecute_CompletesBeforeTimeout(t *testing.T) {
	workDir := t.TempDir()
	s := NewSandbox()

	// Create a context with a generous timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Command that completes quickly
	out, err := s.Execute(ctx, "echo fast", workDir, []string{workDir}, []string{workDir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "fast\n" {
		t.Fatalf("expected 'fast\\n', got %q", out)
	}
}
