package bash_sandboxed

import (
	"strings"
	"testing"
)

func TestValidate_AllowedWriteCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"cp file", "cp src.txt dst.txt"},
		{"cp recursive", "cp -r srcdir dstdir"},
		{"mv file", "mv old.txt new.txt"},
		{"rm file", "rm file.txt"},
		{"rm recursive", "rm -rf dir"},
		{"rm force", "rm -f file.txt"},
		{"touch file", "touch file.txt"},
		{"touch multiple", "touch a.txt b.txt c.txt"},
		{"chmod numeric", "chmod 644 file.txt"},
		{"chmod symbolic", "chmod +x script.sh"},
		{"chmod recursive", "chmod -R 755 dir"},
		{"ln hard link", "ln target link"},
		{"ln symlink", "ln -s target link"},
		{"sed substitute", "sed 's/old/new/' file.txt"},
		{"sed in-place", "sed -i 's/old/new/' file.txt"},
		{"sed in-place backup", "sed -i.bak 's/old/new/' file.txt"},
		{"sed multiple expressions", "sed -e 's/a/b/' -e 's/c/d/' file.txt"},
		{"sed delete line", "sed '/pattern/d' file.txt"},
		{"sed print", "sed -n '/pattern/p' file.txt"},
		{"sed with newword", "sed 's/old/newword/' file.txt"},
		{"sed with rewrite", "sed 's/old/rewrite/' file.txt"},
		{"sed with World", "sed 's/old/World/' file.txt"},
		{"sed with sandbox flag", "sed --sandbox 's/old/new/' file.txt"},
		{"sed in-place notes", "sed -i 's/old/new/' notes.md"},
		{"sed in-place BSD no backup", "sed -i '' 's/old/new/' file.txt"},
		{"sed in-place BSD backup", "sed -i .bak 's/old/new/' file.txt"},
		{"sed -ie", "sed -ie 's/old/new/' file.txt"},
		{"sed -e with files", "sed -n -e p -e '$=' write.txt each.txt"},
		{"sed a text", "sed '1a hello; w /x' file.txt"},
		{"tee file", "echo hi | tee out.txt"},
		{"tee append", "echo hi | tee -a out.txt"},
		{"tee multiple files", "echo hi | tee a.txt b.txt"},
		{"mktemp default", "mktemp"},
		{"mktemp dir", "mktemp -d"},
		{"mktemp template in cwd", "mktemp fileXXXXXX"},
		{"mktemp -p cwd", "mktemp -d -p ."},
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

func TestValidate_BlockedRmFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"rm --no-preserve-root", "rm -rf --no-preserve-root /", `rm flag "--no-preserve-root" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked rm flag")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_BlockedSedCommands(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		// w/W: write to files
		{"sed s///w", "sed 's/old/new/w outfile' file.txt", "not allowed"},
		{"sed W command", "sed 'W outfile' file.txt", "not allowed"},
		{"sed w after address", "sed '/pattern/w outfile' file.txt", "not allowed"},
		// e: execute shell command
		{"sed s///e", "sed 's/old/new/e' file.txt", "not allowed"},
		{"sed e command", "sed 'e' file.txt", "not allowed"},
		{"sed e after address", "sed '/pattern/e' file.txt", "not allowed"},
		// r/R: read from files
		{"sed r command", "sed 'r infile' file.txt", "not allowed"},
		{"sed R command", "sed 'R infile' file.txt", "not allowed"},
		{"sed r after address", "sed '/pattern/r infile' file.txt", "not allowed"},
		// After an address, or a blank: the script is parsed, not scanned.
		{"sed e after line", "sed '1e id' file.txt", "not allowed"},
		{"sed e after blank", "sed '1 e id' file.txt", "not allowed"},
		{"sed e after range", "sed -n '1,5e id' file.txt", "not allowed"},
		{"sed w after line", "sed '1w /tmp/x' file.txt", "not allowed"},
		{"sed w after $", "sed '$w /tmp/x' file.txt", "not allowed"},
		{"sed w in -e", "sed -e p -e '2w /tmp/x' file.txt", "not allowed"},
		{"sed unknown command", "sed 'k' file.txt", "only scripts that can be checked"},
		// BSD's bare -i takes the next argument as the suffix: the script
		// is the second operand.
		{"sed BSD in-place w", "sed -i '' '1w /tmp/x' file.txt", "not allowed"},
		{"sed BSD in-place backup w", "sed -i .bak '1w /tmp/x' file.txt", "not allowed"},
		{"sed BSD -I w", "sed -I '' '$w /tmp/x' file.txt", "not allowed"},
		// -f/--file: script files
		{"sed -f", "sed -f script.sed file.txt", "script files bypass"},
		{"sed --file", "sed --file script.sed file.txt", "script files bypass"},
		{"sed --file=", "sed --file=script.sed file.txt", "script files bypass"},
		{"sed --fi", "sed --fi script.sed file.txt", "script files bypass"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked sed command")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}
