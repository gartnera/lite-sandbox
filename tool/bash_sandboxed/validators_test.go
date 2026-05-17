package bash_sandboxed

import (
	"strings"
	"testing"
)

func TestValidate_BlockedFindFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		// -exec with a non-whitelisted command is blocked via recursive validation
		{"find -exec python", `find . -exec python {} \;`, `command "python" is not allowed`},
		{"find -execdir python", `find . -execdir python {} +`, `command "python" is not allowed`},
		{"find -ok python", `find . -ok python {} \;`, `command "python" is not allowed`},
		{"find -exec empty", `find . -exec \;`, `find -exec has no command to execute`},
		// File-write flags remain unconditionally blocked
		{"find -delete", `find . -delete`, `find flag "-delete" is not allowed`},
		{"find -fls", `find . -fls /tmp/out`, `find flag "-fls" is not allowed`},
		{"find -fprint", `find . -fprint /tmp/out`, `find flag "-fprint" is not allowed`},
		{"find -fprint0", `find . -fprint0 /tmp/out`, `find flag "-fprint0" is not allowed`},
		{"find -fprintf", `find . -fprintf /tmp/out '%p'`, `find flag "-fprintf" is not allowed`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked find flag")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_AllowedFindFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"find -name", "find . -name '*.go'"},
		{"find -type f -print", "find . -type f -print"},
		{"find -maxdepth -ls", "find . -maxdepth 2 -ls"},
		{"find -iname", "find . -iname '*.TXT'"},
		{"find -size", "find . -size +1M"},
		{"find -mtime", "find . -mtime -7"},
		// -exec with whitelisted commands is allowed
		{"find -exec grep semicolon", `find . -exec grep -l pattern {} \;`},
		{"find -exec grep plus", `find . -exec grep -l pattern {} +`},
		{"find -execdir cat", `find . -execdir cat {} +`},
		{"find -ok cat", `find . -ok cat {} \;`},
		{"find -okdir wc", `find . -okdir wc -l {} \;`},
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

func TestValidate_Xargs(t *testing.T) {
	blocked := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"xargs python", `echo file | xargs python`, `command "python" is not allowed`},
		{"xargs with blocked subcommand", `find . -name '*.go' | xargs python -c ''`, `command "python" is not allowed`},
		{"xargs -I python", `find . | xargs -I {} python {}`, `command "python" is not allowed`},
		{"xargs -n python", `find . | xargs -n1 python`, `command "python" is not allowed`},
		{"xargs -- python", `find . | xargs -- python`, `command "python" is not allowed`},
	}
	for _, tt := range blocked {
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

	allowed := []struct {
		name    string
		command string
	}{
		{"xargs grep", `find . -name '*.go' | xargs grep pattern`},
		{"xargs cat", `find . -name '*.txt' | xargs cat`},
		{"xargs wc -l", `find . | xargs wc -l`},
		{"xargs -n1 grep", `find . | xargs -n1 grep pattern`},
		{"xargs -I{} cat", `find . | xargs -I{} cat {}`},
		{"xargs -I {} cat", `find . | xargs -I {} cat {}`},
		{"xargs -0 grep", `find . -print0 | xargs -0 grep pattern`},
		{"xargs no command", `find . | xargs`},
	}
	for _, tt := range allowed {
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

func TestValidate_RecursiveFindAndXargs(t *testing.T) {
	allowed := []struct {
		name    string
		command string
	}{
		// nested find -exec: outer find runs inner find which runs grep
		{"find -exec find -exec grep", `find . -exec find . -name '*.go' -exec grep pattern {} \; \;`},
		// find -exec running xargs which runs grep
		{"find -exec xargs grep", `find . -exec xargs grep pattern {} \;`},
		// xargs running xargs which runs grep
		{"xargs xargs grep", `find . | xargs xargs grep pattern`},
		// xargs running find with -exec
		{"xargs find -exec grep", `find . | xargs find . -exec grep pattern {} \;`},
	}
	for _, tt := range allowed {
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

	blocked := []struct {
		name    string
		command string
		errMsg  string
	}{
		// nested find -exec: inner exec runs a blocked command
		{"find -exec find -exec python", `find . -exec find . -exec python {} \; \;`, `command "python" is not allowed`},
		// find -exec running xargs which runs a blocked command
		{"find -exec xargs python", `find . -exec xargs python {} \;`, `command "python" is not allowed`},
		// xargs running xargs which runs a blocked command
		{"xargs xargs python", `find . | xargs xargs python`, `command "python" is not allowed`},
		// xargs running find whose -exec runs a blocked command
		{"xargs find -exec python", `find . | xargs find . -exec python {} \;`, `command "python" is not allowed`},
	}
	for _, tt := range blocked {
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

// TestValidate_BlockedSubCommandShells verifies that bash, sh, and awk are
// rejected as find -exec / xargs subcommands. Their sandbox safety relies on
// runtime hooks (executeBash, executeAwk) that don't fire when find or xargs
// spawn them as native processes, so allowing them would bypass validation
// of the -c content or awk program.
func TestValidate_BlockedSubCommandShells(t *testing.T) {
	tests := []struct {
		name    string
		command string
	}{
		{"find -exec sh -c", `find . -exec sh -c 'cat /etc/passwd' \;`},
		{"find -exec bash -c", `find . -exec bash -c 'rm -rf /' \;`},
		{"find -execdir sh -c", `find . -execdir sh -c 'echo x' +`},
		{"find -ok bash -c", `find . -ok bash -c 'cat' \;`},
		{"find -exec awk", `find . -exec awk 'BEGIN{system("id")}' \;`},
		{"xargs sh -c", `find . | xargs sh -c 'cat /etc/passwd'`},
		{"xargs bash -c", `find . | xargs bash -c 'echo'`},
		{"xargs -I sh -c", `find . | xargs -I{} sh -c 'cat {}'`},
		{"xargs -- sh", `find . | xargs -- sh -c 'echo'`},
		{"xargs awk", `find . | xargs awk 'BEGIN{system("id")}'`},
		{"find -exec xargs sh -c", `find . -exec xargs sh -c 'echo' \;`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for shell subcommand via find/xargs")
			}
			if !strings.Contains(err.Error(), "not allowed as a find -exec or xargs subcommand") {
				t.Fatalf("expected subcommand denylist error, got %q", err.Error())
			}
		})
	}
}

func TestValidate_BlockedTarFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"tar extract", "tar -xf archive.tar", "tar flag '-x' is not allowed"},
		{"tar create", "tar -cf archive.tar .", "tar flag '-c' is not allowed"},
		{"tar append", "tar -rf archive.tar file", "tar flag '-r' is not allowed"},
		{"tar update", "tar -uf archive.tar file", "tar flag '-u' is not allowed"},
		{"tar delete", "tar --delete -f archive.tar file", `tar flag "--delete" is not allowed`},
		{"tar extract long", "tar --extract -f archive.tar", `tar flag "--extract" is not allowed`},
		{"tar get long", "tar --get -f archive.tar", `tar flag "--get" is not allowed`},
		{"tar create long", "tar --create -f archive.tar .", `tar flag "--create" is not allowed`},
		{"tar append long", "tar --append -f archive.tar file", `tar flag "--append" is not allowed`},
		{"tar update long", "tar --update -f archive.tar file", `tar flag "--update" is not allowed`},
		{"tar extract combined", "tar -xzf archive.tar.gz", "tar flag '-x' is not allowed"},
		{"tar old style extract", "tar xf archive.tar", "tar flag 'x' is not allowed"},
		{"tar old style create", "tar czf archive.tar.gz .", "tar flag 'c' is not allowed"},
		{"tar no mode flag", "tar -f archive.tar", "tar is only allowed in list mode"},
		{"tar verbose only", "tar -v", "tar is only allowed in list mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked tar flag")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_BlockedUnzipFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"unzip extract default", "unzip archive.zip", "unzip is only allowed with"},
		{"unzip with dir", "unzip -d /tmp archive.zip", "unzip is only allowed with"},
		{"unzip overwrite", "unzip -o archive.zip", "unzip is only allowed with"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked unzip usage")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_BlockedArFlags(t *testing.T) {
	tests := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"ar replace", "ar r archive.a file.o", "ar operation 'r' is not allowed"},
		{"ar delete", "ar d archive.a file.o", "ar operation 'd' is not allowed"},
		{"ar quick append", "ar q archive.a file.o", "ar operation 'q' is not allowed"},
		{"ar extract", "ar x archive.a", "ar operation 'x' is not allowed"},
		{"ar move", "ar m archive.a file.o", "ar operation 'm' is not allowed"},
		{"ar no args", "ar", "ar requires an operation argument"},
		{"ar create with s", "ar s archive.a", "ar operation 's' is not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil {
				t.Fatal("expected validation error for blocked ar operation")
			}
			if !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}

func TestValidate_RgPre(t *testing.T) {
	blocked := []struct {
		name    string
		command string
		errMsg  string
	}{
		{"rg --pre python", "rg --pre python pattern", `command "python" is not allowed`},
		{"rg --pre=python", "rg --pre=python pattern", `command "python" is not allowed`},
		{"rg --pre curl", "rg --pre curl pattern", `command "curl" is not allowed`},
		{"rg --pre no arg", "rg --pre", `rg --pre requires a command argument`},
	}
	for _, tt := range blocked {
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

	allowed := []struct {
		name    string
		command string
	}{
		{"rg --pre cat", "rg --pre cat pattern"},
		{"rg --pre=cat", "rg --pre=cat pattern"},
		{"rg --pre zcat", "rg --pre zcat pattern"},
		{"rg --pre-glob without pre", "rg pattern"},
		{"rg empty --pre=", "rg --pre= pattern"},
	}
	for _, tt := range allowed {
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
