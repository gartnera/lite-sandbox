package bash_sandboxed

import (
	"archive/tar"
	"archive/zip"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePaths_ExtractDestination(t *testing.T) {
	workDir := t.TempDir()
	readOnlyDir := t.TempDir()
	os.Mkdir(filepath.Join(workDir, "out"), 0o755)
	os.Mkdir(filepath.Join(workDir, "sub"), 0o755)
	// A symlink inside the boundary that points at the read-only directory.
	os.Symlink(readOnlyDir, filepath.Join(workDir, "link"))

	readPaths := []string{workDir, readOnlyDir}
	writePaths := []string{workDir}

	allowed := []string{
		"tar -xf archive.tar",
		"tar -xf archive.tar -C out",
		"tar -xf archive.tar -Cout",
		"tar -xf archive.tar --directory=" + workDir + "/out",
		"tar xfC archive.tar out",
		"tar -xf " + readOnlyDir + "/archive.tar -C out",
		"tar -tf " + readOnlyDir + "/archive.tar",
		"tar -tf archive.tar -C " + readOnlyDir,
		"unzip archive.zip",
		"unzip archive.zip -d out",
		"unzip -dout archive.zip",
		"unzip " + readOnlyDir + "/archive.zip -d out",
		"unzip -l archive.zip -d " + readOnlyDir,
		"unzip -Z archive.zip",
	}
	for _, cmd := range allowed {
		t.Run("allowed/"+cmd, func(t *testing.T) {
			f, err := ParseBash(cmd)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := validatePaths(f, workDir, readPaths, writePaths); err != nil {
				t.Fatalf("expected %q to be allowed, got: %v", cmd, err)
			}
		})
	}

	blocked := []string{
		"tar -xf archive.tar -C " + readOnlyDir,
		"tar -xf archive.tar -C" + readOnlyDir,
		"tar -xf archive.tar --directory=" + readOnlyDir,
		"tar -xf archive.tar --dir " + readOnlyDir,
		"tar -xf archive.tar --cd " + readOnlyDir,
		"tar xfC archive.tar " + readOnlyDir,
		"tar -xf archive.tar -C link",
		"tar -xf archive.tar -C sub/../link",
		"tar -xf archive.tar -C /",
		"unzip archive.zip -d " + readOnlyDir,
		"unzip -d" + readOnlyDir + " archive.zip",
		"unzip -od " + readOnlyDir + " archive.zip",
		"unzip archive.zip -d link",
	}
	for _, cmd := range blocked {
		t.Run("blocked/"+cmd, func(t *testing.T) {
			f, err := ParseBash(cmd)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validatePaths(f, workDir, readPaths, writePaths)
			if err == nil {
				t.Fatalf("expected %q to be blocked", cmd)
			}
			if !strings.Contains(err.Error(), "outside allowed directories") {
				t.Fatalf("expected outside allowed directories error, got %q", err.Error())
			}
		})
	}

	t.Run("working directory must be writable", func(t *testing.T) {
		for _, cmd := range []string{"tar -xf archive.tar", "tar -xf archive.tar -C " + workDir + "/out", "unzip archive.zip", "unzip archive.zip -d " + workDir + "/out"} {
			f, err := ParseBash(cmd)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = validatePaths(f, readOnlyDir, readPaths, writePaths)
			if err == nil || !strings.Contains(err.Error(), "extracts into the working directory") {
				t.Fatalf("expected %q in a read-only directory to be blocked, got %v", cmd, err)
			}
		}
	})
}

func TestValidate_ZipArgs(t *testing.T) {
	allowed := []string{
		"zip out.zip file.txt",
		"zip -r out.zip dir",
		"zip -rq9 out.zip dir",
		"zip -r out.zip . -x '*.git*' 'node_modules/*'",
		"zip -r out.zip . -x'*.o' -i 'src/*'",
		"zip --recurse-paths --quiet out.zip dir",
		"zip -r out.zip dir --exclude '*.log'",
		"zip -ry out.zip dir",
		"zip -d out.zip old.txt",
		"zip -u out.zip file.txt",
		"zip -T out.zip file.txt",
		"zip -P secret out.zip file.txt",
		"zip -Z store out.zip file.txt",
		"zip --compression-method=deflate out.zip file.txt",
		"zip -q- out.zip file.txt",
		"zip - file.txt",
		"zip -r - dir > out.zip",
	}
	for _, cmd := range allowed {
		t.Run("allowed/"+cmd, func(t *testing.T) {
			f, err := ParseBash(cmd)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			if err := newTestSandbox().validate(f); err != nil {
				t.Fatalf("expected %q to be allowed, got: %v", cmd, err)
			}
		})
	}

	blocked := []struct {
		command string
		errMsg  string
	}{
		{"zip out.zip file.txt -T -TT 'sh -c id'", "zip option -TT is not allowed"},
		{"zip -rTT id out.zip dir", "zip option -TT is not allowed"},
		{"zip out.zip file.txt --unzip-command=id", `zip option "--unzip-command=id" is not allowed`},
		{"zip out.zip -@", "zip option -@ is not allowed"},
		{"zip --names-stdin out.zip", "is not allowed"},
		{"zip -m out.zip file.txt", "zip option -m is not allowed"},
		{"zip --move out.zip file.txt", "is not allowed"},
		{"zip -b /tmp out.zip file.txt", "zip option -b is not allowed"},
		{"zip -O /tmp/x.zip out.zip", "zip option -O is not allowed"},
		{"zip --output-file=/tmp/x.zip out.zip", "is not allowed"},
		{"zip -lf /tmp/log out.zip file.txt", "zip option -lf is not allowed"},
		{"zip --logfile-path=/tmp/log out.zip file.txt", "is not allowed"},
		{"zip -FS out.zip dir", "zip option -FS is not allowed"},
		{"zip --recurse out.zip dir", "is not allowed"},
		{"zip -x '*.o' -r out.zip dir", "must come after the archive name"},
		{"zip -P -TT out.zip file.txt", "looks like an option"},
		{"ZIPOPT='-TT id' zip -T out.zip file.txt", "setting ZIPOPT is not allowed"},
		{"env ZIP=-m zip out.zip file.txt", "setting ZIP is not allowed"},
	}
	for _, tt := range blocked {
		t.Run("blocked/"+tt.command, func(t *testing.T) {
			f, err := ParseBash(tt.command)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil || !strings.Contains(err.Error(), tt.errMsg) {
				t.Fatalf("expected error containing %q, got %v", tt.errMsg, err)
			}
		})
	}
}

func TestValidatePaths_ZipArchiveWriteChecked(t *testing.T) {
	workDir := t.TempDir()
	readOnlyDir := t.TempDir()
	os.WriteFile(filepath.Join(readOnlyDir, "data.txt"), []byte("hi"), 0o644)
	readPaths := []string{workDir, readOnlyDir}
	writePaths := []string{workDir}

	for _, cmd := range []string{
		"zip out.zip " + readOnlyDir + "/data.txt",
		"zip -r out.zip " + readOnlyDir,
		"zip -r " + workDir + "/out.zip . -x " + readOnlyDir,
		"zip -r - " + readOnlyDir,
	} {
		f, err := ParseBash(cmd)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		if err := validatePaths(f, workDir, readPaths, writePaths); err != nil {
			t.Fatalf("expected %q to be allowed, got: %v", cmd, err)
		}
	}
	for _, cmd := range []string{
		"zip " + readOnlyDir + "/out.zip file.txt",
		"zip -q " + readOnlyDir + "/out file.txt",
		"zip -P secret " + readOnlyDir + "/out.zip file.txt",
		"zip -d " + readOnlyDir + "/existing.zip old.txt",
	} {
		f, err := ParseBash(cmd)
		if err != nil {
			t.Fatalf("parse error: %v", err)
		}
		err = validatePaths(f, workDir, readPaths, writePaths)
		if err == nil || !strings.Contains(err.Error(), "outside allowed directories") {
			t.Fatalf("expected %q to be blocked, got %v", cmd, err)
		}
	}
}

func TestValidate_ArchiveEnvInjectionBlocked(t *testing.T) {
	tests := []string{
		"TAR_OPTIONS=--to-command=sh tar -xf archive.tar",
		"export TAR_OPTIONS=--to-command=sh",
		"TAPE=host:archive.tar tar -t",
		"UNZIP=-: unzip archive.zip",
		"UNZIPOPT='-d /etc' unzip archive.zip",
		"env TAR_OPTIONS=--to-command=sh tar -xf archive.tar",
		"env -u FOO UNZIP=-: unzip archive.zip",
		"env LD_PRELOAD=/tmp/evil.so ls",
	}
	for _, cmd := range tests {
		t.Run(cmd, func(t *testing.T) {
			f, err := ParseBash(cmd)
			if err != nil {
				t.Fatalf("parse error: %v", err)
			}
			err = newTestSandbox().validate(f)
			if err == nil || !strings.Contains(err.Error(), "is not allowed") {
				t.Fatalf("expected %q to be blocked, got %v", cmd, err)
			}
		})
	}
}

// TestBashSandboxed_ArchiveExtraction runs real tar and unzip extractions
// through the sandbox, checking both that extraction works and that the
// destination check holds at runtime once variables are expanded.
func TestBashSandboxed_ArchiveExtraction(t *testing.T) {
	workDir := t.TempDir()
	readOnlyDir := t.TempDir()
	os.Mkdir(filepath.Join(workDir, "out"), 0o755)
	writeTestTar(t, filepath.Join(readOnlyDir, "a.tar"), "dir/hello.txt", "hello tar\n")
	writeTestZip(t, filepath.Join(readOnlyDir, "a.zip"), "dir/hello.txt", "hello zip\n")

	readPaths := []string{workDir, readOnlyDir}
	writePaths := []string{workDir}
	s := NewSandbox()
	run := func(cmd string) (string, error) {
		return s.Execute(context.Background(), cmd, workDir, readPaths, writePaths)
	}

	t.Run("tar extracts into the working directory", func(t *testing.T) {
		if _, err := run("tar -xf " + readOnlyDir + "/a.tar"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFileContent(t, filepath.Join(workDir, "dir/hello.txt"), "hello tar\n")
	})

	t.Run("tar extracts into -C", func(t *testing.T) {
		if _, err := run("tar -xf " + readOnlyDir + "/a.tar -C out"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFileContent(t, filepath.Join(workDir, "out/dir/hello.txt"), "hello tar\n")
	})

	t.Run("tar -C via variable outside the boundary", func(t *testing.T) {
		_, err := run("D=" + readOnlyDir + "; tar -xf " + readOnlyDir + "/a.tar -C \"$D\"")
		if err == nil || !strings.Contains(err.Error(), "outside allowed directories") {
			t.Fatalf("expected runtime destination block, got %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(readOnlyDir, "dir")); statErr == nil {
			t.Fatal("tar extracted into the read-only directory")
		}
	})

	if _, err := exec.LookPath("zip"); err == nil {
		t.Run("zip creates an archive", func(t *testing.T) {
			os.WriteFile(filepath.Join(workDir, "in.txt"), []byte("zipped\n"), 0o644)
			if _, err := run("zip -q made.zip in.txt"); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if _, err := os.Stat(filepath.Join(workDir, "made.zip")); err != nil {
				t.Fatalf("archive not written: %v", err)
			}
		})

		t.Run("zip archive via variable outside the boundary", func(t *testing.T) {
			_, err := run("A=" + readOnlyDir + "/evil.zip; zip -q \"$A\" in.txt")
			if err == nil || !strings.Contains(err.Error(), "outside allowed directories") {
				t.Fatalf("expected runtime archive block, got %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(readOnlyDir, "evil.zip")); statErr == nil {
				t.Fatal("zip wrote into the read-only directory")
			}
		})
	}

	if _, err := exec.LookPath("unzip"); err != nil {
		t.Skip("unzip not installed")
	}

	t.Run("unzip extracts into -d", func(t *testing.T) {
		if _, err := run("unzip -q " + readOnlyDir + "/a.zip -d out/z"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertFileContent(t, filepath.Join(workDir, "out/z/dir/hello.txt"), "hello zip\n")
	})

	t.Run("unzip -d via variable outside the boundary", func(t *testing.T) {
		_, err := run("D=" + readOnlyDir + "; unzip -q " + readOnlyDir + "/a.zip -d \"$D\"")
		if err == nil || !strings.Contains(err.Error(), "outside allowed directories") {
			t.Fatalf("expected runtime destination block, got %v", err)
		}
		if _, statErr := os.Stat(filepath.Join(readOnlyDir, "dir")); statErr == nil {
			t.Fatal("unzip extracted into the read-only directory")
		}
	})
}

func writeTestTar(t *testing.T, path, name, content string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeTestZip(t *testing.T, path, name, content string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	w, err := zw.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func assertFileContent(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("%s = %q, want %q", path, got, want)
	}
}
