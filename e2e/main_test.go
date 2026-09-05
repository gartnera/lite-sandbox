package e2e

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// e2eEnv gates the suite: the tests download and run third-party agent
// binaries, so they only run when it is set. Without it every test skips and
// `go test ./...` stays offline.
const e2eEnv = "LITE_SANDBOX_E2E"

// bins holds the binaries TestMain provisions. pathDirs are prepended to PATH
// for every subprocess so `lite-sandbox install` autodetection and the agents'
// own PATH lookups (e.g. `crush --version`) find them.
var bins struct {
	sandbox, crush, codex, claude string
	pathDirs                      []string
}

func TestMain(m *testing.M) {
	if os.Getenv(e2eEnv) != "" {
		if err := provision(); err != nil {
			fmt.Fprintf(os.Stderr, "e2e: provisioning failed: %v\n", err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// requireE2E skips t unless the suite is enabled.
func requireE2E(t *testing.T) {
	t.Helper()
	if os.Getenv(e2eEnv) == "" {
		t.Skipf("set %s=1 to run the agent end-to-end tests (downloads pinned agent binaries)", e2eEnv)
	}
}

// provision builds lite-sandbox and installs the pinned agents. Everything
// lives under e2e/.bin (override with E2E_BIN_DIR): lite-sandbox is rebuilt
// every run, agents are (re)installed only when their version stamp differs
// from versions.go, so repeated local runs and CI cache hits skip the
// downloads.
func provision() error {
	binDir := os.Getenv("E2E_BIN_DIR")
	if binDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		binDir = filepath.Join(wd, ".bin")
	}
	agentsDir := filepath.Join(binDir, "agents")
	if err := os.MkdirAll(agentsDir, 0755); err != nil {
		return err
	}

	bins.sandbox = filepath.Join(binDir, "lite-sandbox")
	if out, err := exec.Command("go", "build", "-o", bins.sandbox, "..").CombinedOutput(); err != nil {
		return fmt.Errorf("go build lite-sandbox: %v\n%s", err, out)
	}

	crushDir := filepath.Join(agentsDir, "crush")
	if err := ensureVersion(crushDir, CrushVersion, func() error { return installCrush(crushDir) }); err != nil {
		return err
	}
	bins.crush = filepath.Join(crushDir, "crush")

	npmDir := filepath.Join(agentsDir, "npm")
	npmVersion := "@openai/codex@" + CodexVersion + " @anthropic-ai/claude-code@" + ClaudeCodeVersion
	if err := ensureVersion(npmDir, npmVersion, func() error { return installNPM(npmDir, strings.Fields(npmVersion)...) }); err != nil {
		return err
	}
	npmBin := filepath.Join(npmDir, "node_modules", ".bin")
	bins.codex = filepath.Join(npmBin, "codex")
	bins.claude = filepath.Join(npmBin, "claude")
	bins.pathDirs = []string{binDir, crushDir, npmBin}

	for _, b := range []string{bins.sandbox, bins.crush, bins.codex, bins.claude} {
		if _, err := os.Stat(b); err != nil {
			return fmt.Errorf("provisioned binary missing: %w", err)
		}
	}
	return nil
}

// ensureVersion runs install into dir unless dir/.version already records
// version. The stamp is written last, so a failed or interrupted install is
// retried next time.
func ensureVersion(dir, version string, install func() error) error {
	stamp := filepath.Join(dir, ".version")
	if b, err := os.ReadFile(stamp); err == nil && strings.TrimSpace(string(b)) == version {
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "e2e: installing %s into %s\n", version, dir)
	if err := install(); err != nil {
		return fmt.Errorf("installing %s: %w", version, err)
	}
	return os.WriteFile(stamp, []byte(version+"\n"), 0644)
}

// installCrush downloads the pinned Crush release tarball for this OS/arch and
// extracts the crush binary into dir.
func installCrush(dir string) error {
	goos := map[string]string{"linux": "Linux", "darwin": "Darwin"}[runtime.GOOS]
	arch := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[runtime.GOARCH]
	if goos == "" || arch == "" {
		return fmt.Errorf("no crush release for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	url := fmt.Sprintf("https://github.com/charmbracelet/crush/releases/download/v%s/crush_%s_%s_%s.tar.gz",
		CrushVersion, CrushVersion, goos, arch)
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%s: no crush binary in archive", url)
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg || filepath.Base(hdr.Name) != "crush" {
			continue
		}
		f, err := os.OpenFile(filepath.Join(dir, "crush"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			return err
		}
		_, err = io.Copy(f, tr)
		return errors.Join(err, f.Close())
	}
}

// installNPM installs the given package@version specs into a private npm
// prefix, so the pinned Codex and Claude Code never touch the host's global
// npm tree. Their launchers end up in dir/node_modules/.bin.
func installNPM(dir string, specs ...string) error {
	npm, err := exec.LookPath("npm")
	if err != nil {
		return fmt.Errorf("npm is required to install Codex and Claude Code: %w", err)
	}
	args := append([]string{"install", "--prefix", dir, "--no-audit", "--no-fund", "--no-package-lock", "--loglevel=error"}, specs...)
	cmd := exec.Command(npm, args...)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
