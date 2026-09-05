package mockedserver

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
	"testing"

	"golang.org/x/sync/errgroup"
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
// lives under e2e/mockedserver/.bin (override with E2E_BIN_DIR): lite-sandbox is rebuilt
// every run; each agent is installed once into its own versioned directory
// (agents/<agent>/<version>), so switching versions — by editing versions.go or
// setting E2E_CRUSH_VERSION / E2E_CODEX_VERSION / E2E_CLAUDE_CODE_VERSION for
// one run — never re-downloads a version that is already there.
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

	bins.sandbox = filepath.Join(binDir, "lite-sandbox")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return err
	}
	if out, err := exec.Command("go", "build", "-o", bins.sandbox, "../..").CombinedOutput(); err != nil {
		return fmt.Errorf("go build lite-sandbox: %v\n%s", err, out)
	}

	// The three installs are independent downloads; run them concurrently.
	crushVersion := versionFromEnv("E2E_CRUSH_VERSION", CrushVersion)
	codexVersion := versionFromEnv("E2E_CODEX_VERSION", CodexVersion)
	claudeVersion := versionFromEnv("E2E_CLAUDE_CODE_VERSION", ClaudeCodeVersion)
	crushDir := filepath.Join(agentsDir, "crush", crushVersion)
	codexDir := filepath.Join(agentsDir, "codex", codexVersion)
	claudeDir := filepath.Join(agentsDir, "claude-code", claudeVersion)
	var g errgroup.Group
	g.Go(func() error {
		return ensureInstalled(crushDir, "crush "+crushVersion, func() error { return installCrush(crushDir, crushVersion) })
	})
	g.Go(func() error {
		return ensureInstalled(codexDir, "codex "+codexVersion, func() error { return installNPM(codexDir, "@openai/codex@"+codexVersion) })
	})
	g.Go(func() error {
		return ensureInstalled(claudeDir, "claude-code "+claudeVersion, func() error { return installNPM(claudeDir, "@anthropic-ai/claude-code@"+claudeVersion) })
	})
	if err := g.Wait(); err != nil {
		return err
	}
	bins.crush = filepath.Join(crushDir, "crush")
	bins.codex = filepath.Join(codexDir, "node_modules", ".bin", "codex")
	bins.claude = filepath.Join(claudeDir, "node_modules", ".bin", "claude")

	bins.pathDirs = []string{binDir, filepath.Dir(bins.crush), filepath.Dir(bins.codex), filepath.Dir(bins.claude)}
	for _, b := range []string{bins.sandbox, bins.crush, bins.codex, bins.claude} {
		if _, err := os.Stat(b); err != nil {
			return fmt.Errorf("provisioned binary missing: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "e2e: crush %s, codex %s, claude-code %s\n", crushVersion, codexVersion, claudeVersion)
	return nil
}

// versionFromEnv returns the version pinned in versions.go unless the named
// environment variable overrides it for this run.
func versionFromEnv(name, pinned string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return pinned
}

// ensureInstalled runs install into dir unless dir/.complete already exists.
// The marker is written last, so a failed or interrupted install is retried
// (from a clean directory) next time.
func ensureInstalled(dir, what string, install func() error) error {
	marker := filepath.Join(dir, ".complete")
	if _, err := os.Stat(marker); err == nil {
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "e2e: installing %s into %s\n", what, dir)
	if err := install(); err != nil {
		return fmt.Errorf("installing %s: %w", what, err)
	}
	return os.WriteFile(marker, nil, 0644)
}

// installCrush downloads the Crush release tarball for version and this
// OS/arch and extracts the crush binary into dir.
func installCrush(dir, version string) error {
	goos := map[string]string{"linux": "Linux", "darwin": "Darwin"}[runtime.GOOS]
	arch := map[string]string{"amd64": "x86_64", "arm64": "arm64"}[runtime.GOARCH]
	if goos == "" || arch == "" {
		return fmt.Errorf("no crush release for %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	url := fmt.Sprintf("https://github.com/charmbracelet/crush/releases/download/v%s/crush_%s_%s_%s.tar.gz",
		version, version, goos, arch)
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

// installNPM installs one package@version spec into a private npm prefix, so
// the pinned Codex and Claude Code never touch the host's global npm tree. The
// launcher ends up in dir/node_modules/.bin.
func installNPM(dir, spec string) error {
	npm, err := exec.LookPath("npm")
	if err != nil {
		return fmt.Errorf("npm is required to install Codex and Claude Code: %w", err)
	}
	cmd := exec.Command(npm, "install", "--prefix", dir, "--no-audit", "--no-fund", "--no-package-lock", "--loglevel=error", spec)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
