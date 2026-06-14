package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"mvdan.cc/sh/v3/syntax"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/dockerproxy"
	"github.com/gartnera/lite-sandbox/internal/imds"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

var shellCmd = &cobra.Command{
	Use:   "shell",
	Short: "Start an interactive sandbox shell",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runShell()
	},
}

func init() {
	rootCmd.AddCommand(shellCmd)
}

func runShell() error {
	sandbox := bash_sandboxed.NewSandbox()

	workDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to load config, using defaults: %v\n", err)
	} else {
		sandbox.UpdateConfig(cfg, workDir)
	}
	defer sandbox.Close()

	// Start IMDS server if AWS uses IMDS (force_profile is set)
	var imdsServer *imds.Server
	if cfg != nil && cfg.AWS != nil && cfg.AWS.UsesIMDS() {
		imdsServer, err = imds.NewServer("127.0.0.1:0", cfg.AWS.IMDSProfile())
		if err != nil {
			return fmt.Errorf("failed to create IMDS server: %w", err)
		}

		// Start IMDS server in background
		go func() {
			slog.Debug("starting IMDS server", "endpoint", imdsServer.Endpoint())
			if err := imdsServer.Start(); err != nil && err != http.ErrServerClosed {
				slog.Error("IMDS server failed", "error", err)
			}
		}()
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := imdsServer.Shutdown(shutdownCtx); err != nil {
				slog.Error("failed to shutdown IMDS server", "error", err)
			}
		}()

		// Set IMDS endpoint in sandbox
		sandbox.SetIMDSEndpoint(imdsServer.Endpoint())

		// Also set in process environment for subprocesses
		os.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", imdsServer.Endpoint())
	}

	ctx := context.Background()
	scanner := bufio.NewScanner(os.Stdin)
	var prevDir string

	// Pin allowed paths to the initial working directory so cd can't escape the sandbox.
	startDir := workDir
	readPaths := append([]string{startDir}, sandbox.RuntimeReadPaths()...)
	writePaths := []string{startDir}

	// Start docker proxy if docker is enabled and usable, validating bind mounts
	// against the same path boundary the shell enforces. The docker command is
	// only permitted under the OS sandbox unless allow_unsandboxed is set.
	if cfg != nil && cfg.Docker.DockerEnabled() && (cfg.OSSandboxEnabled() || cfg.Docker.AllowsUnsandboxed()) {
		// Resolve the upstream socket once and reuse it for both the proxy and
		// the OS-sandbox mask so they can't disagree.
		upstream := cfg.Docker.UpstreamSocket()
		socketDir, err := os.MkdirTemp(dockerSocketBaseDir(), "ls-docker-")
		if err != nil {
			return fmt.Errorf("failed to create docker proxy socket dir: %w", err)
		}
		defer os.RemoveAll(socketDir)

		dockerSrv, err := dockerproxy.NewServer(socketDir, upstream,
			readPaths, writePaths, startDir, cfg.Docker.AllowsPrivileged())
		if err != nil {
			return fmt.Errorf("failed to create docker proxy: %w", err)
		}

		go func() {
			slog.Debug("starting docker proxy", "host", dockerSrv.Endpoint())
			if err := dockerSrv.Start(); err != nil && err != http.ErrServerClosed {
				slog.Error("docker proxy failed", "error", err)
			}
		}()
		defer func() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			if err := dockerSrv.Shutdown(shutdownCtx); err != nil {
				slog.Error("failed to shutdown docker proxy", "error", err)
			}
		}()

		sandbox.SetDockerHost(dockerSrv.Endpoint(), dockerSrv.SocketDir(), upstream)
		os.Setenv("DOCKER_HOST", dockerSrv.Endpoint())
	}

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))

	for {
		fmt.Fprintf(os.Stderr, "sandbox:%s$ ", workDir)

		var accumulated string
		// Read first line
		if !scanner.Scan() {
			fmt.Fprintln(os.Stderr)
			break
		}
		accumulated = scanner.Text()

		// Multi-line support: keep reading if the parse error is "incomplete"
		for {
			_, err := parser.Parse(strings.NewReader(accumulated), "")
			if err == nil || !syntax.IsIncomplete(err) {
				break
			}
			fmt.Fprintf(os.Stderr, "> ")
			if !scanner.Scan() {
				// EOF during multi-line input; try to execute what we have
				break
			}
			accumulated += "\n" + scanner.Text()
		}

		line := strings.TrimSpace(accumulated)
		if line == "" {
			continue
		}
		if line == "exit" {
			break
		}

		// Handle cd builtin
		if line == "cd" || strings.HasPrefix(line, "cd ") {
			target := strings.TrimPrefix(line, "cd")
			target = strings.TrimSpace(target)
			workDir, prevDir = changeDir(workDir, prevDir, target, readPaths)
			continue
		}

		output, err := sandbox.Execute(ctx, line, workDir, readPaths, writePaths)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
		if output != "" {
			fmt.Print(output)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("input error: %w", err)
	}
	return nil
}

// changeDir handles the cd builtin. It validates that the target is within
// the allowed paths so cd can't be used to escape the sandbox.
func changeDir(workDir, prevDir, target string, allowedPaths []string) (string, string) {
	var newDir string
	switch {
	case target == "" || target == "~":
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "cd: %v\n", err)
			return workDir, prevDir
		}
		newDir = home
	case target == "-":
		if prevDir == "" {
			fmt.Fprintln(os.Stderr, "cd: OLDPWD not set")
			return workDir, prevDir
		}
		newDir = prevDir
		fmt.Fprintln(os.Stderr, newDir)
	default:
		if filepath.IsAbs(target) {
			newDir = target
		} else {
			newDir = filepath.Join(workDir, target)
		}
	}

	resolved := bash_sandboxed.ResolvePath(newDir, workDir)
	if !bash_sandboxed.IsUnderAllowedPaths(resolved, allowedPaths) {
		fmt.Fprintf(os.Stderr, "cd: %s: outside sandbox boundary\n", resolved)
		return workDir, prevDir
	}

	info, err := os.Stat(resolved)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cd: %v\n", err)
		return workDir, prevDir
	}
	if !info.IsDir() {
		fmt.Fprintf(os.Stderr, "cd: %s: Not a directory\n", resolved)
		return workDir, prevDir
	}

	return resolved, workDir
}
