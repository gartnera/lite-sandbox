package cmd

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"mvdan.cc/sh/v3/syntax"

	"github.com/gartnera/lite-sandbox/config"
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

	// Resolve per-directory overrides once for the shell's working directory, so
	// the sandbox, IMDS, and docker proxy below all get the same effective config.
	cfg, err := config.LoadForDirectory(workDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to load config, using defaults: %v\n", err)
	} else {
		sandbox.UpdateConfig(cfg, workDir)
	}
	defer sandbox.Close()

	// Start IMDS server if AWS uses IMDS (force_profile is set). cfg is already
	// resolved for workDir, so per-directory overrides take effect.
	var awsCfg *config.AWSConfig
	if cfg != nil {
		awsCfg = cfg.AWS
	}
	imdsLC := &imdsLifecycle{sandbox: sandbox}
	if err := imdsLC.apply(awsCfg); err != nil {
		return err
	}
	defer imdsLC.stop()
	if endpoint := imdsLC.endpoint(); endpoint != "" {
		// Also set in process environment for subprocesses
		os.Setenv("AWS_EC2_METADATA_SERVICE_ENDPOINT", endpoint)
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
		endpoint, cleanup, err := startDockerProxy(cfg, sandbox, readPaths, writePaths, startDir, func(endpoint string) {
			slog.Debug("starting docker proxy", "host", endpoint)
		})
		if err != nil {
			return err
		}
		defer cleanup()

		os.Setenv("DOCKER_HOST", endpoint)
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
		// ResolvePath below joins a relative target onto workDir itself.
		newDir = target
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
