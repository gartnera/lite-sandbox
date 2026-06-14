package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"mvdan.cc/sh/v3/interp"

	"github.com/gartnera/lite-sandbox/config"
	"github.com/gartnera/lite-sandbox/internal/dockerproxy"
	"github.com/gartnera/lite-sandbox/internal/imds"
	bash_sandboxed "github.com/gartnera/lite-sandbox/tool/bash_sandboxed"
)

const runtimeErrorFallbackHint = "\n\nNote: This command passed sandbox validation but failed during execution. " +
	"You may retry this command using the Bash tool with dangerouslyDisableSandbox set to true."

var serveCmd = &cobra.Command{
	Use:   "serve-mcp",
	Short: "Start the MCP server over stdio",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runServe()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
}

// NewMCPServer creates and configures the MCP server with all tools registered.
func NewMCPServer() *server.MCPServer {
	sandbox := bash_sandboxed.NewSandbox()
	return newMCPServer(sandbox)
}

func newMCPServer(sandbox *bash_sandboxed.Sandbox) *server.MCPServer {
	s := server.NewMCPServer(
		"lite-sandbox",
		"0.1.0",
	)

	bashTool := mcp.NewTool(
		"bash",
		mcp.WithDescription("Execute a bash command in a lightweight sandbox. The command is parsed and validated before execution. If a command fails at runtime (not validation), you may retry it using the Bash tool with dangerouslyDisableSandbox set to true.\n\nSet run_in_background to true to start a long-running command without blocking; it returns a shell id you can poll with the bash_output tool and stop with the kill_shell tool."),
		mcp.WithString("command",
			mcp.Description("The bash command to execute"),
			mcp.Required(),
		),
		mcp.WithNumber("timeout",
			mcp.Description("Optional timeout in milliseconds (max 600000ms, default 120000ms). Ignored when run_in_background is true."),
		),
		mcp.WithBoolean("run_in_background",
			mcp.Description("Run the command in the background and return a shell id immediately instead of waiting for it to finish."),
		),
	)

	s.AddTool(bashTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		command, err := request.RequireString("command")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: command"), nil
		}

		args, _ := request.Params.Arguments.(map[string]any)

		// Extract optional timeout parameter (default 120000ms = 2 minutes)
		timeoutMs := 120000.0 // default
		if args != nil {
			if timeout, ok := args["timeout"]; ok {
				if timeoutFloat, ok := timeout.(float64); ok {
					if timeoutFloat > 600000 {
						return mcp.NewToolResultError("timeout exceeds maximum of 600000ms (10 minutes)"), nil
					}
					if timeoutFloat < 0 {
						return mcp.NewToolResultError("timeout must be positive"), nil
					}
					timeoutMs = timeoutFloat
				}
			}
		}

		runInBackground := false
		if args != nil {
			if v, ok := args["run_in_background"].(bool); ok {
				runInBackground = v
			}
		}

		cwd, err := os.Getwd()
		if err != nil {
			return mcp.NewToolResultError("failed to get working directory: " + err.Error()), nil
		}

		readPaths, writePaths := sandboxPaths(sandbox, cwd)

		if runInBackground {
			proc, err := sandbox.ExecuteBackground(command, cwd, readPaths, writePaths)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			msg := fmt.Sprintf(
				"Started background process with shell id %q.\nUse the bash_output tool (bash_id=%q) to read its output and the kill_shell tool (shell_id=%q) to stop it.",
				proc.ID, proc.ID, proc.ID,
			)
			return mcp.NewToolResultText(msg), nil
		}

		// Create a context with timeout
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()

		output, err := sandbox.Execute(timeoutCtx, command, cwd, readPaths, writePaths)
		if err != nil {
			errMsg := err.Error()
			var cmdErr *bash_sandboxed.CommandFailedError
			var exitStatus interp.ExitStatus
			if errors.As(err, &cmdErr) && !errors.As(err, &exitStatus) {
				errMsg += runtimeErrorFallbackHint
			}
			return mcp.NewToolResultError(errMsg), nil
		}

		return mcp.NewToolResultText(output), nil
	})

	bashOutputTool := mcp.NewTool(
		"bash_output",
		mcp.WithDescription("Retrieve output from a background command started with the bash tool (run_in_background=true). Returns only the output produced since the previous call, along with the process status (running, completed, failed, or killed) and exit code."),
		mcp.WithString("bash_id",
			mcp.Description("The shell id returned when the background command was started"),
			mcp.Required(),
		),
		mcp.WithString("filter",
			mcp.Description("Optional regular expression; only output lines matching it are returned"),
		),
	)

	s.AddTool(bashOutputTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		bashID, err := request.RequireString("bash_id")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: bash_id"), nil
		}
		filter := ""
		if args, ok := request.Params.Arguments.(map[string]any); ok {
			if v, ok := args["filter"].(string); ok {
				filter = v
			}
		}

		res, err := sandbox.BackgroundOutput(bashID, filter)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		var b strings.Builder
		fmt.Fprintf(&b, "<status>%s</status>\n", res.Status)
		if res.Done {
			fmt.Fprintf(&b, "<exit_code>%d</exit_code>\n", res.ExitCode)
		}
		fmt.Fprintf(&b, "<output>\n%s</output>", res.Output)
		return mcp.NewToolResultText(b.String()), nil
	})

	killShellTool := mcp.NewTool(
		"kill_shell",
		mcp.WithDescription("Stop a background command started with the bash tool (run_in_background=true)."),
		mcp.WithString("shell_id",
			mcp.Description("The shell id of the background process to stop"),
			mcp.Required(),
		),
	)

	s.AddTool(killShellTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		shellID, err := request.RequireString("shell_id")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: shell_id"), nil
		}
		if err := sandbox.KillBackground(shellID); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Killed background process %q.", shellID)), nil
	})

	listShellsTool := mcp.NewTool(
		"list_shells",
		mcp.WithDescription("List all background commands started with the bash tool (run_in_background=true), with their shell id, status, and exit code."),
	)

	s.AddTool(listShellsTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		procs := sandbox.ListBackground()
		if len(procs) == 0 {
			return mcp.NewToolResultText("No background processes."), nil
		}
		var b strings.Builder
		for _, p := range procs {
			fmt.Fprintf(&b, "%s\t%s", p.ID, p.Status)
			if p.Status != "running" {
				fmt.Fprintf(&b, " (exit %d)", p.ExitCode)
			}
			fmt.Fprintf(&b, "\t%s\n", p.Command)
		}
		return mcp.NewToolResultText(strings.TrimRight(b.String(), "\n")), nil
	})

	return s
}

// sandboxPaths computes the read- and write-allowed path lists for a command
// executed from cwd, combining the working directory, detected runtime paths,
// user-configured paths, and any git worktree parent.
func sandboxPaths(sandbox *bash_sandboxed.Sandbox, cwd string) (readPaths, writePaths []string) {
	readPaths = append([]string{cwd}, sandbox.RuntimeReadPaths()...)
	readPaths = append(readPaths, sandbox.ConfigReadPaths()...)
	writePaths = append([]string{cwd}, sandbox.ConfigWritePaths()...)
	if parent := sandbox.WorktreeParentPath(cwd); parent != "" {
		readPaths = append(readPaths, parent)
		writePaths = append(writePaths, parent)
	}
	return readPaths, writePaths
}

// dockerSocketBaseDir returns the base directory for the docker proxy socket.
// XDG_RUNTIME_DIR is the standard per-user runtime socket location (user-owned
// 0700, tmpfs on Linux, auto-cleaned on logout); its short path also keeps the
// socket well under macOS's ~104-byte sun_path limit. Falls back to the system
// temp dir when it is unset or missing (e.g. on macOS).
func dockerSocketBaseDir() string {
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			return d
		}
	}
	return os.TempDir()
}

func runServe() error {
	slog.Info("starting MCP server")

	sandbox := bash_sandboxed.NewSandbox()

	// Get current working directory for worker pool initialization
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working directory: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Warn("failed to load config, using defaults", "error", err)
	} else {
		sandbox.UpdateConfig(cfg, cwd)
		slog.Info("loaded config", "extra_commands", cfg.ExtraCommands)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer sandbox.Close() // Clean up worker pool on exit

	// Start IMDS server if AWS uses IMDS (force_profile is set)
	var imdsServer *imds.Server
	if cfg != nil && cfg.AWS != nil && cfg.AWS.UsesIMDS() {
		// Use port 0 to get a random available port
		imdsServer, err = imds.NewServer("127.0.0.1:0", cfg.AWS.IMDSProfile())
		if err != nil {
			return fmt.Errorf("failed to create IMDS server: %w", err)
		}

		// Start IMDS server in background
		go func() {
			slog.Info("IMDS server endpoint", "url", imdsServer.Endpoint())
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
	}

	// Start docker proxy if docker is enabled and usable (the docker command is
	// only permitted under the OS sandbox, unless allow_unsandboxed is set).
	if cfg != nil && cfg.Docker.DockerEnabled() && (cfg.OSSandboxEnabled() || cfg.Docker.AllowsUnsandboxed()) {
		readPaths, writePaths := sandboxPaths(sandbox, cwd)
		// Resolve the upstream socket once and reuse it for both the proxy and
		// the OS-sandbox mask so they can't disagree.
		upstream := cfg.Docker.UpstreamSocket()
		socketDir, err := os.MkdirTemp(dockerSocketBaseDir(), "ls-docker-")
		if err != nil {
			return fmt.Errorf("failed to create docker proxy socket dir: %w", err)
		}
		defer os.RemoveAll(socketDir)

		dockerSrv, err := dockerproxy.NewServer(socketDir, upstream,
			readPaths, writePaths, cwd, cfg.Docker.AllowsPrivileged())
		if err != nil {
			return fmt.Errorf("failed to create docker proxy: %w", err)
		}

		go func() {
			slog.Info("docker proxy endpoint", "host", dockerSrv.Endpoint())
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
	}

	go func() {
		err := config.Watch(ctx, func(newCfg *config.Config) {
			sandbox.UpdateConfig(newCfg, cwd)
			slog.Info("reloaded config", "extra_commands", newCfg.ExtraCommands)

			// Handle IMDS server lifecycle on config changes
			wasEnabled := cfg != nil && cfg.AWS != nil && cfg.AWS.AWSEnabled()
			nowEnabled := newCfg != nil && newCfg.AWS != nil && newCfg.AWS.AWSEnabled()

			if !wasEnabled && nowEnabled {
				// AWS was just enabled
				slog.Info("AWS enabled, starting IMDS server")
				// TODO: Start IMDS server dynamically
			} else if wasEnabled && !nowEnabled {
				// AWS was just disabled
				slog.Info("AWS disabled, stopping IMDS server")
				// TODO: Stop IMDS server dynamically
			}

			cfg = newCfg
		})
		if err != nil && ctx.Err() == nil {
			slog.Error("config watcher failed", "error", err)
		}
	}()

	s := newMCPServer(sandbox)
	return server.ServeStdio(s)
}
