package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/spf13/cobra"
	"mvdan.cc/sh/v3/interp"

	"github.com/gartnera/lite-sandbox/config"
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
		mcp.WithDescription("Execute a bash command in a lightweight sandbox. The command is parsed and validated before execution. If a command fails at runtime (not validation), you may retry it using the Bash tool with dangerouslyDisableSandbox set to true."),
		mcp.WithString("command",
			mcp.Description("The bash command to execute"),
			mcp.Required(),
		),
		mcp.WithNumber("timeout",
			mcp.Description("Optional timeout in milliseconds (max 600000ms, default 120000ms)"),
		),
	)

	s.AddTool(bashTool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		command, err := request.RequireString("command")
		if err != nil {
			return mcp.NewToolResultError("missing required parameter: command"), nil
		}

		// Extract optional timeout parameter (default 120000ms = 2 minutes)
		timeoutMs := 120000.0 // default
		if args, ok := request.Params.Arguments.(map[string]any); ok {
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

		cwd, err := os.Getwd()
		if err != nil {
			return mcp.NewToolResultError("failed to get working directory: " + err.Error()), nil
		}

		// Create a context with timeout
		timeoutCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutMs)*time.Millisecond)
		defer cancel()

		readPaths := append([]string{cwd}, sandbox.RuntimeReadPaths()...)
		readPaths = append(readPaths, sandbox.ConfigReadPaths()...)
		writePaths := append([]string{cwd}, sandbox.ConfigWritePaths()...)
		if parent := sandbox.WorktreeParentPath(cwd); parent != "" {
			readPaths = append(readPaths, parent)
			writePaths = append(writePaths, parent)
		}
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
	return s
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
