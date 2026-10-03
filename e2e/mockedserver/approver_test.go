package mockedserver

import (
	"context"
	"encoding/json"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// approverLogEnv turns the test binary into the approver: an MCP server whose
// one tool, passed to `claude -p --permission-prompt-tool`, answers Claude
// Code's permission prompts the way a user approving them would. It allows
// every prompt and appends each request it receives to the file the variable
// names, one JSON object per line. TestMain checks for it before anything
// else, so the agent can launch the test binary itself as the server.
const approverLogEnv = "LITE_SANDBOX_E2E_APPROVER_LOG"

// approverTool is the approver's tool under Claude Code's MCP naming.
const approverTool = "mcp__approver__approve"

// serveApprover runs the approver over stdio until the agent closes it.
func serveApprover(logPath string) error {
	s := server.NewMCPServer("approver", "0.0.1")
	tool := mcp.NewTool("approve",
		mcp.WithDescription("Answers permission prompts for the e2e tests."),
		mcp.WithString("tool_name"),
		mcp.WithObject("input"),
		mcp.WithString("tool_use_id"),
	)
	s.AddTool(tool, func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args := req.GetArguments()
		line, err := json.Marshal(args)
		if err != nil {
			return nil, err
		}
		f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		_, werr := f.Write(append(line, '\n'))
		if cerr := f.Close(); werr == nil {
			werr = cerr
		}
		if werr != nil {
			return nil, werr
		}
		answer, err := json.Marshal(map[string]any{"behavior": "allow", "updatedInput": args["input"]})
		if err != nil {
			return nil, err
		}
		return mcp.NewToolResultText(string(answer)), nil
	})
	return server.ServeStdio(s)
}
