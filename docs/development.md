# Building & Development

## Building

```bash
go install .            # Build and install lite-sandbox to $GOPATH/bin
lite-sandbox install    # Automatically configure Claude Code
```

(`go build -o lite-sandbox` still works if you'd rather keep the binary in the
working directory.)

## Development

```bash
go test ./...              # Run all tests
go test -v ./tool/...      # Run tool package tests with verbose output
```

## E2E Testing

End-to-end tests verify real-world usage via the Claude Agent SDK. They test that Claude can successfully use the sandboxed MCP tool without falling back to built-in Bash:

```bash
cd e2e/claude
uv run pytest -v          # Run all e2e tests
uv run pytest -v -k test_go_project_workflow  # Run specific test
```

**Showcase test**: `e2e/claude/test_go_runtime_e2e.py` demonstrates a complete Go development workflow — module initialization, writing code and tests, running `go test`, and creating a git commit — all using only the `bash` MCP tool with no built-in Bash calls. This test shows how the sandbox enables safe, autonomous development workflows for AI coding agents.
