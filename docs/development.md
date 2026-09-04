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

### Crush installer end-to-end

`TestCrushEndToEnd` (in `cmd/`) drives a real [Crush](https://github.com/charmbracelet/crush) binary through `lite-sandbox install crush` and a non-interactive `crush run`, with a local mock OpenAI-compatible model server standing in for the LLM — so it needs no API key. The mock asks Crush to run a blocked command (`curl`) and then an allowed one through `mcp_lite-sandbox_bash`, and the test asserts that Crush loaded the generated config (both the `crushrc` and legacy `crush.json` forms), launched `lite-sandbox serve-mcp`, no longer offers its built-in `bash` tool, and fed the sandbox's rejection and output back to the model. It always compiles but only runs when `CRUSH_E2E_TESTS` is set and a `crush` binary is available:

```bash
go build -o lite-sandbox
CRUSH_E2E_TESTS=1 CRUSH_BIN=/path/to/crush go test ./cmd/ -run TestCrushEndToEnd -v   # CRUSH_BIN optional if crush is on PATH
```
