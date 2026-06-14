# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
go build -o lite-sandbox        # Build binary
go test ./...                    # Run default suite (OS-sandbox-runtime tests skipped)
go test -v ./tool/...            # Run tool package tests with verbose output
go test -run TestValidate ./tool # Run a specific test
go run . serve-mcp               # Start MCP server over stdio
cd e2e/claude && uv run pytest -v # Run e2e tests (Claude Agent SDK)

# Tests that exercise the real OS sandbox (bwrap on Linux / sandbox-exec on macOS)
# always compile but only run when OS_SANDBOX_TESTS is set (CI sets it). To run
# the full suite locally:
go build -o lite-sandbox && OS_SANDBOX_TESTS=1 go test ./...  # Linux needs bubblewrap + unprivileged userns
```

## Architecture

This is an MCP (Model Context Protocol) server that exposes a single `bash` tool for executing bash commands with strict security validation.

**Command flow:** MCP request → `cmd/serve.go:handleBashSandboxed()` → `tool.BashSandboxed()` which does: parse bash AST → validate against whitelist → execute via `bash -c`.

**Security model in `tool/bash_sandboxed.go`:**
- Bash is parsed into an AST using `mvdan.cc/sh/v3`
- `validate()` walks the AST enforcing: commands must be in `allowedCommands` whitelist, no redirections, no process substitutions, no coprocesses, no dynamic command names
- The whitelist is intentionally strict — only read-only, non-destructive commands. Code execution runtimes, networking, archives, shell escapes, VCS, package managers, and file-modifying commands are all blocked.

**Key packages:**
- `cmd/` — Cobra CLI setup and MCP server registration
- `tool/` — Sandbox implementation (parsing, validation, execution)

## Testing

After making complex changes (new commands, validation logic, security rules), run the e2e tests in addition to unit tests. These send real prompts to Claude via the Agent SDK and verify the sandbox tool works end-to-end:

```bash
cd e2e/claude && uv run pytest -v
```

## Notes

- always inspect `man` pages of commands you are asked to parse. you can rely on the local pages rather than using web fetch.
