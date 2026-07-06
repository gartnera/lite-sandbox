# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
go build -o lite-sandbox         # Build binary
go test ./...                    # Run default suite (OS-sandbox-runtime tests skipped)
go test -v ./tool/...            # Run tool package tests with verbose output
go test -run TestValidate ./tool/... # Run a specific test
go run . serve-mcp               # Start MCP server over stdio
cd e2e/claude && uv run pytest -v # Run e2e tests (Claude Agent SDK)

# Tests that exercise the real OS sandbox (bwrap on Linux / sandbox-exec on macOS)
# always compile but only run when OS_SANDBOX_TESTS is set (CI sets it). To run
# the full suite locally:
go build -o lite-sandbox && OS_SANDBOX_TESTS=1 go test ./...  # Linux needs bubblewrap + unprivileged userns
```

## Architecture

This is an MCP (Model Context Protocol) server that gives AI coding agents shell access with layered security validation. It registers four tools: `bash` (execute a command, optionally in the background), plus `bash_output`, `kill_shell`, and `list_shells` for managing background processes. `lite-sandbox install` configures Claude Code (or Codex with `--codex`) to route shell commands through it; `lite-sandbox hook` provides an optional PreToolUse hook that confines the built-in file tools to the same path boundary.

**Command flow:** MCP request → `cmd/serve.go` → `Sandbox.Execute()` in `tool/bash_sandboxed/`, which parses the command into a bash AST (`mvdan.cc/sh/v3`), statically validates it, then executes it via the `mvdan.cc/sh` interpreter (NOT `bash -c`) with runtime hooks that re-validate after variable expansion. When the OS sandbox is enabled, commands are additionally dispatched to a long-lived sandboxed worker process (`os_sandbox/`).

**Security layers** (see `docs/security.md`, the source of truth):

1. **Static preflight** — commands must be in the `allowedCommands` whitelist (`tool/bash_sandboxed/commands.go`); per-command argument validators (`validators*.go`) block dangerous flags (e.g. `find -exec`, `git push`); coprocesses, read-write redirections, and dynamic command names are rejected; literal path arguments are checked against allowed directories (`paths.go`).
2. **Runtime validation** — the interpreter's `CallHandler`/`OpenHandler` re-validate every command's expanded arguments and every file open, catching bypasses like `cat $HOME/secret`.
3. **Optional OS sandbox** — bubblewrap (Linux) or sandbox-exec (macOS) confines writes to the working directory and masks sensitive paths (`~/.ssh` private keys, `~/.aws` in IMDS mode).

The whitelist is not read-only: path-scoped write commands (`cp`, `mv`, `rm`, `sed`, `touch`, `mkdir`, ...) are allowed inside the boundary, and opt-in config enables runtimes (Go, pnpm, Deno, Rust), `git`, `aws` (via a local IMDS credential broker), and `docker` (via a filtering proxy). Bare `extra_commands` config entries bypass validation entirely and run via real `bash -c` — a trust-based escape hatch.

**Key packages:**
- `cmd/` — Cobra CLI: MCP server (`serve.go`), installers (`install*.go`), PreToolUse hook (`hook.go`), interactive shell (`shell.go`), config subcommands (`config_*.go`)
- `tool/bash_sandboxed/` — parsing, validation (static + runtime), execution, background process management
- `os_sandbox/` — sandboxed worker process and pool (bwrap/sandbox-exec, gob protocol)
- `config/` — YAML config loading, watching, and per-directory AWS overrides
- `internal/hook` — hook event/decision types; `internal/imds` — IMDS credential server; `internal/dockerproxy` — Docker socket filtering proxy

## Testing

After making complex changes (new commands, validation logic, security rules), run the e2e tests in addition to unit tests. These send real prompts to Claude via the Agent SDK and verify the sandbox tool works end-to-end:

```bash
cd e2e/claude && uv run pytest -v
```

## Notes

- always inspect `man` pages of commands you are asked to parse. you can rely on the local pages rather than using web fetch.
- user-facing documentation lives in `docs/` (installation, configuration, runtimes, AWS/Docker, background processes, security, development). Keep it in sync with behavior changes.
