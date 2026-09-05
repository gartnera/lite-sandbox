# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
go build -o lite-sandbox         # Build binary
go test ./...                    # Run default suite (OS-sandbox-runtime tests skipped)
go test -v ./tool/...            # Run tool package tests with verbose output
go test -run TestValidate ./tool/... # Run a specific test
go run . serve-mcp               # Start MCP server over stdio
LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v  # Agent e2e: drives real Crush/Codex/Claude Code/opencode binaries (pinned, auto-downloaded to e2e/.bin) through the installer against a mock model; no API key
cd e2e/claude && uv run pytest -v # Real-model e2e (Claude Agent SDK; needs an API key)

# Tests that exercise the real OS sandbox (bwrap on Linux / sandbox-exec on macOS)
# always compile but only run when OS_SANDBOX_TESTS is set (CI sets it). To run
# the full suite locally:
go build -o lite-sandbox && OS_SANDBOX_TESTS=1 go test ./...  # Linux needs bubblewrap + unprivileged userns
```

## Architecture

This is an MCP (Model Context Protocol) server that gives AI coding agents shell access with layered security validation. It registers four tools: `bash` (execute a command, optionally in the background), plus `bash_output`, `kill_shell`, and `list_shells` for managing background processes. `lite-sandbox install` configures Claude Code, Codex, opencode, and Crush (autodetecting which are installed on the host; pass names like `install codex` to select explicitly) to route shell commands through it; `lite-sandbox hook` provides an optional PreToolUse hook that confines the built-in file tools to the same path boundary.

**Command flow:** MCP request → `cmd/serve.go` → `Sandbox.Execute()` in `tool/bash_sandboxed/`, which parses the command into a bash AST (`mvdan.cc/sh/v3`), statically validates it, then executes it via the `mvdan.cc/sh` interpreter (NOT `bash -c`) with runtime hooks that re-validate after variable expansion. When the OS sandbox is enabled, commands are additionally dispatched to a long-lived sandboxed worker process (`os_sandbox/`).

**Security layers** (see `docs/security.md`, the source of truth):

1. **Static preflight** — commands must be in the `allowedCommands` whitelist (`tool/bash_sandboxed/commands.go`); per-command argument validators (`validators*.go`) block dangerous flags (e.g. `find -exec`, `git push`); coprocesses and read-write redirections are rejected; literal path arguments are checked against allowed directories (`paths.go`). Dynamically-named top-level commands (`$CMD ...`) can't be resolved statically, so they are deferred to the runtime layer rather than rejected; dynamic names inside wrappers (`env`/`xargs`/`find -exec`/`timeout`) are still rejected since those children never re-enter the interpreter.
2. **Runtime validation** — the interpreter's `CallHandler`/`ExecHandler`/`OpenHandler` re-validate every command's expanded arguments and every file open, catching bypasses like `cat $HOME/secret`. The whitelist and per-command argument validators are re-enforced here on the fully expanded argv (`CallHandler` covers builtins, `ExecHandler` covers externals), which is what makes deferring dynamic command names safe.
3. **Optional OS sandbox** — bubblewrap (Linux) or sandbox-exec (macOS) confines writes to the working directory and masks sensitive paths (`~/.ssh` private keys, `~/.aws` in IMDS mode).

The whitelist is not read-only: path-scoped write commands (`cp`, `mv`, `rm`, `sed`, `touch`, `mkdir`, ...) are allowed inside the boundary, and opt-in config enables runtimes (Go, pnpm, Deno, Rust, Flutter, uv), `git`, `aws` (via a local IMDS credential broker), and `docker` (via a filtering proxy). Bare `extra_commands` config entries bypass validation entirely and run via real `bash -c` (inside the OS sandbox worker when it is enabled) — a trust-based escape hatch. `unsandboxed_commands` is parsed like `extra_commands` but matching invocations run directly on the host, bypassing the OS sandbox worker (and the docker filtering proxy) even when it is enabled — a stronger escape hatch.

**Key packages:**
- `cmd/` — Cobra CLI: MCP server (`serve.go`), installers (`install*.go`), PreToolUse hook (`hook.go`), interactive shell (`shell.go`), config subcommands (`config_*.go`)
- `tool/bash_sandboxed/` — parsing, validation (static + runtime), execution, background process management
- `os_sandbox/` — sandboxed worker process and pool (bwrap/sandbox-exec, gob protocol)
- `config/` — YAML config loading, watching, and per-directory overrides (any section, via `Config.ForDirectory`)
- `internal/hook` — hook event/decision types; `internal/imds` — IMDS credential server; `internal/dockerproxy` — Docker socket filtering proxy
- `internal/version` — build version (set by GoReleaser ldflags; `lite-sandbox version`); `internal/ghrelease` — GitHub release download client shared by `lite-sandbox update` (`internal/selfupdate`) and the e2e agent provisioning

**Releases:** every push to `main` that passes CI and E2E is tagged and released by `.github/workflows/release.yaml` (GoReleaser, `.goreleaser.yaml`). The semver bump comes from `release:major|minor|patch|skip` labels on the merged PRs (`.github/scripts/next-version.sh`; unlabeled = patch, major is capped to minor while `RELEASE_ALLOW_MAJOR` is false). Asset names (`lite-sandbox_<version>_<os>_<arch>.tar.gz`, `checksums.txt`) are relied on by `internal/selfupdate` — change them together. See `docs/development.md`.

## Testing

After making complex changes (new commands, validation logic, security rules, installer changes), run the e2e suite in addition to unit tests. It drives the real Crush, Codex, Claude Code, and opencode binaries through `lite-sandbox install` and a non-interactive run, with `e2e/mockedserver/mockmodel` (one server speaking the OpenAI chat-completions, OpenAI Responses, and Anthropic Messages APIs) standing in for the LLM — so it needs no API key and behaves identically locally and in CI:

```bash
LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v            # all agents
LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v -run TestCodex
```

The agent versions are pinned in `e2e/mockedserver/versions.go`; `TestMain` downloads all three into `e2e/mockedserver/.bin/agents/<agent>/<version>` on first run, even with `-run` narrowing the tests, and `E2E_CRUSH_VERSION` / `E2E_CODEX_VERSION` / `E2E_CLAUDE_CODE_VERSION` / `E2E_OPENCODE_VERSION` override a version for one run. Without `LITE_SANDBOX_E2E` the tests skip, so `go test ./...` stays offline.

`e2e/claude` is the complementary real-model suite: it sends real prompts to Claude via the Agent SDK (API key required) and checks Claude actually chooses the sandbox tool over built-in Bash — behavior the mock cannot exercise:

```bash
cd e2e/claude && uv run pytest -v
```

## Notes

- always inspect `man` pages of commands you are asked to parse. you can rely on the local pages rather than using web fetch.
- user-facing documentation lives in `docs/` (installation, configuration, runtimes, AWS/Docker, background processes, security, development). Keep it in sync with behavior changes.
