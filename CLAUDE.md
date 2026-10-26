# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
go build -o lite-sandbox         # Build binary
go test ./...                    # Run default suite (OS-sandbox-runtime tests skipped)
go test -run TestValidate ./tool/... # Run a specific test
go run . serve-mcp               # Start MCP server over stdio

# Tests that exercise the real OS sandbox (bwrap on Linux / sandbox-exec on macOS)
# only run when OS_SANDBOX_TESTS is set (CI sets it):
go build -o lite-sandbox && OS_SANDBOX_TESTS=1 go test ./...  # Linux needs bubblewrap + unprivileged userns
```

## Architecture

An MCP server that gives AI coding agents shell access with layered security validation. It exposes `bash` (foreground or background), `kill_shell`, and `list_shells`. `lite-sandbox install` wires it into Claude Code, Codex, opencode, Crush, and Grok Build; `lite-sandbox launch` does the same for a single run without writing config; `lite-sandbox hook` is a PreToolUse hook that confines the agents' built-in file tools to the same boundary.

**Command flow:** MCP request → `cmd/serve.go` → `Sandbox.Execute()` in `tool/bash_sandboxed/`. Commands are parsed into a bash AST (`mvdan.cc/sh/v3`), statically validated, then run by the `mvdan.cc/sh` interpreter — **not** `bash -c` — whose handlers re-validate every expanded command and file open at runtime. With the OS sandbox enabled, commands run in a long-lived sandboxed worker (`os_sandbox/`).

**Security layers** (`docs/security.md` is the source of truth):

1. **Static preflight** — command whitelist, per-command argument validators, path boundary checks on literal arguments.
2. **Runtime validation** — the same checks re-applied to fully expanded argv and file opens. This is what makes deferring dynamic command names (`$CMD ...`) safe; dynamic names inside wrappers (`env`, `xargs`, `find -exec`, ...) are still rejected because those children never re-enter the interpreter.
3. **OS sandbox** (optional) — bubblewrap / sandbox-exec confining writes and hiding the user's private state from the code commands run.

**Modes** (`open`, `denylist`, `allowlist` — the default) decide which validation rules block; every finding is routed through one reporting path that also feeds the audit log. See `docs/adoption.md`.

**Config** (`config/`): YAML with per-directory overrides (linked git worktrees inherit their repository's override). The `paths` and `commands` sections hold grants, escape hatches, and deny lists, merged over built-in denials; a user grant on the same path/command lifts a built-in denial, a profile's never does. **Profiles** (`go`, `pnpm`, `rust`, `gh`, `montypython`, ...) are presets expressed in those same config types and folded in by `Config.Effective()`. Deprecated keys still load and are migrated on save — read config through the accessors, not the raw fields.

**Config requests / ask commands**: the built-in deny list stops the agent from running `lite-sandbox config`, but a single literal `lite-sandbox config ...` (or a `commands` entry with `ask: true`) can be approved by the user through the hook's `ask` answer; the hook records a single-use ticket the server must consume. Config requests are always scoped to the project directory. Codex and Grok must never be answered `ask`.

**Python**: `python`/`python3` run in monty, a wasm Python interpreter embedded in the binary, with its OS calls authorized against the same path sets as bash. monty comes from the `gartnera/monty-go` fork (replace in `go.mod`), which commits `monty.wasm`; changing what crosses the Go/wasm boundary means editing the fork's Rust shim and rebuilding it there (needs Rust and `wasm32-wasip1`).

**Non-obvious invariants:**
- `.claude` directories are read-only to bash validation, but the OS sandbox worker deliberately does **not** mask them (masking broke git checkouts/rebases of tracked `.claude` files).
- Nothing the sandbox can write may be something the host later runs unsandboxed (server `PATH` dirs, GOBIN, the lite-sandbox binary) — see `tool/bash_sandboxed/host_guards.go`.

**Key packages:** `cmd/` (CLI, server, installers, hook, interactive shell), `tool/bash_sandboxed/` (parsing, validation, execution, background processes), `os_sandbox/` (worker and pool), `config/`, `internal/` (audit log, hook types, config requests/approvals, git worktree mapping, IMDS broker, docker proxy, self-update).

**Releases:** every push to `main` is tagged and released by `.github/workflows/release.yaml` (GoReleaser). Asset names are relied on by `internal/selfupdate` — change them together. See `docs/development.md`.

**Label every PR you open with exactly one `release:*` label**: `release:minor` for a new feature or command, `release:patch` for a fix or refactor with no new behavior, `release:skip` for changes that ship nothing to users (docs, CI, tests only), `release:major` for a breaking change (removed/renamed command or flag, config-format change). An unlabeled PR silently becomes a patch release; upgrade the label if the PR grows.

## Testing

After complex changes (new commands, validation logic, security rules, installer changes), run the e2e suite in addition to unit tests. It drives the real Crush, Codex, Claude Code, opencode, and Grok Build binaries (versions pinned in `e2e/mockedserver/versions.go`, auto-downloaded on first run) against a mock model, so it needs no API key:

```bash
LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v            # all agents
LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v -run TestCodex
```

`e2e/claude` is the real-model suite (API key required) checking that Claude actually picks the sandbox tool over built-in Bash: `cd e2e/claude && uv run pytest -v`.

`lite-sandbox launch claude --dry-run` prints the generated agent command — the quickest way to eyeball launch wiring.

## Notes

- Always inspect `man` pages of commands you are asked to parse; rely on the local pages rather than web fetch.
- User-facing documentation lives in `docs/`. Keep it in sync with behavior changes.
