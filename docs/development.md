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

Two complementary suites live under `e2e/`: `e2e/mockedserver` (below) drives the real agent binaries against a mocked model server, so it needs no API key and checks that each installer's configuration works end to end; `e2e/claude` uses a real model to check that Claude actually *chooses* the sandbox tool.

### `e2e/mockedserver` — agents against a mocked model server

The mocked suite (`e2e/mockedserver`) drives the **real agent binaries** — [Crush](https://github.com/charmbracelet/crush), [Codex](https://developers.openai.com/codex), [Claude Code](https://code.claude.com), and [opencode](https://opencode.ai) — through `lite-sandbox install <agent>` and a non-interactive run, and checks that each agent loaded the generated config, launched `lite-sandbox serve-mcp`, offered the sandbox tools (and stopped offering, or had blocked, its built-in shell), and fed the sandbox's results back to the model. No API key is needed: `e2e/mockedserver/mockmodel` stands in for the LLM.

```bash
LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v                 # all agents
LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v -run TestCodex  # one agent
```

`TestMain` provisions everything the suite needs into `e2e/mockedserver/.bin` (override with `E2E_BIN_DIR`) before any test runs, regardless of `-run`: it builds `lite-sandbox` and downloads the pinned Crush, Codex, and opencode GitHub releases and the pinned Claude Code native binary (from the distribution `claude.ai/install.sh` uses, verified against its manifest checksum) — no Node or npm involved. Versions are pinned in `e2e/mockedserver/versions.go`, and each agent is installed once into its own versioned directory (`e2e/mockedserver/.bin/agents/<agent>/<version>`), so switching versions never re-downloads one that is already there. To try a different version for a single run without editing the file, set `E2E_CRUSH_VERSION`, `E2E_CODEX_VERSION`, `E2E_CLAUDE_CODE_VERSION`, or `E2E_OPENCODE_VERSION`. Without `LITE_SANDBOX_E2E` every test skips, so `go test ./...` stays offline. The `E2E` GitHub workflow runs the same command on Linux and macOS, caching `e2e/mockedserver/.bin/agents` keyed on `versions.go`, so a CI run is exactly a local run.

The runs themselves are offline: the model is the mock, each agent's update and telemetry calls are switched off where it offers a switch (`DISABLE_AUTOUPDATER` for Claude Code, `check_for_update_on_startup = false` for Codex; Crush's background version check has no switch), and the harness points `HTTPS_PROXY` at a closed loopback port so any remaining outbound https call fails fast and identically on every machine (`NO_PROXY` keeps the loopback mock off the proxy).

Each test isolates its agent in per-test temp directories through the agent's own config-dir variables — `CRUSH_GLOBAL_CONFIG`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR`, and the XDG directories for opencode — which the installers honor too, so nothing on the developer's machine is read or written.

#### The mock model

The agents speak three different wire protocols — Crush and opencode the OpenAI chat-completions API, Codex only the OpenAI Responses API, Claude Code the Anthropic Messages API — so, like Ollama, `mockmodel` is one server with three endpoints (`/v1/chat/completions`, `/v1/responses`, `/v1/messages`, streaming and not). The protocol is hidden from the tests: every request is normalized into a `Turn` (the tool names offered, the tool results fed back so far), and the scripted behavior is the same everywhere — issue the next scripted tool call, or the final answer once every call has a result. Codex-specific detail: it exposes MCP tools under a namespace (`mcp__lite_sandbox` with functions `bash`, …), which the mock records under Codex's canonical `mcp__lite_sandbox__bash` name and calls back with the namespace-qualified form.

The shared scenario asks each agent to run a blocked command (`curl`, not whitelisted) and then an allowed one, asserts on the sandbox's rejection and output in the results, and checks the installer's usage directive (`CLAUDE.md` / `AGENTS.md` / `CRUSH.md`) reached the model. The install modes are covered too:

- **Claude Code** — default (built-in `Bash` denied and gone from the tool list), `--with-tool-hook` (`Bash` stays but the hook blocks it with a redirect, and a `Write` outside the writable paths is denied), and `--bash-ast-hook-mode` (no MCP server; the hook rejects `curl` and lets `echo` run).
- **Codex** — default (the hook redirects the built-in shell, then the MCP tool runs the scenario) and `--bash-ast-hook-mode`. `codex exec` is run with `--dangerously-bypass-hook-trust`, since Codex otherwise skips hooks the user has not trusted via `/hooks`.
- **Crush** — both config formats the installer edits (`crushrc` and the legacy `crush.json`); Crush has no hook integration.
- **opencode** — the single install mode (built-in `bash` denied via permissions, gone from the tool list); opencode has no hook protocol.

### `e2e/claude` — Claude Agent SDK against a real model

`e2e/claude` verifies real-world usage via the Claude Agent SDK: it sends real prompts and checks that Claude uses the sandboxed MCP tool without falling back to built-in Bash. It needs an Anthropic API key and is run on demand rather than in CI:

```bash
cd e2e/claude
uv run pytest -v          # Run all e2e tests
uv run pytest -v -k test_go_project_workflow  # Run specific test
```

**Showcase test**: `e2e/claude/test_go_runtime_e2e.py` demonstrates a complete Go development workflow — module initialization, writing code and tests, running `go test`, and creating a git commit — all using only the `bash` MCP tool with no built-in Bash calls. This test shows how the sandbox enables safe, autonomous development workflows for AI coding agents.
