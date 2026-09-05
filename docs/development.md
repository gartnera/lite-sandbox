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

The e2e suite (`e2e/`) drives the **real agent binaries** — [Crush](https://github.com/charmbracelet/crush), [Codex](https://developers.openai.com/codex), and [Claude Code](https://code.claude.com) — through `lite-sandbox install <agent>` and a non-interactive run, and checks that each agent loaded the generated config, launched `lite-sandbox serve-mcp`, offered the sandbox tools (and stopped offering, or had blocked, its built-in shell), and fed the sandbox's results back to the model. No API key is needed: `e2e/mockmodel` stands in for the LLM.

```bash
LITE_SANDBOX_E2E=1 go test ./e2e/ -v                 # all agents
LITE_SANDBOX_E2E=1 go test ./e2e/ -v -run TestCodex  # one agent
```

`TestMain` provisions everything the suite needs into `e2e/.bin` (override with `E2E_BIN_DIR`): it builds `lite-sandbox`, downloads the pinned Crush release, and `npm install`s the pinned Codex and Claude Code into private prefixes (so `npm` must be on `PATH`). Versions are pinned in `e2e/versions.go`, and each agent is installed once into its own versioned directory (`e2e/.bin/agents/<agent>/<version>`), so switching versions never re-downloads one that is already there. To try a different version for a single run without editing the file, set `E2E_CRUSH_VERSION`, `E2E_CODEX_VERSION`, or `E2E_CLAUDE_CODE_VERSION`. Without `LITE_SANDBOX_E2E` every test skips, so `go test ./...` stays offline. The `E2E` GitHub workflow runs the same command on Linux and macOS, caching `e2e/.bin/agents` keyed on `versions.go`, so a CI run is exactly a local run.

The runs themselves are offline: the model is the mock, each agent's update and telemetry calls are switched off where it offers a switch (`DISABLE_AUTOUPDATER` for Claude Code, `check_for_update_on_startup = false` for Codex; Crush's background version check has no switch), and the harness points `HTTPS_PROXY` at a closed loopback port so any remaining outbound https call fails fast and identically on every machine (`NO_PROXY` keeps the loopback mock off the proxy).

Each test isolates its agent in per-test temp directories through the agent's own config-dir variable — `CRUSH_GLOBAL_CONFIG`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR` — which the installers honor too, so nothing on the developer's machine is read or written.

### The mock model

The three agents speak three different wire protocols — Crush the OpenAI chat-completions API, Codex only the OpenAI Responses API, Claude Code the Anthropic Messages API — so, like Ollama, `mockmodel` is one server with three endpoints (`/v1/chat/completions`, `/v1/responses`, `/v1/messages`, streaming and not). The protocol is hidden from the tests: every request is normalized into a `Turn` (the tool names offered, the tool results fed back so far), and the scripted behavior is the same everywhere — issue the next scripted tool call, or the final answer once every call has a result. Codex-specific detail: it exposes MCP tools under a namespace (`mcp__lite_sandbox` with functions `bash`, …), which the mock records under Codex's canonical `mcp__lite_sandbox__bash` name and calls back with the namespace-qualified form.

The shared scenario asks each agent to run a blocked command (`curl`, not whitelisted) and then an allowed one, and asserts on the sandbox's rejection and output in the results. Codex additionally runs the built-in shell first to prove the installer's `PreToolUse` hook blocks it (`codex exec` is run with `--dangerously-bypass-hook-trust`, since Codex otherwise skips hooks the user has not trusted via `/hooks`).
