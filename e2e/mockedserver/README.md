# Mocked-server e2e

Drives the real Crush, Codex, Claude Code, and opencode binaries through `lite-sandbox install <agent>` and a non-interactive run, with an in-process mock standing in for the model. Run it with `LITE_SANDBOX_E2E=1 go test ./e2e/mockedserver/ -v`.

- `mockmodel/` serves the three wire protocols the agents speak (OpenAI chat completions, OpenAI Responses, Anthropic Messages) and normalizes every request into a protocol-agnostic `Turn`, so the tests never see the protocol.
- The mock is scripted: it asks the agent to run a blocked command (`curl`), then an allowed one, and answers with the last tool result; the tests assert on the tools offered, the sandbox's rejection and output, and that the installer's directive reached the model.
- `TestMain` provisions the pinned agents (`versions.go`) as native release binaries into `.bin/agents/<agent>/<version>`, plus a fresh `lite-sandbox` build; nothing but Go is needed, and no API key.
- Each test isolates its agent in temp directories via `CRUSH_GLOBAL_CONFIG`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR`, or the XDG variables (opencode), and runs offline (`HTTPS_PROXY` points at a closed port).
- Install modes are covered per agent (default, `--with-tool-hook`, `--bash-ast-hook-mode` where the agent supports them). The sibling `e2e/claude` suite is the real-model counterpart.
