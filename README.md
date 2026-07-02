# lite-sandbox-mcp

An MCP (Model Context Protocol) server that provides a `bash` tool as a replacement for basic shell access in AI coding agents. The goal is to let agents run shell commands freely without per-command permission prompts, while enforcing safety through static analysis and runtime validation — commands are parsed into an AST and validated against a whitelist, then executed via a shell interpreter with runtime path validation that catches variable expansion bypasses.

## Quick start

```bash
go install github.com/gartnera/lite-sandbox@latest  # Install the lite-sandbox binary (to $GOPATH/bin)
lite-sandbox install                                 # Configure Claude Code, then restart it
```

`install` registers the MCP server, auto-allows the sandbox tools, denies the built-in `Bash` tool, and adds a usage directive so Claude routes shell commands through the sandbox. See [docs/installation.md](docs/installation.md) for manual setup and the optional tool-hook modes.

To configure **OpenAI Codex CLI** instead, add `--codex`:

```bash
lite-sandbox install --codex                   # MCP server + AGENTS.md directive + PreToolUse hook in ~/.codex
lite-sandbox install --codex --with-tool-hook  # also confine reads/writes (incl. apply_patch) to the sandbox paths
```

Codex's hook protocol matches Claude Code's, so lite-sandbox reuses the same hook binary and the **same config file** to govern both agents — one security/sandbox config for Claude Code and Codex. The `--with-tool-hook` and `--bash-ast-hook-mode` flags compose with `--codex`. See [docs/installation.md](docs/installation.md#openai-codex-cli) for details and coverage caveats.

## Documentation

- **[Installation](docs/installation.md)** — automatic and manual setup, built-in tool boundaries, and hook modes.
- **[Configuration](docs/configuration.md)** — config file, CLI management, readable/writable paths, and git support.
- **[Runtime support](docs/runtimes.md)** — enabling Go, pnpm, and Deno.
- **[AWS & Docker access](docs/aws-and-docker.md)** — brokered AWS credentials and the filtering Docker proxy.
- **[Background processes](docs/background-processes.md)** — running and managing long-lived commands.
- **[Security model](docs/security.md)** — validation layers, the optional OS sandbox, and known limitations.
- **[Development](docs/development.md)** — building, testing, and the e2e suite.
