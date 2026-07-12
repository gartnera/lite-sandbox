# lite-sandbox-mcp

An MCP (Model Context Protocol) server that provides a `bash` tool as a replacement for basic shell access in AI coding agents. The goal is to let agents run shell commands freely without per-command permission prompts, while enforcing safety through static analysis and runtime validation — commands are parsed into an AST and validated against a whitelist, then executed via a shell interpreter with runtime path validation that catches variable expansion bypasses.

## Quick start

```bash
go install github.com/gartnera/lite-sandbox@latest  # Install the lite-sandbox binary (to $GOPATH/bin)
lite-sandbox install                                 # Configure every detected agent CLI, then restart them
```

`install` autodetects which supported agent CLIs — **Claude Code**, **OpenAI Codex CLI**, and **opencode** — are installed on the host (binary on `PATH` or config directory present) and configures each one: it registers the MCP server, auto-allows the sandbox tools, blocks the built-in shell tool, and adds a usage directive so the agent routes shell commands through the sandbox. Name agents explicitly to configure just those:

```bash
lite-sandbox install                       # autodetect claude / codex / opencode
lite-sandbox install codex                 # configure only Codex
lite-sandbox install claude opencode       # configure exactly these
lite-sandbox install codex --with-tool-hook # also confine reads/writes (incl. apply_patch) to the sandbox paths
```

Codex's hook protocol matches Claude Code's, so lite-sandbox reuses the same hook binary and the **same config file** to govern both agents — one security/sandbox config for all of them. The `--with-tool-hook` and `--bash-ast-hook-mode` flags apply to `claude` and `codex` (opencode has no compatible hook protocol). See [docs/installation.md](docs/installation.md) for manual setup, per-agent details, and coverage caveats.

## Documentation

- **[Installation](docs/installation.md)** — automatic and manual setup, built-in tool boundaries, and hook modes.
- **[Configuration](docs/configuration.md)** — config file, CLI management, readable/writable paths, and git support.
- **[Runtime support](docs/runtimes.md)** — enabling Go, pnpm, Rust, Deno, and uv.
- **[AWS & Docker access](docs/aws-and-docker.md)** — brokered AWS credentials and the filtering Docker proxy.
- **[Background processes](docs/background-processes.md)** — running and managing long-lived commands.
- **[Security model](docs/security.md)** — validation layers, the optional OS sandbox, and known limitations.
- **[Development](docs/development.md)** — building, testing, and the e2e suite.
