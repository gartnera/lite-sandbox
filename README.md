# lite-sandbox-mcp

An MCP (Model Context Protocol) server that gives AI coding agents a `bash` tool to use instead of their built-in shell. Agents can run commands without a permission prompt for each one. Every command is parsed into an AST, checked against a whitelist, and then run by a shell interpreter that re-checks paths after variable expansion.

## Quick start

```bash
go install github.com/gartnera/lite-sandbox@latest  # Install the lite-sandbox binary (to $GOPATH/bin)
lite-sandbox install                                 # Configure every detected agent CLI, then restart them
```

Prebuilt binaries for Linux and macOS (amd64/arm64) are attached to every [GitHub release](https://github.com/gartnera/lite-sandbox/releases). `lite-sandbox update` upgrades an installed binary to the latest release, and `lite-sandbox version` shows the current one.

The default is the strictest mode: only whitelisted commands run, and code-execution runtimes are opt-in. To start looser and tighten over time, see [docs/adoption.md](docs/adoption.md).

`install` detects which supported agent CLIs are installed (**Claude Code**, **OpenAI Codex CLI**, **opencode**, and **Crush**), by looking for the binary on `PATH` or the config directory. For each one it registers the MCP server, auto-allows the sandbox tools, blocks the built-in shell tool, and adds a directive telling the agent to use the sandbox for shell commands. Name agents to configure only those:

```bash
lite-sandbox install                       # autodetect claude / codex / opencode / crush
lite-sandbox install codex                 # configure only Codex
lite-sandbox install claude opencode       # configure exactly these
lite-sandbox install codex --with-tool-hook # also confine reads/writes (incl. apply_patch) to the sandbox paths
```

To try the sandbox without changing any agent configuration, use `launch`. It runs the agent sandboxed for one session and doesn't touch your setup.

```bash
lite-sandbox launch claude
```

Codex uses the same hook protocol as Claude Code, so both agents share one hook binary and one config file. The `--with-tool-hook` and `--bash-ast-hook-mode` flags apply to `claude` and `codex`; opencode has no compatible hook protocol. See [docs/installation.md](docs/installation.md) for manual setup, per-agent details, and coverage caveats.

## Documentation

- **[Incremental adoption](docs/adoption.md)**: the other enforcement modes, audit reports, and tightening over time.
- **[Installation](docs/installation.md)**: getting and updating the binary, automatic and manual agent setup, built-in tool boundaries, and hook modes.
- **[Configuration](docs/configuration.md)**: the config file, CLI management, readable/writable paths, and git support.
- **[Runtime support](docs/runtimes.md)**: the built-in sandboxed Python, and enabling Go, pnpm, Rust, Deno, and uv.
- **[AWS & Docker access](docs/aws-and-docker.md)**: brokered AWS credentials and the filtering Docker proxy.
- **[Background processes](docs/background-processes.md)**: running and managing long-lived commands.
- **[Security model](docs/security.md)**: validation layers, the optional OS sandbox, and known limitations.
- **[Development](docs/development.md)**: building, testing, the e2e suite, and the release flow.
