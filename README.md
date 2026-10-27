# lite-sandbox-mcp

An MCP (Model Context Protocol) server that gives AI coding agents a `bash` tool to use instead of their built-in shell. Agents can run commands without a permission prompt for each one. Every command is parsed into an AST, checked against a whitelist, and then run by a shell interpreter that re-checks paths after variable expansion.

## Quick start

```bash
curl -fsSL https://raw.githubusercontent.com/gartnera/lite-sandbox/main/install.sh | sh  # Install the latest release to ~/.local/bin
lite-sandbox install                                                                       # Configure every detected agent CLI, then restart them
```

The script downloads the prebuilt binary for Linux or macOS (amd64/arm64) from the latest [GitHub release](https://github.com/gartnera/lite-sandbox/releases). With the [GitHub CLI](https://cli.github.com) logged in, it uses `gh` to download and verify the release's build provenance attestation; otherwise it checks the download against `checksums.txt`. See [docs/installation.md](docs/installation.md#getting-the-binary) for options. `lite-sandbox update` upgrades an installed binary to the latest release, and `lite-sandbox version` shows the current one.

The default is the strictest mode: only whitelisted commands run, and toolchain profiles (Go, Rust, uv, ...) are opt-in. To start looser and tighten over time, see [docs/adoption.md](docs/adoption.md).

`install` detects which supported agent CLIs are installed (**Claude Code**, **OpenAI Codex CLI**, **opencode**, **Crush**, and **Grok Build**), by looking for the binary on `PATH` or the config directory. For each one it registers the MCP server, auto-allows the sandbox tools, blocks the built-in shell tool, and adds a directive telling the agent to use the sandbox for shell commands. Name agents to configure only those:

```bash
lite-sandbox install                       # autodetect claude / codex / opencode / crush / grok
lite-sandbox install codex                 # configure only Codex
lite-sandbox install claude opencode       # configure exactly these
lite-sandbox install codex --with-tool-hook # also confine reads/writes (incl. apply_patch) to the sandbox paths
lite-sandbox install grok                  # Grok Build: its file tools are always confined to the sandbox paths
```

To try the sandbox without changing any agent configuration, use `launch`. It runs the agent sandboxed for one session and doesn't touch your setup.

```bash
lite-sandbox launch claude
```

All agents share one sandbox config file. See [docs/installation.md](docs/installation.md) for manual setup, hook modes, and per-agent caveats.

## Documentation

- **[Incremental adoption](docs/adoption.md)**: the other enforcement modes, audit reports, and tightening over time.
- **[Installation](docs/installation.md)**: getting and updating the binary, automatic and manual agent setup, built-in tool boundaries, and hook modes.
- **[Configuration](docs/configuration.md)**: the config file, CLI management, readable/writable paths, and git support.
- **[Toolchain profiles](docs/profiles.md)**: the built-in sandboxed Python, and enabling Go, pnpm, Rust, Deno, Flutter, Xcode, uv, and the GitHub CLI.
- **[AWS & Docker access](docs/aws-and-docker.md)**: brokered AWS credentials and the filtering Docker proxy.
- **[Background processes](docs/background-processes.md)**: running and managing long-lived commands.
- **[Interactive shell](docs/shell.md)**: `lite-sandbox shell`, a shell for you that runs commands under the sandbox's rules.
- **[Security model](docs/security.md)**: validation layers, the optional OS sandbox, and known limitations.
- **[Development](docs/development.md)**: building, testing, the e2e suite, and the release flow.
