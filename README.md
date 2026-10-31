# lite-sandbox

`lite-sandbox` gives AI coding agents a `bash` tool to use instead of their built-in shell, so they can run commands without a permission prompt for each one. Rather than matching commands with regexps or asking an LLM to judge them, it parses every command into an AST and checks the programs, flags, and paths it finds.

## Quick start

```bash
curl -fsSL https://github.com/gartnera/lite-sandbox/raw/main/install.sh | sh
```

Try it for one session first. This doesn't touch your agent configuration:

```bash
lite-sandbox launch claude
```

If you like it, configure your agents permanently:

```bash
lite-sandbox install
```

This sets up every supported agent it finds. Run `lite-sandbox install --help` for options.

All agents share one sandbox config file, so you can switch agents without reconfiguring anything.

The default is strict: only allowlisted commands run, and toolchains like Go, Rust, and uv are opt-in. To start looser and tighten over time, see [incremental adoption](docs/adoption.md).

## Agent support

| | [Claude Code](docs/installation.md#claude-code) | [Codex CLI](docs/installation.md#openai-codex-cli) | [opencode v1](docs/installation.md#opencode) | [Crush](docs/installation.md#crush) | [Grok Build](docs/installation.md#grok-build) |
|---|:-:|:-:|:-:|:-:|:-:|
| Sandboxed `bash` tool, built-in shell blocked | ✅ | ✅ | ✅ | ✅ | ✅ |
| Built-in file tools confined to sandbox paths | `--with-tool-hook` | `--with-tool-hook` | | | ✅ |
| AST-check the built-in shell (`--bash-ast-hook-mode`) | ✅ | ✅ | | | ✅ |
| [Config requests](docs/configuration.md#config-requests-the-agent-runs-lite-sandbox-config-with-your-approval) | ✅ | | | | |
| [`lite-sandbox launch`](docs/installation.md#temporary-setup-lite-sandbox-launch) | ✅ | | | | |

## Documentation

- [Incremental adoption](docs/adoption.md): enforcement modes, audit reports
- [Installation](docs/installation.md): updating, manual setup, per-agent caveats, hook modes
- [Configuration](docs/configuration.md): config file, readable/writable paths, git
- [Toolchain profiles](docs/profiles.md): built-in Python, Go, pnpm, Rust, Deno, Flutter, Xcode, uv, `gh`, agent-browser
- [AWS & Docker](docs/aws-and-docker.md): brokered AWS credentials, filtering Docker proxy
- [SSH](docs/ssh.md): ssh to the hosts you list, filtered ssh agent
- [Background processes](docs/background-processes.md): long-running commands
- [Interactive shell](docs/shell.md): `lite-sandbox shell`, a shell for you that follows the same rules
- [Security model](docs/security.md): validation layers, OS sandbox, known limitations
- [Development](docs/development.md): building, testing, releases
