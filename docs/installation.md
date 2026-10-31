# Installing & Configuring

## Getting the binary

Every merge to `main` publishes a [GitHub release](https://github.com/gartnera/lite-sandbox/releases) with prebuilt binaries for Linux and macOS on amd64 and arm64, as `lite-sandbox_<version>_<os>_<arch>.tar.gz` archives plus a `checksums.txt`. The install script picks the archive for your platform and installs the binary to `~/.local/bin`:

```bash
curl -fsSL https://github.com/gartnera/lite-sandbox/raw/main/install.sh | sh
```

The script ends by telling you what to run next. If `~/.local/bin` isn't on your `PATH` yet, it prints the full path to the binary and the `export PATH=...` line to add to your shell profile.

Pass options after `sh -s --`:

```bash
curl -fsSL https://github.com/gartnera/lite-sandbox/raw/main/install.sh | sh -s -- --version v0.4.0
curl -fsSL https://github.com/gartnera/lite-sandbox/raw/main/install.sh | sh -s -- --dir /usr/local/bin
```

How the script downloads and verifies the archive depends on the [GitHub CLI](https://cli.github.com):

- **`gh` 2.67 or later, logged in** (`gh auth status`): it downloads with `gh release download` and checks the archive's [build provenance attestation](#verifying-a-download) with `gh attestation verify`, requiring it to be signed by this repository's release workflow running on `main`. A failed verification stops the install. Older `gh` versions are skipped: before 2.49 they have no `gh attestation`, and before 2.67 `gh attestation verify` can pass an archive that has no attestation ([CVE-2025-25204](https://osv.dev/vulnerability/CVE-2025-25204)).
- **Otherwise**: it downloads with `curl` and checks the archive's SHA-256 against the release's `checksums.txt`. This catches a corrupted download but, unlike the attestation, does not prove where the archive came from.

The binary is replaced atomically, so a running `lite-sandbox serve-mcp` keeps the old build until your agent restarts. Afterwards the script checks your `PATH`: it warns if the install directory isn't on it (with the `export PATH=...` line to add to your shell profile), or if another `lite-sandbox` earlier on `PATH` (for example an old `go install` in `$GOPATH/bin`) would run instead.

To build from source instead:

```bash
go install github.com/gartnera/lite-sandbox@latest   # latest release, into $GOPATH/bin
```

### Verifying a download

Releases are immutable, and each asset has a signed [build provenance attestation](https://docs.github.com/en/actions/concepts/security/artifact-attestations) showing it was built from this repository by the release workflow. The install script checks it when `gh` is available. To verify an archive by hand:

```bash
gh attestation verify lite-sandbox_<version>_<os>_<arch>.tar.gz -R gartnera/lite-sandbox
```

### Updating

`lite-sandbox update` replaces the running binary with the latest release, wherever it is installed. It follows symlinks to the real file, so a `go install`ed binary in `$GOPATH/bin` updates too:

```bash
lite-sandbox update                   # install the latest release
lite-sandbox update --check           # only report whether one is available
lite-sandbox update --version v0.4.0  # install (or roll back to) a specific release
lite-sandbox update --force           # reinstall even if already on the target version
```

It downloads the archive for this OS/arch, verifies it against the release's `checksums.txt`, and atomically renames a temp file over the binary. A failed update never leaves a half-written binary, and running MCP servers keep using the old build. **Restart your agent afterwards** so its `lite-sandbox serve-mcp` picks up the new version. If the binary is in a directory you can't write to, use `sudo`. Downloads are anonymous by default; set `GITHUB_TOKEN` (or `GH_TOKEN`) to use the authenticated GitHub API if you hit the anonymous rate limit.

## Automatic Installation

```bash
lite-sandbox install
```

With no arguments, `install` detects which supported agent CLIs are installed ([Claude Code](#claude-code), [OpenAI Codex CLI](#openai-codex-cli), [opencode](#opencode), [Crush](#crush), [Grok Build](#grok-build), and [pi](#pi)) and configures each one. A CLI counts as installed when its binary is on `PATH` (`claude`, `codex`, `opencode`, `crush`, `grok`, `pi`) or its config directory exists (`~/.claude`/`$CLAUDE_CONFIG_DIR`, `~/.codex`/`$CODEX_HOME`, `~/.config/opencode`/`$XDG_CONFIG_HOME/opencode`/`$OPENCODE_CONFIG_DIR`, `~/.config/crush`/`$XDG_CONFIG_HOME/crush`/`$CRUSH_GLOBAL_CONFIG`, `~/.grok`/`$GROK_HOME`, `~/.pi/agent`/`$PI_CODING_AGENT_DIR`). Name agents to configure only those:

```bash
lite-sandbox install                  # autodetect claude / codex / opencode / crush / grok / pi
lite-sandbox install codex            # configure only Codex
lite-sandbox install claude opencode  # configure exactly these
```

`install` also sets up lite-sandbox's own config (`lite-sandbox config path`). A **first-time** config is created with only `audit: true`, so the mode is the `allowlist` default and validation findings are logged for `lite-sandbox audit report`. An **existing** config is left alone. To start in a looser mode, pass `--mode denylist` (or `open`). `denylist` also enables the OS sandbox if `os_sandbox` was never set and bubblewrap (Linux) or sandbox-exec (macOS) passes a preflight check. See [Incremental adoption](adoption.md).

The `--with-tool-hook` and `--bash-ast-hook-mode` flags described below apply to `claude`, `codex`, and `grok`, which share lite-sandbox's PreToolUse hook protocol, and to `pi`, whose lite-sandbox extension runs the same hook (for `grok` and `pi`, `--with-tool-hook` is always on). opencode has no compatible hook protocol, and lite-sandbox's hook doesn't govern Crush's built-in tools, so `--with-tool-hook` does nothing for those two and `--bash-ast-hook-mode` skips them.

## Temporary setup: `lite-sandbox launch`

`launch` starts an agent CLI with the sandbox wired up, without writing to the agent's configuration. Everything `install` would write to the agent's config files is passed on the agent's command line or in its environment instead, so the sandbox applies to that session only.

It supports Claude Code, Codex, opencode, Crush, and pi:

```bash
lite-sandbox launch claude                     # interactive session, sandboxed
lite-sandbox launch claude -p "run the tests"  # arguments after the agent are passed through
lite-sandbox launch codex exec "run the tests"
lite-sandbox launch opencode
lite-sandbox launch crush
lite-sandbox launch pi
lite-sandbox launch --dry-run codex            # print the command instead of running it
```

Everything after the agent name is passed to the agent unchanged, so lite-sandbox's own flags go before it (or are separated with `--`).

Grok Build isn't supported. Its `GROK_CONFIG` overlay only accepts soft settings and `--plugin-dir` only works with `grok agent stdio`, so the interactive CLI has no way to add an MCP server or hook for one session. Use `lite-sandbox install grok`.

### What it passes

**These are added on top of your own configuration.** Your own settings, MCP servers, and instruction files still load, and your sign-in state is untouched.

| Agent | What `install` writes | What `launch` passes |
| --- | --- | --- |
| Claude Code | MCP server in `~/.claude.json` | `--mcp-config` (without `--strict-mcp-config`, so your servers still load) |
| | Permissions + `PreToolUse` hook in `~/.claude/settings.json` | `--settings`, merged with your `settings.json` |
| | Usage directive in `~/.claude/CLAUDE.md` | `--append-system-prompt` |
| Codex | `[mcp_servers.lite-sandbox]` in `config.toml` | `-c mcp_servers.lite-sandbox.*` overrides |
| | Usage directive in `AGENTS.md` | `-c developer_instructions`, after any `developer_instructions` of your own from `config.toml` (one from a `--profile` file is replaced for the session) |
| | `PreToolUse` hook redirecting the built-in shell | `--disable shell_tool`: the built-in shell is removed from the session |
| | `PreToolUse` hook for the file tools (`--with-tool-hook`) | `-c hooks.PreToolUse`, `--enable hooks`, and `--dangerously-bypass-hook-trust` ([below](#codex-hook-trust)) |
| opencode v1 | MCP server and permissions in `opencode.json` | `OPENCODE_CONFIG_CONTENT`, which opencode merges over your global and project configs (and over an `OPENCODE_CONFIG_CONTENT` you already set) |
| opencode v2 | v2's MCP server and permission rules in `opencode.json` | The same in `OPENCODE_CONFIG_CONTENT`, plus `--standalone` (see [below](#opencode-v2-standalone)) |
| | Usage directive in `AGENTS.md` | `instructions` naming a file in lite-sandbox's cache directory |
| Crush | MCP server and permissions in `crushrc` (or `crush.json`) | `CRUSH_GLOBAL_CONFIG` pointing at a stand-in config directory ([below](#crush-stand-in-config)) |
| | Usage directive in `CRUSH.md` | A global context path in the stand-in `crushrc` |
| pi | Extension in `~/.pi/agent/extensions/lite-sandbox.ts` (MCP server, hook, usage directive) | `-e`, with the same extension kept in lite-sandbox's cache directory (`<cache>/lite-sandbox/launch/pi`, named by its content) |
| | `"-bash"` in `defaultTools` in `~/.pi/agent/settings.json` | `--exclude-tools bash` |

<a id="opencode-v2-standalone"></a>
#### opencode v2: `--standalone`

By default, v2's TUI and `opencode run` hand the session to a background service that every opencode client shares. The service is started with whatever environment its first client had and is reused while it's healthy, so a launched session's `OPENCODE_CONFIG_CONTENT` would never reach it, and the session would run with the built-in shell and without the sandbox. `launch` therefore adds `--standalone`, which runs a private server that inherits the sandbox configuration, and refuses `--server`, which connects to a server started without it.

#### Codex hook trust

Codex runs only the hooks you've trusted in its `/hooks` screen, and it records that trust in `config.toml`, so a hook passed for one session would be silently skipped. Its only per-session way past that is `--dangerously-bypass-hook-trust`, which `launch codex` passes whenever it registers a hook (the default `--with-tool-hook`, or `--bash-ast-hook-mode`), along with `--enable hooks` in case you turned the hooks feature off. The bypass covers every enabled hook in the session, so **your own enabled user and plugin hooks also run without review**. Project hooks still need the project to be trusted. Pass `--with-tool-hook=false` to launch with no hook and no bypass. The built-in shell is removed either way, so blocking it doesn't depend on a hook.

#### Crush stand-in config

Crush has no flag or variable that adds configuration, only `CRUSH_GLOBAL_CONFIG`, which moves its whole global config directory. `launch crush` points it at a stand-in directory, `<cache>/lite-sandbox/launch/crush/<id>` (`<cache>` is `~/.cache` on Linux, `~/Library/Caches` on macOS). There's one per config directory and lite-sandbox binary, since Crush reloads its `crushrc` while it runs, and launch rewrites it on every launch:

- `crush.json` is a symlink to your global `crush.json`, if you have one.
- `crushrc` sources your global `crushrc`, if you have one, in a subshell from your config directory, so it runs as it would without the launch and an `exit` in it can't skip what follows. Then it adds the sandbox's MCP server, `permissions deny bash`, and `permissions allow` for the sandbox tools, as `install crush` writes them. Last, it sets the global context paths to your `CRUSH.md`, the `AGENTS.md` beside your config directory (Crush's defaults), and the usage directive. These are added to any `global_context_paths` you set yourself, so if you dropped one of the defaults, it comes back for launched sessions.

Crush's data directory, skills, and commands don't depend on `CRUSH_GLOBAL_CONFIG`, and project configs still load. `launch crush` needs crush v0.88.0 or newer, since older versions don't read `crushrc`.

`launch pi` refuses to run when the extension is already installed in `~/.pi/agent/extensions`: plain `pi` is then sandboxed already, and pi would refuse to load a second copy.

### Defaults

Because it configures one session rather than every project, `launch` is stricter than `install` by default:

- **The built-in shell is blocked outright.** Claude Code's `Bash` is denied as in the default install, so the model isn't offered it. Codex's is removed with `--disable shell_tool`. opencode's `bash` (v2: `shell`) is denied and Crush's is disabled, as `install` does, and pi's is left out with `--exclude-tools`.
- **`--with-tool-hook` is on** for Claude Code and Codex. The `PreToolUse` hook confines the built-in `Read`/`Glob`/`Grep` to the sandbox's readable paths and `Write`/`Edit`/`NotebookEdit` (and Codex's `apply_patch`) to its writable paths. For Claude Code this is stricter than `install --with-tool-hook`, which moves the `Bash` block into the hook so the redirect message reaches the model; `launch` keeps the permission deny and adds the file-tool boundary. Pass `--with-tool-hook=false` to get install's default behavior. opencode and Crush have no compatible hook, so their file tools aren't confined, as with `install`. pi's are always confined, as with `install pi`, so `--with-tool-hook=false` is refused for it.
- **`--permission-mode acceptEdits`** (Claude Code only), written as `permissions.defaultMode`, so edits apply without a prompt. The hook keeps them inside the boundary, and a write outside it is still denied. Pass `--permission-mode ""` to keep Claude Code's own default, or pass your own `--permission-mode` *after* the agent name, which overrides the setting.

`--bash-ast-hook-mode` and `--always-load` behave as they do for `install` (see below), for Claude Code and Codex, and `--bash-ast-hook-mode` for pi too. A flag that has no effect on the chosen agent (`--permission-mode` for anything but Claude Code, `--bash-ast-hook-mode` or an explicit `--with-tool-hook` for opencode or Crush) is refused rather than ignored.

`launch` reads lite-sandbox's own config (`lite-sandbox config path`) as usual but, unlike `install`, never creates or modifies it. A host without one runs at the `allowlist` default. Use `lite-sandbox config ...` to change it, and `install` for a persistent agent setup. The only files `launch` writes are opencode's directive, Crush's stand-in config, and pi's extension, under lite-sandbox's cache directory. That directory is as protected as lite-sandbox's config file: outside the path boundary, and read-only under the OS sandbox in `denylist` mode. This matters for Crush, which runs the stand-in `crushrc` as a script.

## Claude Code

For Claude Code, `lite-sandbox install` (or `lite-sandbox install claude`):
1. Adds the MCP server (`lite-sandbox serve-mcp --config-requests`) to `~/.claude.json` (user-scoped) with `"alwaysLoad": true` (see [`--always-load`](#always-load) below)
2. Adds allow rules for the lite-sandbox MCP tools (`bash`, `kill_shell`, `list_shells`) **and denies the built-in `Bash` tool** in `~/.claude/settings.json`
3. Registers a `PreToolUse` hook matching `mcp__lite-sandbox__.*` that allows those tools. Subagents and skills don't inherit `permissions.allow` from `settings.json` ([anthropics/claude-code#18950](https://github.com/anthropics/claude-code/issues/18950)), but hooks still fire there, so this keeps the sandbox tools prompt-free inside them. It grants nothing the allow rules don't: the tools validate every command themselves, and a `permissions.deny` rule still overrides a hook allow. The one bash command it doesn't allow is a [config request](configuration.md#config-requests-the-agent-runs-lite-sandbox-config-with-your-approval), a lone `lite-sandbox config ...` that the agent runs to change the sandbox's policy. For that command the hook answers `ask` (unless it only asks for `--help`), so you approve each change (the hook is registered as `lite-sandbox hook --config-requests`). It answers `ask` the same way for a command that runs a [command that asks first](configuration.md#commands-that-ask-first) (`commands` entry with `ask: true`).
4. Adds a usage directive to `~/.claude/CLAUDE.md`

All of these honor `CLAUDE_CONFIG_DIR` the way Claude Code does: when it is set, `settings.json`, `CLAUDE.md`, and `.claude.json` are all written under that directory (Claude Code then keeps its user config at `$CLAUDE_CONFIG_DIR/.claude.json` instead of `~/.claude.json`).

Denying the built-in `Bash` tool leaves Claude Code no unvalidated shell, so every command goes through AST validation and, if enabled, the OS sandbox. Claude Code applies `Bash` permission rules to its [`Monitor`](https://code.claude.com/docs/en/tools-reference#monitor-tool) tool too, which runs a command in the background and streams its output to the model, so the deny covers it as well.

To extend the sandbox to Claude Code's **built-in tools**, add `--with-tool-hook`:

```bash
lite-sandbox install --with-tool-hook
```

This widens the `PreToolUse` hook matcher. Besides allowing the `mcp__lite-sandbox__*` tools, the hook then (1) blocks the built-in `Bash` and `Monitor` tools with a message redirecting the model to `mcp__lite-sandbox__bash`, and (2) denies `Read` outside the sandbox's readable paths and `Write`/`Edit`/`NotebookEdit` outside its writable paths (see [Built-in tool boundaries](#built-in-tool-boundaries)). It is off by default. When on, the hook blocks `Bash` instead of the permission `deny` rule, so the redirect message reaches the model.

To keep using Claude Code's own `Bash` tool with a static check in front of it, add `--bash-ast-hook-mode`:

```bash
lite-sandbox install --bash-ast-hook-mode                  # AST-check Bash only
lite-sandbox install --with-tool-hook --bash-ast-hook-mode # AST-check Bash + confine Read/Write/Edit
```

In this mode the hook parses each `Bash` and `Monitor` command and checks it against the same whitelist and path boundaries as the bash tool. It allows the command without a permission prompt if it passes and denies it with the validation error if it doesn't; a passing command that runs a [command that asks first](configuration.md#commands-that-ask-first) gets Claude Code's permission prompt instead (Codex, which runs a tool call it is answered `ask` for instead of asking, gets a denial: the hook recognizes its events by the `turn_id` and `model` fields Codex adds). **`Bash` and `Monitor` still run unsandboxed.** There is no runtime enforcement, only the static check, so this is weaker than running commands through the MCP tool (see [Built-in tool boundaries](#built-in-tool-boundaries)). Since nothing is redirected to the MCP tool, this mode **does not configure the MCP server** (no MCP allow, no `CLAUDE.md` directive). On its own it governs only `Bash` and `Monitor`; add `--with-tool-hook` to also confine the built-in `Read`/`Write`/`Edit` tools.

<a id="always-load"></a>

### `--always-load`

Claude Code's [Tool Search](https://docs.claude.com/en/docs/claude-code/mcp) defers MCP tool definitions by default and loads them on demand. With the built-in `Bash` tool denied, the sandbox `bash` tool is needed on almost every turn, so `install claude` sets `"alwaysLoad": true` on the MCP server entry. Its tools are then present at session start instead of appearing only after a Tool Search:

```jsonc
// ~/.claude.json
{
  "mcpServers": {
    "lite-sandbox": {
      "command": "/path/to/lite-sandbox",
      "args": ["serve-mcp"],
      "alwaysLoad": true
    }
  }
}
```

To let the sandbox tools be deferred like any other MCP server, pass `--always-load=false`:

```bash
lite-sandbox install claude --always-load=false
```

Codex works the same way. Newer Codex models defer MCP tools behind Codex's `tool_search` by default, so `install codex` sets `omit_tools_from = ["deferred"]` on its server table, which keeps the sandbox tools in the model's initial tool list. `--always-load=false` omits it there too. The flag does nothing for opencode, Crush, and Grok Build (which always reaches MCP tools through its `search_tool`/`use_tool` pair; opencode v2 reaches them through Code Mode), or in `--bash-ast-hook-mode` (which doesn't configure the MCP server).

Restart the agent after running the install command.

## OpenAI Codex CLI

To configure [OpenAI Codex CLI](https://developers.openai.com/codex), run the install (autodetected, or named explicitly):

```bash
lite-sandbox install codex
```

(The old `--codex` flag still works but is deprecated.)

This:
1. Registers the MCP server under `[mcp_servers.lite-sandbox]` in `~/.codex/config.toml`, with `default_tools_approval_mode = "approve"` so Codex auto-approves the sandboxed tools, and `omit_tools_from = ["deferred"]` (Codex's equivalent of Claude's `alwaysLoad`; see [`--always-load`](#always-load)). A per-call Codex prompt would be redundant since lite-sandbox is itself the boundary. Only this server's tools are affected. Older Codex versions that don't know these keys ignore them.
2. Adds a usage directive to `~/.codex/AGENTS.md` pointing Codex to the sandboxed `bash` tool
3. Registers a `PreToolUse` hook (`[[hooks.PreToolUse]]`) that blocks Codex's built-in shell and redirects it to the sandboxed MCP tool

> **Trust the hook.** Codex skips hooks it hasn't been told to trust. Trust is recorded against the hook's exact definition, so a new or changed hook does nothing until you open Codex, run `/hooks`, and trust the lite-sandbox entry. Do this again after reinstalling with a different mode or binary path. Non-interactive runs (`codex exec`) can pass `--dangerously-bypass-hook-trust` instead. Until the hook is trusted, the built-in shell is *not* blocked, though the MCP server and `AGENTS.md` directive still work. Hooks also require `[features] hooks` to be enabled, which is the default.

Both files honor `CODEX_HOME` (`$CODEX_HOME` when set, otherwise `~/.codex`). They are edited as text, so your existing tables, ordering, and comments are preserved. The `[mcp_servers.lite-sandbox]` table is rewritten in place and the hook lives in a marked managed block, so re-running the install (including to switch modes) is idempotent.

### One config for both Claude Code and Codex

Codex's hook protocol matches Claude Code's: the same `PreToolUse` event, the same JSON payload on stdin (`tool_name`, `tool_input`, `cwd`, …), and the same `permissionDecision: "deny"` response. Both agents use **the same `hook` binary and the same config file** (`paths`, extra commands, git settings; see [Configuration](configuration.md)), so a change like `lite-sandbox config paths allow … --write` applies to both.

To also confine **reads and writes** to the sandbox's paths, add `--with-tool-hook` as with Claude Code:

```bash
lite-sandbox install codex --with-tool-hook
```

This widens the hook matcher to cover Codex's file tools. The two agents reach the filesystem differently:

- **Reads**: Codex has no `Read` tool; it reads by running `cat`, `sed`, `rg`, and so on. Those go through the sandboxed shell, which enforces the readable paths at runtime. Claude Code's `Read`/`Glob`/`Grep` are checked by the hook directly.
- **Writes**: Codex edits files with its native `apply_patch` tool. The hook parses the patch envelope (`*** Add/Update/Delete File:`, `*** Move to:`) and denies the call if any target is outside the writable paths. Claude Code's `Write`/`Edit`/`NotebookEdit` are checked directly.

`--bash-ast-hook-mode` also works with `install codex`: the built-in shell is AST-validated in place instead of redirected, and no MCP server is configured.

> **Coverage caveat.** Codex hooks are on by default; if you've set `[features] hooks = false` in `config.toml`, the hook won't run until you re-enable it. OpenAI's docs say `PreToolUse` fires for the shell, `apply_patch`, and MCP tools, but hook coverage has known gaps (e.g. some newer exec paths), so treat the hook as a guardrail, not an absolute boundary. Commands run through `mcp__lite-sandbox__bash` are validated and path-checked at execution time regardless of hook coverage, which makes the MCP tool the strongest layer. For extra protection on writes, you can also set Codex's native `sandbox_mode` / `writable_roots`.

### Manual Codex setup

Add the MCP server and hook to `~/.codex/config.toml` (replace the path with your built binary):

```toml
[mcp_servers.lite-sandbox]
command = "/path/to/lite-sandbox"
args = ["serve-mcp"]
default_tools_approval_mode = "approve"
omit_tools_from = ["deferred"]  # keep the tools out of tool-search deferral

[[hooks.PreToolUse]]
matcher = "Bash|Read|Edit|Write|NotebookEdit|Glob|Grep|apply_patch"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/path/to/lite-sandbox hook"
```

Use `matcher = "Bash"` to govern only the shell, or `command = "/path/to/lite-sandbox hook --validate-bash"` to AST-validate the shell in place instead of redirecting it. Then add a directive to `~/.codex/AGENTS.md` (global) or a project-level `AGENTS.md`:

```markdown
Prefer the `bash` tool from the `lite-sandbox` MCP server for running shell commands. It runs commands through lite-sandbox's AST validation and filesystem path boundaries, which the built-in shell bypasses. Use it instead of the built-in shell whenever possible.
```

Restart Codex after making these changes.

## opencode

To configure [opencode](https://opencode.ai), run the install (autodetected, or named explicitly):

```bash
lite-sandbox install opencode
```

opencode v1 and v2 are configured differently enough to be treated as two agents that share a binary name, so the install writes the setup that matches the installed one:

- If `opencode --version` reports v2, the install writes [v2's setup](#opencode-v2). If it reports v1, it writes [v1's](#opencode-v1).
- With no `opencode` on `PATH`, the existing config decides. A config that already uses v2's `permissions` array or `mcp.servers` gets v2's setup. Anything else gets v1's, which v2 also reads (normalizing it in memory).

Both edit opencode's **global** config and add a usage directive to its `AGENTS.md`. All other keys are preserved, and re-running is idempotent. `opencode.json` (plain JSON) and `opencode.jsonc` (JSONC, with comments and trailing commas) are both edited in place, and comments and formatting in a `.jsonc` file are preserved. If both exist, `opencode.json` is edited; if neither exists, a new `opencode.json` is created.

opencode has **no PreToolUse hook protocol** (its plugins are JavaScript), so the hook-based modes don't apply: `--with-tool-hook` does nothing for opencode (use opencode's own `edit` / `external_directory` permission rules to confine its file tools), and `--bash-ast-hook-mode` skips it. Reads and writes made *through the sandboxed shell* are still confined at runtime.

The directive, for `~/.config/opencode/AGENTS.md` (global) or a project-level `AGENTS.md` when configuring by hand:

```markdown
ALWAYS use the `bash` tool from the `lite-sandbox` MCP server for running shell commands (in Code Mode, call `tools["lite-sandbox"].bash({ command })` from `execute`). The built-in shell tool is denied by the permission config and will not run. The sandboxed tool runs commands through lite-sandbox's AST validation and filesystem path boundaries.
```

Restart opencode after the install or a manual change.

### opencode v1

The install edits `~/.config/opencode` (honoring `$XDG_CONFIG_HOME`):

1. Registers the MCP server under `mcp.lite-sandbox` in `opencode.json` (or `opencode.jsonc`)
2. Sets `permission.bash` to `"deny"` so the built-in bash tool is blocked (replacing any existing granular `bash` rule), and sets `permission."lite-sandbox*"` to `"allow"` so the sandbox's tools (`lite-sandbox_bash`, `lite-sandbox_list_shells`, ...) never prompt
3. Adds the usage directive to `AGENTS.md`

The model calls `lite-sandbox_bash` directly. To configure it by hand, add this to `~/.config/opencode/opencode.json` (replace the path with your built binary), then add the directive above:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "lite-sandbox": {
      "type": "local",
      "command": ["/path/to/lite-sandbox", "serve-mcp"],
      "enabled": true
    }
  },
  "permission": {
    "bash": "deny",
    "lite-sandbox*": "allow"
  }
}
```

### opencode v2

The install edits `~/.config/opencode` (honoring `$XDG_CONFIG_HOME`), or `$OPENCODE_CONFIG_DIR` when set, which v2 reads in its place:

1. Registers the MCP server under `mcp.servers.lite-sandbox` in `opencode.json` (or `opencode.jsonc`)
2. Appends two rules to the end of `permissions`: `{"action": "shell", "resource": "*", "effect": "deny"}` blocks the built-in shell tool (v1's `bash`) and removes it from the model's tools, and `{"action": "lite-sandbox_*", "resource": "*", "effect": "allow"}` auto-allows the sandbox's tools
3. Adds the usage directive to `AGENTS.md`

What differs from v1, and why the setup accounts for it:

- **Rule order.** v2 applies the *last* matching permission rule, so the install appends its rules after yours and moves them back to the end on every re-run; your own rules are kept. v2 applies global rules after its built-in agents' rules, so the deny also covers the explore subagent, which allows the shell itself. A rule in a project config, or in an agent's own `permissions`, is applied after the global rules and can still re-allow the shell.
- **Code Mode.** v2 reaches MCP tools through [Code Mode](https://opencode.ai/v2/docs/mcp-servers/) by default: the model calls `tools["lite-sandbox"].bash({ command })` from a short program it passes to the `execute` tool. The install leaves that on (and keeps a `codemode` setting you add to the server entry). Code Mode is an interpreter with no filesystem, network, or process access of its own. It can only call the tools opencode offers, so commands still run only through the sandbox.
- **Background MCP startup.** v2 connects MCP servers in the background, so in a fresh session the sandbox's tools can be missing from the first turn and appear from the next one.
- **External directories.** v2 allows `external_directory` by default; add an `ask` rule for it to restore v1's prompting.
- **Upgrading.** Re-running the install after upgrading from v1 replaces the v1 entries it wrote in the same file with their v2 equivalents.

To configure it by hand, add this to `opencode.json` (replace the path with your built binary), keeping the two rules at the end of `permissions`, then add the directive above:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "lite-sandbox": {
        "type": "local",
        "command": ["/path/to/lite-sandbox", "serve-mcp"]
      }
    }
  },
  "permissions": [
    {"action": "shell", "resource": "*", "effect": "deny"},
    {"action": "lite-sandbox_*", "resource": "*", "effect": "allow"}
  ]
}
```

## Crush

To configure [Crush](https://github.com/charmbracelet/crush), run the install (autodetected, or named explicitly):

```bash
lite-sandbox install crush
```

This edits Crush's **global** config in `~/.config/crush` (honoring `$XDG_CONFIG_HOME` and `$CRUSH_GLOBAL_CONFIG`):

1. Registers the MCP server as `lite-sandbox` (stdio, `lite-sandbox serve-mcp`). Crush names MCP tools `mcp_<server>_<tool>`, so the sandbox shell appears as `mcp_lite-sandbox_bash`.
2. Removes the built-in `bash` tool from the model's tool list with `permissions deny bash` (Crush's `options.disabled_tools`), and auto-allows the sandbox's tools (`mcp_lite-sandbox_bash`, `mcp_lite-sandbox_kill_shell`, `mcp_lite-sandbox_list_shells`) with `permissions allow` (`permissions.allowed_tools`) so they never prompt
3. Adds a usage directive to `CRUSH.md`, the global context file Crush loads into every session

Crush reads and merges two global config files: `crushrc` (Crush's current Bash-based format, introduced in v0.88.0) takes precedence over the deprecated `crush.json`. The installer edits whichever exists, `crushrc` if both do. If neither exists it creates a `crushrc`, or a `crush.json` if `crush --version` reports a release older than v0.88.0. In a `crushrc`, the settings go in a marked managed block at the end of the file, so `mcp add` overrides any earlier definition of the same server. In `crush.json`, the `mcp.lite-sandbox`, `options.disabled_tools`, and `permissions.allowed_tools` entries are edited in place. All other content is preserved and re-running is idempotent.

Crush's [hooks](https://github.com/charmbracelet/crush/tree/main/docs/hooks) use Claude Code's protocol, but its built-in tools have different names (`bash`, `view`, `edit`, …) from the ones `lite-sandbox hook` governs, so the hook-based modes don't apply: `--with-tool-hook` does nothing for Crush and `--bash-ast-hook-mode` skips it. Removing the built-in `bash` tool is a stronger block than a hook anyway, since the model never sees it. Reads and writes made *through the sandboxed shell* are confined at runtime.

### Manual Crush setup

Add this to `~/.config/crush/crushrc` (replace the path with your built binary):

```bash
mcp add lite-sandbox --type stdio --command /path/to/lite-sandbox --args serve-mcp
permissions deny bash
permissions allow mcp_lite-sandbox_bash mcp_lite-sandbox_kill_shell mcp_lite-sandbox_list_shells
```

Or, for the legacy JSON config (`~/.config/crush/crush.json`, required on Crush releases before v0.88.0):

```json
{
  "$schema": "https://charm.land/crush.json",
  "mcp": {
    "lite-sandbox": {
      "type": "stdio",
      "command": "/path/to/lite-sandbox",
      "args": ["serve-mcp"]
    }
  },
  "options": {
    "disabled_tools": ["bash"]
  },
  "permissions": {
    "allowed_tools": [
      "mcp_lite-sandbox_bash",
      "mcp_lite-sandbox_kill_shell",
      "mcp_lite-sandbox_list_shells"
    ]
  }
}
```

Then add a directive to `~/.config/crush/CRUSH.md` (global) or a project-level `CRUSH.md`:

```markdown
ALWAYS use the `mcp_lite-sandbox_bash` tool for running shell commands. The built-in `bash` tool is disabled and not available. The sandboxed tool is pre-approved and requires no permission prompts; it runs commands through lite-sandbox's AST validation and filesystem path boundaries.
```

Restart Crush after making these changes.

## Grok Build

To configure [Grok Build](https://x.ai/cli) (xAI's `grok` CLI), run the install (autodetected, or named explicitly):

```bash
lite-sandbox install grok
```

This edits Grok's **user** config in `~/.grok` (honoring `$GROK_HOME`):

1. Registers the MCP server under `[mcp_servers.lite-sandbox]` in `config.toml`. Grok names MCP tools `<server>__<tool>` and doesn't list them to the model directly: the model calls `use_tool` with `tool_name` `lite-sandbox__bash`.
2. Adds two `[[permission.rules]]` to `config.toml`: one allows the sandbox's tools (`tool = "mcp"`, `pattern = "lite-sandbox__*"`), and one denies the built-in shell (`tool = "bash"`). The allow rule is required: a hook's `allow` doesn't skip Grok's approval prompt, and headless `grok -p` stops at a prompt it can't answer. The rules live in a marked managed block. If your `[permission]` section already defines `rules = [...]` inline, which `[[permission.rules]]` tables can't extend, the installer leaves the file alone and prints the rules for you to add by hand.
3. Writes a `PreToolUse` hook to `hooks/lite-sandbox.json`. Hooks in `~/.grok/hooks` are always trusted, unlike project hooks. The hook redirects the built-in shell tools (`run_terminal_command`, `monitor`) to `lite-sandbox__bash`. It also confines Grok's file tools to the sandbox's paths: `read_file`, `grep`, and `list_dir` to the readable paths, `search_replace` and `write` to the writable paths. The same goes for the variants other toolsets use (`hashline_*`, `apply_patch`, and the opencode-style `read`/`edit`/`glob`) and for local image paths passed to `image_edit`, `image_to_video`, and `reference_to_video`, which Grok reads and uploads. Unlike Claude Code, **this is always on** (`--with-tool-hook` is implied). Grok treats `read_file`, `grep`, and `list_dir` as read-only and runs them anywhere on disk without a prompt, so the hook is the only thing confining them.
4. Writes a usage directive to `rules/lite-sandbox.md`. Grok loads it in every project, whatever the folder trust.

Re-running the install (including to switch modes) is idempotent. The MCP table is rewritten in place, the permission block is replaced, and the hook and rules files are owned outright. `--bash-ast-hook-mode` works too: the hook AST-checks `run_terminal_command` in place instead of redirecting it, the shell deny rule is dropped, and no MCP server or directive is configured. The file tools stay confined.

Things to know about Grok's hook runner:

- **It fails open.** A hook that crashes or times out doesn't block the call. The installer sets a 30-second timeout (Grok's default is 5) and adds the shell deny rule as a backstop that holds even when the hook doesn't answer.
- **It truncates large inputs.** A tool input over 128 KiB reaches the hook as a clipped string with no usable path or command. For the tools it governs, the hook denies such a call instead of deferring (except in `open` mode) and tells the model to split it, e.g. a large `write` into a smaller write plus edits. Arguments that don't decode (a path that isn't a string) are denied the same way, since Grok's own parsing may still accept them. Every path spelling a call sets is checked, and keys are matched case-sensitively, as Grok matches them.
- **It clips deny reasons to 256 characters** before the model sees them, so lite-sandbox sends Grok shorter denials than Claude Code gets, with the verdict and the fix first. The audit log keeps the full reason.
- **It also loads Claude Code's config** by default: hooks and permissions from `~/.claude/settings.json`, MCP servers from `~/.claude.json`, and `~/.claude/CLAUDE.md`. A Claude Code install of lite-sandbox therefore also applies to Grok. The hook understands Grok's tool names whichever file registered it. If the two agents were installed in different modes, both hooks run and the first denial wins, and a default Claude Code install's `Bash` deny rule blocks Grok's shell too, even under `install grok --bash-ast-hook-mode`. Set `[compat.claude] hooks = false` (or `mcps`, `agents`) in `~/.grok/config.toml` to stop Grok reading them.

Grok's own sandbox mode (`grok --sandbox workspace|read-only|strict`, Landlock on Linux and Seatbelt on macOS) is a separate, optional layer. It applies to the Grok process and everything it spawns, including `lite-sandbox serve-mcp` and the hook. The installer doesn't turn it on.

### Manual Grok Build setup

Add this to `~/.grok/config.toml` (replace the path with your built binary):

```toml
[mcp_servers.lite-sandbox]
command = "/path/to/lite-sandbox"
args = ["serve-mcp"]

[[permission.rules]]
action = "allow"
tool = "mcp"
pattern = "lite-sandbox__*"

[[permission.rules]]
action = "deny"
tool = "bash"
```

Then create `~/.grok/hooks/lite-sandbox.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "run_terminal_command|run_terminal_cmd|bash|monitor|read_file|hashline_read|read|grep|hashline_grep|grep_files|list_dir|glob|search_replace|hashline_edit|edit|write|image_edit|image_to_video|reference_to_video|apply_patch",
        "hooks": [
          {"type": "command", "command": "/path/to/lite-sandbox hook", "timeout": 30}
        ]
      }
    ]
  }
}
```

A plain `|`-list matcher is an exact match on each name in Grok, not a regex. Finally, add a directive to `~/.grok/rules/lite-sandbox.md`:

```markdown
For every shell command, run it with the `lite-sandbox__bash` MCP tool: call `use_tool` with `tool_name` "lite-sandbox__bash" and `tool_input` {"command": "<the command>"}. The built-in shell tools are blocked and will not run.
```

Restart Grok after making these changes; `/hooks` lists the loaded hook.

## pi

To configure [pi](https://pi.dev) (`@earendil-works/pi-coding-agent`, 1.0 or later), run the install (autodetected, or named explicitly):

```bash
lite-sandbox install pi
```

pi has no hook protocol or permission prompts of its own; it is extended with TypeScript [extensions](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/extensions.md) that run inside the pi process. So the installer writes one, in pi's **agent directory** (`~/.pi/agent`, or `$PI_CODING_AGENT_DIR`):

1. `extensions/lite-sandbox.ts`, which pi loads in every session. It:
   - registers the MCP server (`lite-sandbox serve-mcp --config-requests`) with `exposure: "direct"`, so its tools are declared to the model like built-in ones (pi's default for MCP servers, `codemode`, would hide them behind scripts). pi names MCP tools `mcp__<server>__<tool>` with `-` replaced by `_`, so the sandbox shell is `mcp__lite_sandbox__bash`. The server runs for the whole session, like with the other agents.
   - forwards each call of pi's built-in `bash`, `powershell`, `read`, `write`, `edit`, `grep`, `find`, and `ls` tools, and of `mcp__lite_sandbox__bash`, to `lite-sandbox hook --config-requests` from pi's `tool_call` event. The hook redirects `bash` and `powershell` to the sandbox tool, confines `read`/`grep`/`find`/`ls` to the readable paths and `write`/`edit` to the writable paths (and denies writes into `.git`, `.pi`, and `.claude` directories), and answers `ask` for a [config request](configuration.md#config-requests-the-agent-runs-lite-sandbox-config-with-your-approval) or a [command that asks first](configuration.md#commands-that-ask-first). A denial blocks the call with the hook's reason. An `ask` opens a confirmation dialog, and the call runs only if you approve; in print (`-p`) and JSON mode, which have no UI, it is blocked. Unlike the other agents' hooks, **the extension fails closed**: if the hook can't be run, exits with an error, prints an unreadable answer, or takes more than 30 seconds, the call is blocked.
   - adds a usage directive to the system prompt as a section of its own.
2. `"-bash"` in `defaultTools` in `settings.json`, so the model isn't offered pi's built-in shell. Any other `bash` entry is removed first; an empty `defaultTools` (all built-in tools off) is left alone. If the extension fails to load, pi then has no shell at all rather than an unsandboxed one. Its file tools, though, run unconfined in such a session, so treat an extension load error that pi reports at startup as the sandbox being off.

Like for Grok Build, the file tools are **always** confined (`--with-tool-hook` is implied): pi never asks before a tool call, so the hook is the only thing keeping `read` and `write` inside the project. `--bash-ast-hook-mode` works too: the extension registers no MCP server and adds no directive, the built-in `bash` stays enabled (a `"-bash"` an earlier install added is removed), and the hook AST-checks each command (`lite-sandbox hook --validate-bash`). `powershell` is always redirected, since the check parses bash. Outside `allowlist` mode a command that passes the check isn't on a full whitelist, and pi's `bash` runs it unsandboxed, so the extension asks you before running it (where Claude Code would show its own permission prompt). The installer refuses a pi on `PATH` older than 1.0, the first release with built-in MCP support, and warns when `settings.json` disables it (`"-builtin:mcp"` in `extensions`).

Re-running the install (including to switch modes) is idempotent: the extension file is owned outright and rewritten, and only the `bash` entries of `defaultTools` are touched. Restart pi, or run `/reload`, for the changes to take effect; `/mcp` lists the lite-sandbox server.

Things to know:

- **Extensions are trusted code.** The hook's checks hold only while the lite-sandbox extension runs. pi runs `tool_call` handlers in load order, and a later extension's handler can still change a call's arguments after lite-sandbox approved them. The `--no-extensions`, `--no-mcp`, `--tools`, and `-e` flags change what loads for one run.
- **Project `.pi` directories are read-only to the sandbox.** pi loads a project's `.pi/settings.json`, `.pi/extensions`, and `.pi/mcp.json` into its own process once you trust the project, so neither sandboxed commands nor pi's `write`/`edit` tools may write there (see [Security](security.md)). Make such changes yourself.
- **`!` commands you type run unsandboxed.** pi's `user_bash` event (`!cmd` and `!!cmd`) is left alone: the commands are yours, not the model's.

### Manual pi setup

The extension is generated from [`cmd/pi_extension.ts`](../cmd/pi_extension.ts) with the binary path and mode filled in, so the simplest manual setup is to run the installer with `PI_CODING_AGENT_DIR` pointing at a scratch directory and copy `extensions/lite-sandbox.ts` from there. Then add `"-bash"` to `defaultTools` in `~/.pi/agent/settings.json`:

```json
{
  "defaultTools": ["-bash"]
}
```

Restart pi after making these changes.

## Manual Claude Code setup

### 1. Add the MCP server

Add this to `.mcp.json` in your project root (project-scoped) or to `~/.claude.json` under the `mcpServers` key (user-scoped):

```json
{
  "mcpServers": {
    "lite-sandbox": {
      "command": "/path/to/lite-sandbox",
      "args": ["serve-mcp"]
    }
  }
}
```

Replace `/path/to/lite-sandbox` with the path to the built binary.

### 2. Auto-allow the sandbox tool and deny built-in Bash

Add this to `~/.claude/settings.json` so Claude Code never prompts for the sandboxed tools and can't use the built-in `Bash` tool:

```json
{
  "permissions": {
    "allow": [
      "mcp__lite-sandbox__bash",
      "mcp__lite-sandbox__kill_shell",
      "mcp__lite-sandbox__list_shells"
    ],
    "deny": [
      "Bash"
    ]
  }
}
```

The `kill_shell` and `list_shells` entries cover the background-process
tools, so checking on and stopping background commands don't prompt either.

Without the `Bash` deny, Claude could fall back to the unvalidated built-in shell whenever the sandbox rejected a command.

Subagents and skills don't inherit these `allow` entries ([anthropics/claude-code#18950](https://github.com/anthropics/claude-code/issues/18950)), so also register a `PreToolUse` hook that allows the sandbox tools there:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "mcp__lite-sandbox__.*",
        "hooks": [
          {"type": "command", "command": "/path/to/lite-sandbox hook"}
        ]
      }
    ]
  }
}
```

### 3. Direct Claude to use the sandboxed tool

Add this to `~/.claude/CLAUDE.md` (global) or a project-level `CLAUDE.md`:

```markdown
ALWAYS use the mcp__lite-sandbox__bash tool for running shell commands. The built-in Bash tool is denied and will not run. The sandboxed tool is pre-approved and requires no permission prompts.
```

> **Note**: Tool names follow the pattern `mcp__<server-name>__<tool-name>`. If you gave the server a different name in your MCP config, adjust the tool name to match.

## Built-in tool boundaries

The bash tool confines shell commands to the sandbox's readable and writable paths, but Claude Code's **built-in tools** bypass the sandbox. (This section is about Claude Code. Codex, Grok Build, and pi get the same hook; see [OpenAI Codex CLI](#openai-codex-cli), [Grok Build](#grok-build), and [pi](#pi) for their tool names.) The built-in `Bash` tool runs unvalidated shell, and `Read`/`Write`/`Edit`/`NotebookEdit` (plus the `Grep`/`Glob` path argument) can read and write anywhere, so an agent could read `~/.ssh/id_rsa` or write outside the project through them. The optional tool hook closes that gap.

Enable it at install time:

```bash
lite-sandbox install --with-tool-hook
```

This registers a `PreToolUse` hook (`lite-sandbox hook`) in `~/.claude/settings.json`. On each matching tool call it:

- **redirects `Bash` and `Monitor`**: the built-in shell tools are denied with a message telling the model to use `mcp__lite-sandbox__bash` instead (with `run_in_background` for a `Monitor` watch). A `Monitor` call that watches a WebSocket instead of running a command runs no shell, so it defers to Claude Code's own prompt;
- **denies reads** (`Read`, and `Grep`/`Glob` with an explicit `path`) outside the readable paths;
- **denies writes** (`Write`, `Edit`, `NotebookEdit`) outside the writable paths;
- **allows the sandbox's own tools** (`mcp__lite-sandbox__*`), so they stay prompt-free in subagents and skills, which don't inherit `permissions.allow` ([anthropics/claude-code#18950](https://github.com/anthropics/claude-code/issues/18950));
- **defers** everything in bounds to Claude Code's normal permission flow;
- **defers `.claude`** paths (the project's or `~/.claude`, reads and writes alike, except `.claude/worktrees`) to Claude Code's normal permission flow too, inside the boundary or not. Only the resolved path counts, so a symlink named `.claude` pointing elsewhere is checked like any other path, and the deny-listed files under it (`~/.claude/.credentials.json`) and writes into a `.git` keep their denial. Claude Code treats `.claude` as a [protected path](https://code.claude.com/docs/en/permission-modes) and prompts before writing it, so you decide on each change to the agent's own settings, skills, and instructions. The sandboxed bash tool can only read `.claude`.

The path boundaries are computed the same way as the bash tool's (see `cmd/serve.go`): the working directory, plus any paths granted in the config's `paths` list, plus the worktree parent when `git.allow_worktree_parent` is set. Writable paths are also readable. A denial tells the model the path is out of bounds and that the user can widen the boundary with `lite-sandbox config paths allow <path>` (`--write` for writes).

### Bash: hook vs. permission deny

`PreToolUse` hooks run *after* `permissions.deny`, and a matching deny rule blocks a call whatever the hook returns, so a `deny` rule and the hook can't both handle `Bash` (nor `Monitor`, which Claude Code checks against the same `Bash` rules). The two install modes handle it differently:

- **`lite-sandbox install`** (default) hard-denies `Bash` with a `permissions.deny` rule. This is the strongest option, but the model only sees a terse rejection; the [`CLAUDE.md` directive](#claude-code) is what points it to the MCP tool.
- **`lite-sandbox install --with-tool-hook`** leaves `Bash` out of `deny` (removing it if a previous install added it) and lets the hook block it with the redirect message. If the hook fails to run, `Bash` falls back to a normal permission prompt instead of running silently.

The hook is **fail-open**: on an internal error (unparseable event, missing working directory) it defers instead of blocking. It reads the config on every call, so boundary changes apply without reinstalling. To remove it, delete the `PreToolUse` entry for `lite-sandbox hook` from `settings.json`.

### AST-check mode (`--bash-ast-hook-mode`)

`--bash-ast-hook-mode` registers the hook as `lite-sandbox hook --validate-bash`, which **statically AST-checks** built-in `Bash` and `Monitor` commands instead of redirecting them. On each such call it parses the command and runs the sandbox's whitelist and path checks, then:

- **allows** the call, skipping the permission prompt, when it passes, so Claude keeps using its own `Bash` tool behind the static check;
- **denies** it with the validation error when it fails, so the model can fix the command.

This mode configures no MCP server, adds no `Bash` deny, and writes no `CLAUDE.md` directive. On its own it matches only `Bash` and `Monitor`; with `--with-tool-hook` it uses the full matcher, so both are AST-checked and `Read`/`Write`/`Edit` are confined to the sandbox's paths. Switching install modes is idempotent: a later `install`, `--with-tool-hook`, or `--bash-ast-hook-mode` replaces the previous lite-sandbox hook entry.

> **Trade-off: `Bash` runs unsandboxed.** The hook checks the command statically, then the real `Bash` tool runs it unsandboxed. Without runtime enforcement, it misses what the MCP tool's interpreter catches during execution: the `OpenHandler` and expansion checks (e.g. `cat $VAR`), and reads of paths that don't exist at validation time. The AST whitelist (no `curl`/`nc`/`eval`/shell escapes/etc.) and static checks on literal path arguments still apply in full. For the strongest enforcement, use the default or `--with-tool-hook` modes, which run commands through the sandbox.
