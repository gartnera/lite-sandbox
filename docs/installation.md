# Installing & Configuring

## Getting the binary

Every merge to `main` publishes a [GitHub release](https://github.com/gartnera/lite-sandbox/releases) with prebuilt binaries for Linux and macOS on amd64 and arm64, as `lite-sandbox_<version>_<os>_<arch>.tar.gz` archives plus a `checksums.txt`. Download the archive for your platform and put the `lite-sandbox` binary on your `PATH`, or build from source:

```bash
go install github.com/gartnera/lite-sandbox@latest   # latest release, into $GOPATH/bin
lite-sandbox version                                 # "lite-sandbox v0.4.0"; a release binary adds the commit and date
```

### Verifying a download

Releases are immutable, and each asset has a signed [build provenance attestation](https://docs.github.com/en/actions/concepts/security/artifact-attestations) showing it was built from this repository by the release workflow. To verify an archive:

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

With no arguments, `install` detects which supported agent CLIs are installed ([Claude Code](#claude-code), [OpenAI Codex CLI](#openai-codex-cli), [opencode](#opencode), and [Crush](#crush)) and configures each one. A CLI counts as installed when its binary is on `PATH` (`claude`, `codex`, `opencode`, `crush`) or its config directory exists (`~/.claude`/`$CLAUDE_CONFIG_DIR`, `~/.codex`/`$CODEX_HOME`, `~/.config/opencode`/`$XDG_CONFIG_HOME/opencode`, `~/.config/crush`/`$XDG_CONFIG_HOME/crush`/`$CRUSH_GLOBAL_CONFIG`). Name agents to configure only those:

```bash
lite-sandbox install                  # autodetect claude / codex / opencode / crush
lite-sandbox install codex            # configure only Codex
lite-sandbox install claude opencode  # configure exactly these
```

`install` also sets up lite-sandbox's own config (`lite-sandbox config path`). A **first-time** config is created with only `audit: true`, so the mode is the `allowlist` default and validation findings are logged for `lite-sandbox audit report`. An **existing** config is left alone. To start in a looser mode, pass `--mode denylist` (or `open`). `denylist` also enables the OS sandbox if `os_sandbox` was never set and bubblewrap (Linux) or sandbox-exec (macOS) passes a preflight check. See [Incremental adoption](adoption.md).

The `--with-tool-hook` and `--bash-ast-hook-mode` flags described below apply to `claude` and `codex`, which share lite-sandbox's PreToolUse hook protocol. opencode has no compatible hook protocol, and lite-sandbox's hook doesn't govern Crush's built-in tools, so `--with-tool-hook` does nothing for those two and `--bash-ast-hook-mode` skips them.

## Temporary setup: `lite-sandbox launch`

`launch` starts an agent CLI with the sandbox wired up, without writing to the agent's configuration. Everything `install` would write to the agent's config files is passed on the agent's command line instead, so the sandbox applies to that session only.

**Only Claude Code is supported for now**, since its CLI accepts an MCP server, settings, and a system-prompt addition per run:

```bash
lite-sandbox launch claude                     # interactive session, sandboxed
lite-sandbox launch claude -p "run the tests"  # arguments after the agent are passed through
lite-sandbox launch --dry-run claude           # print the command instead of running it
```

Everything after the agent name is passed to the agent unchanged, so lite-sandbox's own flags go before it (or are separated with `--`).

### What it passes

| What `install claude` writes | What `launch claude` passes |
| --- | --- |
| MCP server in `~/.claude.json` | `--mcp-config` |
| Permissions + `PreToolUse` hook in `~/.claude/settings.json` | `--settings` |
| Usage directive in `~/.claude/CLAUDE.md` | `--append-system-prompt` |

**These are added on top of your own configuration.** Your `settings.json` permission rules still apply (the allow/deny lists are merged), your own MCP servers still load (`--strict-mcp-config` is not passed), your `CLAUDE.md` still reaches the model, and your sign-in state is untouched.

### Defaults

Because it configures one session rather than every project, `launch` is stricter than `install` by default:

- **The built-in `Bash` tool is denied**, as in the default install, so the model isn't offered it.
- **`--with-tool-hook` is on**, so the `PreToolUse` hook confines the built-in `Read`/`Glob`/`Grep` to the sandbox's readable paths and `Write`/`Edit`/`NotebookEdit` to its writable paths. This is stricter than `install --with-tool-hook`, which moves the `Bash` block into the hook so the redirect message reaches the model; `launch` keeps the permission deny and adds the file-tool boundary. Pass `--with-tool-hook=false` to get install's default behavior.
- **`--permission-mode acceptEdits`**, written as `permissions.defaultMode`, so edits apply without a prompt. The hook keeps them inside the boundary, and a write outside it is still denied. Pass `--permission-mode ""` to keep Claude Code's own default, or pass your own `--permission-mode` *after* the agent name, which overrides the setting.

`--bash-ast-hook-mode` and `--always-load` behave as they do for `install` (see below).

`launch` reads lite-sandbox's own config (`lite-sandbox config path`) as usual but, unlike `install`, never creates or modifies it. A host without one runs at the `allowlist` default. Use `lite-sandbox config ...` to change it, and `install` for a persistent agent setup.

## Claude Code

For Claude Code, `lite-sandbox install` (or `lite-sandbox install claude`):
1. Adds the MCP server to `~/.claude.json` (user-scoped) with `"alwaysLoad": true` (see [`--always-load`](#always-load) below)
2. Adds allow rules for the lite-sandbox MCP tools (`bash`, `bash_output`, `kill_shell`, `list_shells`) **and denies the built-in `Bash` tool** in `~/.claude/settings.json`
3. Registers a `PreToolUse` hook matching `mcp__lite-sandbox__.*` that allows those tools. Subagents and skills don't inherit `permissions.allow` from `settings.json` ([anthropics/claude-code#18950](https://github.com/anthropics/claude-code/issues/18950)), but hooks still fire there, so this keeps the sandbox tools prompt-free inside them. It grants nothing the allow rules don't: the tools validate every command themselves, and a `permissions.deny` rule still overrides a hook allow.
4. Adds a usage directive to `~/.claude/CLAUDE.md`

All of these honor `CLAUDE_CONFIG_DIR` the way Claude Code does: when it is set, `settings.json`, `CLAUDE.md`, and `.claude.json` are all written under that directory (Claude Code then keeps its user config at `$CLAUDE_CONFIG_DIR/.claude.json` instead of `~/.claude.json`).

Denying the built-in `Bash` tool leaves Claude Code no unvalidated shell, so every command goes through AST validation and, if enabled, the OS sandbox.

To extend the sandbox to Claude Code's **built-in tools**, add `--with-tool-hook`:

```bash
lite-sandbox install --with-tool-hook
```

This widens the `PreToolUse` hook matcher. Besides allowing the `mcp__lite-sandbox__*` tools, the hook then (1) blocks the built-in `Bash` tool with a message redirecting the model to `mcp__lite-sandbox__bash`, and (2) denies `Read` outside the sandbox's readable paths and `Write`/`Edit`/`NotebookEdit` outside its writable paths (see [Built-in tool boundaries](#built-in-tool-boundaries)). It is off by default. When on, the hook blocks `Bash` instead of the permission `deny` rule, so the redirect message reaches the model.

To keep using Claude Code's own `Bash` tool with a static check in front of it, add `--bash-ast-hook-mode`:

```bash
lite-sandbox install --bash-ast-hook-mode                  # AST-check Bash only
lite-sandbox install --with-tool-hook --bash-ast-hook-mode # AST-check Bash + confine Read/Write/Edit
```

In this mode the hook parses each `Bash` command and checks it against the same whitelist and path boundaries as the bash tool. It allows the command without a permission prompt if it passes and denies it with the validation error if it doesn't. **`Bash` itself still runs unsandboxed.** There is no runtime enforcement, only the static check, so this is weaker than running commands through the MCP tool (see [Built-in tool boundaries](#built-in-tool-boundaries)). Since nothing is redirected to the MCP tool, this mode **does not configure the MCP server** (no MCP allow, no `CLAUDE.md` directive). On its own it governs only `Bash`; add `--with-tool-hook` to also confine the built-in `Read`/`Write`/`Edit` tools.

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

Codex works the same way. Newer Codex models defer MCP tools behind Codex's `tool_search` by default, so `install codex` sets `omit_tools_from = ["deferred"]` on its server table, which keeps the sandbox tools in the model's initial tool list. `--always-load=false` omits it there too. The flag does nothing for opencode and Crush, or in `--bash-ast-hook-mode` (which doesn't configure the MCP server).

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

This edits opencode's **global** config and rules in `~/.config/opencode` (honoring `$XDG_CONFIG_HOME`):

1. Registers the MCP server under `mcp.lite-sandbox` in `opencode.json` (or `opencode.jsonc`, whichever exists)
2. Sets `permission.bash` to `"deny"` so the built-in bash tool is blocked (replacing any existing granular `bash` rule), and sets `permission."lite-sandbox*"` to `"allow"` so the sandbox's tools (`lite-sandbox_bash`, `lite-sandbox_bash_output`, ...) never prompt
3. Adds a usage directive to `AGENTS.md`

All other keys are preserved, and re-running is idempotent. `opencode.json` (plain JSON) and `opencode.jsonc` (JSONC, with comments and trailing commas) are both edited in place; comments and formatting in a `.jsonc` file are preserved. If both exist, `opencode.json` is edited; if neither exists, a new `opencode.json` is created. To configure it by hand, see below.

opencode has **no PreToolUse hook protocol** (its plugins are JavaScript), so the hook-based modes don't apply: `--with-tool-hook` does nothing for opencode (use opencode's `permission.edit` / `permission.external_directory` rules to confine its file tools), and `--bash-ast-hook-mode` skips it. Reads and writes made *through the sandboxed shell* are still confined at runtime.

### Manual opencode setup

Add this to `~/.config/opencode/opencode.json` (replace the path with your built binary):

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

Then add a directive to `~/.config/opencode/AGENTS.md` (global) or a project-level `AGENTS.md`:

```markdown
ALWAYS use the `bash` tool from the `lite-sandbox` MCP server for running shell commands. The built-in bash tool is denied by the permission config and will not run. The sandboxed tool runs commands through lite-sandbox's AST validation and filesystem path boundaries.
```

Restart opencode after making these changes.

## Crush

To configure [Crush](https://github.com/charmbracelet/crush), run the install (autodetected, or named explicitly):

```bash
lite-sandbox install crush
```

This edits Crush's **global** config in `~/.config/crush` (honoring `$XDG_CONFIG_HOME` and `$CRUSH_GLOBAL_CONFIG`):

1. Registers the MCP server as `lite-sandbox` (stdio, `lite-sandbox serve-mcp`). Crush names MCP tools `mcp_<server>_<tool>`, so the sandbox shell appears as `mcp_lite-sandbox_bash`.
2. Removes the built-in `bash` tool from the model's tool list with `permissions deny bash` (Crush's `options.disabled_tools`), and auto-allows the sandbox's tools (`mcp_lite-sandbox_bash`, `mcp_lite-sandbox_bash_output`, `mcp_lite-sandbox_kill_shell`, `mcp_lite-sandbox_list_shells`) with `permissions allow` (`permissions.allowed_tools`) so they never prompt
3. Adds a usage directive to `CRUSH.md`, the global context file Crush loads into every session

Crush reads and merges two global config files: `crushrc` (Crush's current Bash-based format, introduced in v0.88.0) takes precedence over the deprecated `crush.json`. The installer edits whichever exists, `crushrc` if both do. If neither exists it creates a `crushrc`, or a `crush.json` if `crush --version` reports a release older than v0.88.0. In a `crushrc`, the settings go in a marked managed block at the end of the file, so `mcp add` overrides any earlier definition of the same server. In `crush.json`, the `mcp.lite-sandbox`, `options.disabled_tools`, and `permissions.allowed_tools` entries are edited in place. All other content is preserved and re-running is idempotent.

Crush's [hooks](https://github.com/charmbracelet/crush/tree/main/docs/hooks) use Claude Code's protocol, but its built-in tools have different names (`bash`, `view`, `edit`, …) from the ones `lite-sandbox hook` governs, so the hook-based modes don't apply: `--with-tool-hook` does nothing for Crush and `--bash-ast-hook-mode` skips it. Removing the built-in `bash` tool is a stronger block than a hook anyway, since the model never sees it. Reads and writes made *through the sandboxed shell* are confined at runtime.

### Manual Crush setup

Add this to `~/.config/crush/crushrc` (replace the path with your built binary):

```bash
mcp add lite-sandbox --type stdio --command /path/to/lite-sandbox --args serve-mcp
permissions deny bash
permissions allow mcp_lite-sandbox_bash mcp_lite-sandbox_bash_output mcp_lite-sandbox_kill_shell mcp_lite-sandbox_list_shells
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
      "mcp_lite-sandbox_bash_output",
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
      "mcp__lite-sandbox__bash_output",
      "mcp__lite-sandbox__kill_shell",
      "mcp__lite-sandbox__list_shells"
    ],
    "deny": [
      "Bash"
    ]
  }
}
```

The `bash_output`, `kill_shell`, and `list_shells` entries cover the
background-process tools, so polling and stopping background commands don't
prompt either.

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

The bash tool confines shell commands to the sandbox's readable and writable paths, but Claude Code's **built-in tools** bypass the sandbox. The built-in `Bash` tool runs unvalidated shell, and `Read`/`Write`/`Edit`/`NotebookEdit` (plus the `Grep`/`Glob` path argument) can read and write anywhere, so an agent could read `~/.ssh/id_rsa` or write outside the project through them. The optional tool hook closes that gap.

Enable it at install time:

```bash
lite-sandbox install --with-tool-hook
```

This registers a `PreToolUse` hook (`lite-sandbox hook`) in `~/.claude/settings.json`. On each matching tool call it:

- **redirects `Bash`**: the built-in Bash tool is denied with a message telling the model to use `mcp__lite-sandbox__bash` instead;
- **denies reads** (`Read`, and `Grep`/`Glob` with an explicit `path`) outside the readable paths;
- **denies writes** (`Write`, `Edit`, `NotebookEdit`) outside the writable paths;
- **allows the sandbox's own tools** (`mcp__lite-sandbox__*`), so they stay prompt-free in subagents and skills, which don't inherit `permissions.allow` ([anthropics/claude-code#18950](https://github.com/anthropics/claude-code/issues/18950));
- **defers** everything in bounds to Claude Code's normal permission flow.

The path boundaries are computed the same way as the bash tool's (see `cmd/serve.go`): the working directory, plus any paths granted in the config's `paths` list, plus the worktree parent when `git.allow_worktree_parent` is set. Writable paths are also readable. A denial tells the model the path is out of bounds and that the user can widen the boundary with `lite-sandbox config paths allow <path>` (`--write` for writes).

### Bash: hook vs. permission deny

`PreToolUse` hooks run *after* `permissions.deny`, and a matching deny rule blocks a call whatever the hook returns, so a `deny` rule and the hook can't both handle `Bash`. The two install modes handle it differently:

- **`lite-sandbox install`** (default) hard-denies `Bash` with a `permissions.deny` rule. This is the strongest option, but the model only sees a terse rejection; the [`CLAUDE.md` directive](#claude-code) is what points it to the MCP tool.
- **`lite-sandbox install --with-tool-hook`** leaves `Bash` out of `deny` (removing it if a previous install added it) and lets the hook block it with the redirect message. If the hook fails to run, `Bash` falls back to a normal permission prompt instead of running silently.

The hook is **fail-open**: on an internal error (unparseable event, missing working directory) it defers instead of blocking. It reads the config on every call, so boundary changes apply without reinstalling. To remove it, delete the `PreToolUse` entry for `lite-sandbox hook` from `settings.json`.

### AST-check mode (`--bash-ast-hook-mode`)

`--bash-ast-hook-mode` registers the hook as `lite-sandbox hook --validate-bash`, which **statically AST-checks** built-in `Bash` commands instead of redirecting them. On each `Bash` call it parses the command and runs the sandbox's whitelist and path checks, then:

- **allows** the call, skipping the permission prompt, when it passes, so Claude keeps using its own `Bash` tool behind the static check;
- **denies** it with the validation error when it fails, so the model can fix the command.

This mode configures no MCP server, adds no `Bash` deny, and writes no `CLAUDE.md` directive. On its own it matches only `Bash`; with `--with-tool-hook` it uses the full matcher, so `Bash` is AST-checked and `Read`/`Write`/`Edit` are confined to the sandbox's paths. Switching install modes is idempotent: a later `install`, `--with-tool-hook`, or `--bash-ast-hook-mode` replaces the previous lite-sandbox hook entry.

> **Trade-off: `Bash` runs unsandboxed.** The hook checks the command statically, then the real `Bash` tool runs it unsandboxed. Without runtime enforcement, it misses what the MCP tool's interpreter catches during execution: the `OpenHandler` and expansion checks (e.g. `cat $VAR`), and reads of paths that don't exist at validation time. The AST whitelist (no `curl`/`nc`/`eval`/shell escapes/etc.) and static checks on literal path arguments still apply in full. For the strongest enforcement, use the default or `--with-tool-hook` modes, which run commands through the sandbox.
