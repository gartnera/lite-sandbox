# Installing & Configuring

## Automatic Installation

The easiest way to configure your coding agents is the built-in install command:

```bash
lite-sandbox install
```

With no arguments, `install` **autodetects which supported agent CLIs are installed on the host** — [Claude Code](#claude-code), [OpenAI Codex CLI](#openai-codex-cli), and [opencode](#opencode) — and configures every detected one. A CLI counts as installed when its binary is on `PATH` (`claude`, `codex`, `opencode`) or its config directory exists (`~/.claude`, `~/.codex`/`$CODEX_HOME`, `~/.config/opencode`/`$XDG_CONFIG_HOME/opencode`). To configure an explicit set instead, name the agents:

```bash
lite-sandbox install                  # autodetect claude / codex / opencode
lite-sandbox install codex            # configure only Codex
lite-sandbox install claude opencode  # configure exactly these
```

The `--with-tool-hook` and `--bash-ast-hook-mode` flags described below apply to `claude` and `codex`, which share lite-sandbox's PreToolUse hook protocol; opencode has no compatible hook protocol, so `--with-tool-hook` is a no-op for it and `--bash-ast-hook-mode` skips it.

## Claude Code

For Claude Code, `lite-sandbox install` (or `lite-sandbox install claude`) automatically:
1. Adds the MCP server to `~/.claude.json` (user-scoped)
2. Adds auto-allow permissions for the lite-sandbox MCP tools (`bash`, `bash_output`, `kill_shell`, `list_shells`) **and denies the built-in `Bash` tool** in `~/.claude/settings.json`
3. Adds usage directive to `~/.claude/CLAUDE.md`

Denying the built-in `Bash` tool forces Claude Code through the sandbox: there is no unvalidated shell escape hatch, so every command runs through the AST validation and (optionally) the OS sandbox.

To extend the sandbox to Claude Code's **built-in tools**, add `--with-tool-hook`:

```bash
lite-sandbox install --with-tool-hook
```

This registers a `PreToolUse` hook that (1) blocks the built-in `Bash` tool with a message redirecting the model to `mcp__lite-sandbox__bash`, and (2) denies `Read` outside the sandbox's readable paths and `Write`/`Edit`/`NotebookEdit` outside its writable paths (see [Built-in tool boundaries](#built-in-tool-boundaries)). It is optional and off by default. When used, the hook governs `Bash` instead of the blunt permission `deny` (so the redirect message actually reaches the model).

If you'd rather keep using Claude Code's own `Bash` tool but still put a static gate in front of it, add `--bash-ast-hook-mode`:

```bash
lite-sandbox install --bash-ast-hook-mode                  # AST-check Bash only
lite-sandbox install --with-tool-hook --bash-ast-hook-mode # AST-check Bash + confine Read/Write/Edit
```

`--bash-ast-hook-mode` changes how the hook treats `Bash`: instead of redirecting it to the MCP tool, the hook parses each `Bash` command's AST and checks it against the same whitelist and path boundaries as the bash tool — allowing it when it passes (no permission prompt) and denying it with the validation error when it doesn't. **`Bash` itself still runs unsandboxed** — there is no runtime enforcement, only this up-front static check, so it's a weaker guarantee than routing execution through the MCP tool (see [Built-in tool boundaries](#built-in-tool-boundaries) for the trade-off). Because nothing redirects to the MCP tool, this mode **does not configure the MCP server** (no MCP allow, no `CLAUDE.md` directive). On its own it governs only `Bash`; combine it with `--with-tool-hook` to also confine the built-in `Read`/`Write`/`Edit` tools to the sandbox's paths.

Restart Claude Code after running the install command.

## OpenAI Codex CLI

To configure [OpenAI Codex CLI](https://developers.openai.com/codex), run the install (autodetected, or named explicitly):

```bash
lite-sandbox install codex
```

(The old `--codex` flag still works but is deprecated in favor of the positional name.)

This automatically:
1. Registers the MCP server under `[mcp_servers.lite-sandbox]` in `~/.codex/config.toml`, with `default_tools_approval_mode = "approve"` so Codex auto-approves the sandboxed tools (the mirror of the Claude installer's `mcp__lite-sandbox__*` allow entries — lite-sandbox is itself the boundary, so a per-call Codex prompt is redundant). Only this server's tools are affected. Requires a Codex build new enough to honor the key; older versions ignore it harmlessly and will still prompt.
2. Adds a usage directive to `~/.codex/AGENTS.md` steering Codex to the sandboxed `bash` tool
3. Registers a `PreToolUse` hook (`[[hooks.PreToolUse]]`) that blocks Codex's built-in shell and redirects it to the sandboxed MCP tool

Both paths honor `CODEX_HOME` (they use `$CODEX_HOME` when set, otherwise `~/.codex`). Everything is edited as text — your existing tables, ordering, and comments are preserved. The `[mcp_servers.lite-sandbox]` table is rewritten in place, and the hook lives in a clearly-marked managed block, so re-running (and switching modes) is idempotent.

### One config for both Claude Code and Codex

Codex's hook protocol is the same as Claude Code's — same `PreToolUse` event, the same JSON payload on stdin (`tool_name`, `tool_input`, `cwd`, …), and the same `permissionDecision: "deny"` response. lite-sandbox reuses **the same `hook` binary and the same config file** (`readable_paths`/`writable_paths`, extra commands, git settings — see [Configuration](configuration.md)) for both agents. So one security/sandbox config governs Claude Code and Codex together; a `lite-sandbox config writable-paths add …` change applies to both.

To also confine **reads and writes** to the sandbox's paths (not just the shell), add `--with-tool-hook`, exactly as with Claude Code:

```bash
lite-sandbox install codex --with-tool-hook
```

This widens the hook matcher so it also governs Codex's file tools. Note the two agents reach the filesystem differently:

- **Reads** — Codex has no `Read` tool; it reads by shelling out (`cat`, `sed`, `rg`). Those reads are governed because the shell is routed through the sandbox (which enforces the readable paths at runtime). Claude Code's `Read`/`Glob`/`Grep` are governed directly.
- **Writes** — Codex edits via its native `apply_patch` tool. The hook parses the patch envelope (`*** Add/Update/Delete File:`, `*** Move to:`) and denies the call if any target resolves outside the writable paths. Claude Code's `Write`/`Edit`/`NotebookEdit` are governed directly.

`--bash-ast-hook-mode` also composes with `install codex` (AST-validate the built-in shell in place instead of redirecting it; no MCP server), just like the Claude install.

> **Coverage caveat.** Codex hooks are enabled by default; if you have set `[features] hooks = false` in `config.toml`, re-enable it or the hook will not run. OpenAI's docs state `PreToolUse` fires for the shell, `apply_patch`, and MCP tools, but hook coverage has known gaps (e.g. some newer exec paths), so treat the hook as a strong guardrail rather than an absolute boundary. The **MCP-tool boundary is the hardest layer** — commands routed through `mcp__lite-sandbox__bash` are validated and path-checked at execution time regardless of hook coverage. For defense-in-depth on writes, you can additionally set Codex's native `sandbox_mode` / `writable_roots`.

### Manual Codex setup

Add the MCP server and hook to `~/.codex/config.toml` (replace the path with your built binary):

```toml
[mcp_servers.lite-sandbox]
command = "/path/to/lite-sandbox"
args = ["serve-mcp"]
default_tools_approval_mode = "approve"

[[hooks.PreToolUse]]
matcher = "Bash|Read|Edit|Write|NotebookEdit|Glob|Grep|apply_patch"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/path/to/lite-sandbox hook"
```

Use `matcher = "Bash"` if you only want to govern the shell, or `command = "/path/to/lite-sandbox hook --validate-bash"` to AST-validate the shell in place instead of redirecting it. Then add a directive to `~/.codex/AGENTS.md` (global) or a project-level `AGENTS.md`:

```markdown
Prefer the `bash` tool from the `lite-sandbox` MCP server for running shell commands. It runs commands through lite-sandbox's AST validation and filesystem path boundaries, which the built-in shell bypasses. Use it instead of the built-in shell whenever possible.
```

Restart Codex after making these changes.

## opencode

To configure [opencode](https://opencode.ai), run the install (autodetected, or named explicitly):

```bash
lite-sandbox install opencode
```

This automatically edits opencode's **global** config and rules (in `~/.config/opencode`, honoring `$XDG_CONFIG_HOME`):

1. Registers the MCP server under `mcp.lite-sandbox` in `opencode.json`
2. Sets `permission.bash` to `"deny"` so the built-in bash tool is blocked and opencode must use the sandbox (the analogue of the Claude installer's `Bash` permission deny; any existing granular `bash` rule is replaced), and sets `permission."lite-sandbox*"` to `"allow"` so the sandbox's tools (`lite-sandbox_bash`, `lite-sandbox_bash_output`, ...) never prompt
3. Adds a usage directive to `AGENTS.md`

All other keys in `opencode.json` are preserved, and re-running is idempotent. Note lite-sandbox can only edit plain JSON — if your global config is `opencode.jsonc` or uses comments, add the entries below manually instead.

Unlike Claude Code and Codex, opencode has **no PreToolUse hook protocol** (its plugins are JavaScript), so the hook-based modes don't apply: `--with-tool-hook` is a no-op for opencode (use opencode's own `permission.edit` / `permission.external_directory` rules to confine its file tools), and `--bash-ast-hook-mode` skips opencode entirely. Reads and writes made *through the sandboxed shell* are still confined at runtime like on every other agent.

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

## Manual Claude Code setup

If you prefer to configure Claude Code manually or need a custom setup:

### 1. Add the MCP server

Add this to `.mcp.json` in your project root (project-scoped) or `~/.claude.json` under the `mcpServers` key (user-scoped/global):

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

Replace `/path/to/lite-sandbox` with the actual path to the built binary.

### 2. Auto-allow the sandbox tool and deny built-in Bash

Add this to `~/.claude/settings.json` so Claude Code never prompts for the sandboxed tools and can no longer use the built-in `Bash` tool:

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
background-process tools, so polling and stopping background commands also run
without prompts.

Denying `Bash` is what makes the sandbox enforceable — without it, Claude could fall back to the unvalidated built-in shell whenever the sandbox rejected a command.

### 3. Direct Claude to use the sandboxed tool

Add the following to your `~/.claude/CLAUDE.md` (global) or project-level `CLAUDE.md`:

```markdown
ALWAYS use the mcp__lite-sandbox__bash tool for running shell commands. The built-in Bash tool is denied and will not run. The sandboxed tool is pre-approved and requires no permission prompts.
```

> **Note**: The tool name follows the pattern `mcp__<server-name>__<tool-name>`. If you named the server differently in your MCP config, adjust the tool name accordingly.

## Built-in tool boundaries

The bash tool confines shell commands to the sandbox's readable and writable paths. But Claude Code's **built-in tools** bypass the sandbox entirely: the built-in `Bash` tool runs unvalidated shell, and `Read`/`Write`/`Edit`/`NotebookEdit` (plus the `Grep`/`Glob` path argument) read and write anywhere — so an agent could read `~/.ssh/id_rsa` or write outside the project through them. The optional tool hook closes that gap.

Enable it at install time:

```bash
lite-sandbox install --with-tool-hook
```

This registers a `PreToolUse` hook (`lite-sandbox hook`) in `~/.claude/settings.json`. On each matching tool call it:

- **redirects `Bash`** — the built-in Bash tool is denied with a message telling the model to use `mcp__lite-sandbox__bash` instead;
- **denies reads** (`Read`, and `Grep`/`Glob` with an explicit `path`) that resolve outside the readable paths;
- **denies writes** (`Write`, `Edit`, `NotebookEdit`) that resolve outside the writable paths;
- **defers** everything in-bounds to Claude Code's normal permission flow.

The path boundaries are computed exactly like the bash tool's (see `cmd/serve.go`): the working directory plus any `readable_paths`/`writable_paths` from config, plus the worktree parent when `git.allow_worktree_parent` is set. Writable paths are also treated as readable. Denials carry a clear reason telling the model the path is out of bounds and that the user can widen the boundary with `lite-sandbox config readable-paths add` / `writable-paths add`.

### Bash: hook vs. permission deny

`PreToolUse` hooks run *after* `permissions.deny`, and a matching deny rule blocks a call regardless of what the hook returns — so a `deny` rule and the hook can't both apply to `Bash`. The two install modes therefore handle `Bash` differently:

- **`lite-sandbox install`** (default) — hard-denies `Bash` via a `permissions.deny` rule. Strongest, but the model only sees a terse rejection; the [`CLAUDE.md` directive](#claude-code) is what points it to the MCP tool.
- **`lite-sandbox install --with-tool-hook`** — leaves `Bash` out of `deny` (removing it if a prior install added it) and lets the hook block it with the actionable redirect message. If the hook ever fails to run, `Bash` falls back to a normal user permission prompt rather than executing silently.

The hook is **fail-open**: any internal error (unparseable event, missing working directory) defers rather than blocking work. It reads config fresh on each call, so boundary changes take effect without reinstalling. To remove it, delete the `PreToolUse` entry for `lite-sandbox hook` from `settings.json`.

### AST-check mode (`--bash-ast-hook-mode`)

`--bash-ast-hook-mode` registers the hook as `lite-sandbox hook --validate-bash` so it **statically AST-checks** the built-in `Bash` command rather than redirecting it. On each `Bash` call it parses the command, runs the sandbox's AST whitelist and path checks, then:

- **allows** the call (skipping the permission prompt) when it passes — so Claude keeps using its own `Bash` tool, gated by the static check;
- **denies** it with the validation error when it fails, so the model can correct the command.

This mode configures no MCP server, adds no `Bash` deny, and writes no `CLAUDE.md` directive — it's purely the AST-checking hook. On its own it matches only `Bash`; combined with `--with-tool-hook` it uses the full matcher, so `Bash` is AST-checked while `Read`/`Write`/`Edit` are confined to the sandbox's paths. Switching install modes is idempotent: a later `install` / `--with-tool-hook` / `--bash-ast-hook-mode` replaces the previous lite-sandbox hook entry rather than stacking a conflicting one.

> **Trade-off — `Bash` runs unsandboxed:** the hook checks the command *statically* and then the real, unsandboxed `Bash` tool executes it. There is no runtime enforcement, so it misses what the MCP tool's interpreter catches at execution (`OpenHandler`/expansion checks for e.g. `cat $VAR`, or reads of paths that don't exist at validation time). The AST whitelist (no `curl`/`nc`/`eval`/shell escapes/etc.) and static path checks on literal arguments still apply in full, but this is a weaker guarantee. For the strongest enforcement, prefer the default or `--with-tool-hook` modes, which route execution through the sandbox.
