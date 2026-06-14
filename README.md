# lite-sandbox-mcp

An MCP (Model Context Protocol) server that provides a `bash` tool as a replacement for basic shell access in AI coding agents. The goal is to let agents run shell commands freely without per-command permission prompts, while enforcing safety through static analysis and runtime validation — commands are parsed into an AST and validated against a whitelist, then executed via a shell interpreter with runtime path validation that catches variable expansion bypasses.

## Configuring with Claude Code

### Automatic Installation

The easiest way to configure Claude Code is to use the built-in install command:

```bash
lite-sandbox install
```

This automatically:
1. Adds the MCP server to `~/.claude.json` (user-scoped)
2. Adds auto-allow permission for `mcp__lite-sandbox__bash` **and denies the built-in `Bash` tool** in `~/.claude/settings.json`
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

<details>
<summary><b>Manual Installation</b> (click to expand)</summary>

If you prefer to configure manually or need a custom setup:

#### 1. Add the MCP server

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

#### 2. Auto-allow the sandbox tool and deny built-in Bash

Add this to `~/.claude/settings.json` so Claude Code never prompts for the sandboxed tool and can no longer use the built-in `Bash` tool:

```json
{
  "permissions": {
    "allow": [
      "mcp__lite-sandbox__bash"
    ],
    "deny": [
      "Bash"
    ]
  }
}
```

Denying `Bash` is what makes the sandbox enforceable — without it, Claude could fall back to the unvalidated built-in shell whenever the sandbox rejected a command.

#### 3. Direct Claude to use the sandboxed tool

Add the following to your `~/.claude/CLAUDE.md` (global) or project-level `CLAUDE.md`:

```markdown
ALWAYS use the mcp__lite-sandbox__bash tool for running shell commands. The built-in Bash tool is denied and will not run. The sandboxed tool is pre-approved and requires no permission prompts.
```

> **Note**: The tool name follows the pattern `mcp__<server-name>__<tool-name>`. If you named the server differently in your MCP config, adjust the tool name accordingly.

</details>

## Background processes

The `bash` tool can run long-lived commands in the background, mirroring the
Claude Code `Bash` / `BashOutput` / `KillShell` tools. Pass
`run_in_background: true` to start a command without blocking; it returns a
shell id immediately. Three companion tools manage these processes:

- **`bash`** with `run_in_background: true` — validates the command (validation
  errors are returned synchronously), starts it detached from the request, and
  returns its shell id. The `timeout` parameter is ignored for background
  commands.
- **`bash_output`** (`bash_id`, optional `filter`) — returns the output produced
  since the previous call, plus the process status (`running`, `completed`,
  `failed`, or `killed`) and exit code once finished. `filter` is a regular
  expression that keeps only matching output lines. Per-process output is capped
  (oldest bytes are dropped) so chatty commands can't grow unbounded.
- **`kill_shell`** (`shell_id`) — stops a running background process.
- **`list_shells`** — lists all background processes with their id, status, and
  exit code.

Background commands pass through the same AST validation, path confinement, and
OS sandbox as foreground commands. They are terminated when the server shuts
down.

**Stopping background processes.** `kill_shell` (and shutdown) tears down the
whole process group, so children the command forked — dev servers, daemons,
`something &` — are reaped, not just the direct process:

- Bare `extra_commands` background commands (where forking servers typically
  run) lead their own process group on the host and are killed as a group.
- Under the OS sandbox, the worker kills each command's process group on Linux;
  on macOS the sandbox's signal confinement limits this to the direct process,
  with the worker's own process group reaped on shutdown.
- For validated commands run through the interpreter (not the OS sandbox), kill
  signals the direct process; deeply forked grandchildren of those are reaped on
  shutdown.

## Configuration

Extra commands can be allowed via a config file at the platform-appropriate location:

- **Linux**: `~/.config/lite-sandbox/config.yaml`
- **macOS**: `~/Library/Application Support/lite-sandbox/config.yaml`

```yaml
extra_commands:
  - curl
  - python3
```

The config file is automatically reloaded when changed — no server restart needed.

### CLI config management

```bash
# Print config file path
lite-sandbox config path

# Show current configuration
lite-sandbox config show

# Add extra allowed commands
lite-sandbox config extra-commands add curl wget

# List extra allowed commands
lite-sandbox config extra-commands list

# Remove extra allowed commands
lite-sandbox config extra-commands remove curl
```

### Readable / writable paths

By default the sandbox confines reads and writes to the working directory. Extra
locations can be granted via `readable_paths` / `writable_paths`:

```yaml
readable_paths:
  - ~/reference-data                 # this dir and everything under it
  - ~/.superconductor/worktrees/haystack/*  # only paths NESTED below it
writable_paths:
  - ~/scratch
```

A bare path grants the directory **and** all of its contents. A trailing `/*`
grants only paths **nested below** the directory — the directory itself is not a
valid read/search target. This is useful for a container that holds many sibling
directories (e.g. a worktree parent): `worktrees/haystack/*` lets the sandbox
read an individual peer worktree while blocking a single `grep`/`ls` from
sweeping every worktree at once. Manage these with
`lite-sandbox config readable-paths add <path>` / `writable-paths add <path>`.

## Git Support

Git commands are enabled by default with granular permission levels that can be configured:

```yaml
git:
  local_read: true             # git status, log, diff, show (default: true)
  local_write: true            # git add, commit, branch, tag (default: true)
  remote_read: true            # git fetch, pull, clone (default: true)
  remote_write: false          # git push (default: false)
  allow_worktree_parent: false # if cwd is a linked worktree, also allow read+write to the main worktree (default: false)
```

Remote write operations (`git push`) are disabled by default since they affect shared state. Enable them only if you want to allow Claude to push commits:

```bash
# Show current git configuration
lite-sandbox config show

# Edit config file to enable git push
# Add 'remote_write: true' under the git section
```

Git commands use runtime path validation to ensure repository paths stay within allowed directories, even when variables are expanded (e.g., `git -C $REPO_DIR status` validates the expanded path).

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

- **`lite-sandbox install`** (default) — hard-denies `Bash` via a `permissions.deny` rule. Strongest, but the model only sees a terse rejection; the [`CLAUDE.md` directive](#automatic-installation) is what points it to the MCP tool.
- **`lite-sandbox install --with-tool-hook`** — leaves `Bash` out of `deny` (removing it if a prior install added it) and lets the hook block it with the actionable redirect message. If the hook ever fails to run, `Bash` falls back to a normal user permission prompt rather than executing silently.

The hook is **fail-open**: any internal error (unparseable event, missing working directory) defers rather than blocking work. It reads config fresh on each call, so boundary changes take effect without reinstalling. To remove it, delete the `PreToolUse` entry for `lite-sandbox hook` from `settings.json`.

### AST-check mode (`--bash-ast-hook-mode`)

`--bash-ast-hook-mode` registers the hook as `lite-sandbox hook --validate-bash` so it **statically AST-checks** the built-in `Bash` command rather than redirecting it. On each `Bash` call it parses the command, runs the sandbox's AST whitelist and path checks, then:

- **allows** the call (skipping the permission prompt) when it passes — so Claude keeps using its own `Bash` tool, gated by the static check;
- **denies** it with the validation error when it fails, so the model can correct the command.

This mode configures no MCP server, adds no `Bash` deny, and writes no `CLAUDE.md` directive — it's purely the AST-checking hook. On its own it matches only `Bash`; combined with `--with-tool-hook` it uses the full matcher, so `Bash` is AST-checked while `Read`/`Write`/`Edit` are confined to the sandbox's paths. Switching install modes is idempotent: a later `install` / `--with-tool-hook` / `--bash-ast-hook-mode` replaces the previous lite-sandbox hook entry rather than stacking a conflicting one.

> **Trade-off — `Bash` runs unsandboxed:** the hook checks the command *statically* and then the real, unsandboxed `Bash` tool executes it. There is no runtime enforcement, so it misses what the MCP tool's interpreter catches at execution (`OpenHandler`/expansion checks for e.g. `cat $VAR`, or reads of paths that don't exist at validation time). The AST whitelist (no `curl`/`nc`/`eval`/shell escapes/etc.) and static path checks on literal arguments still apply in full, but this is a weaker guarantee. For the strongest enforcement, prefer the default or `--with-tool-hook` modes, which route execution through the sandbox.

## Go Runtime Support

Go commands (`go build`, `go test`, `go mod`, etc.) are disabled by default. Enable them via config:

```yaml
runtimes:
  go:
    enabled: true    # Allow go build, test, mod, etc. (default: false)
    generate: false  # Allow go generate (default: false)
```

Go runtime commands use the same runtime path validation as other commands to ensure file paths stay within allowed directories. This enables safe development workflows like:

```bash
go mod init myproject
go test ./...
go build -o mybinary
```

The `go generate` subcommand requires explicit opt-in since it can execute arbitrary code specified in source files.

See `e2e/claude/test_go_runtime_e2e.py` for a complete example demonstrating a Go development workflow (module init, testing, git workflow) using only the sandboxed tool.

## pnpm Runtime Support

pnpm commands are disabled by default. Enable them via config:

```yaml
runtimes:
  pnpm:
    enabled: true   # Allow pnpm install, add, test, run, etc. (default: false)
    publish: false  # Allow pnpm publish (default: false)
```

Enable pnpm via CLI:

```bash
# Enable pnpm commands
lite-sandbox config runtimes pnpm enable

# Enable with publish permission
lite-sandbox config runtimes pnpm enable --with-publish

# Show current pnpm configuration
lite-sandbox config runtimes pnpm show
```

pnpm runtime commands enable safe package management workflows:

```bash
pnpm install
pnpm add react
pnpm test
pnpm run build
```

Security features:
- `pnpm dlx` is blocked (downloads and executes remote packages)
- `pnpm publish` requires explicit opt-in since it affects the npm registry (shared state)

## Deno Runtime Support

Deno commands are disabled by default. Enable them via config:

```yaml
runtimes:
  deno:
    enabled: true        # Allow deno run, test, fmt, lint, task, etc. (default: false)
    publish: false       # Allow deno publish to JSR (default: false)
    auto_sandbox: true   # Auto-scope --allow-read/--allow-write to sandbox paths (default: true)
    allow_network: false # Allow outbound network sockets (default: false)
    allow_import: true   # Allow fetching remote modules (default: true)
```

Enable deno via CLI:

```bash
# Enable deno commands (auto-sandbox is on by default)
lite-sandbox config runtimes deno enable

# Allow outbound network sockets
lite-sandbox config runtimes deno enable --with-network

# Lock down remote module imports (also blocks deno cache/add/install)
lite-sandbox config runtimes deno disable --with-import

# Turn off auto-sandbox but keep deno enabled
lite-sandbox config runtimes deno disable --with-auto-sandbox

# Show current deno configuration
lite-sandbox config runtimes deno show
```

Deno runtime commands enable safe development workflows:

```bash
deno run main.ts
deno test
deno fmt
deno lint
deno task build
```

Security features:
- `deno publish` requires explicit opt-in since it affects the JSR registry (shared state)
- `deno upgrade` is blocked (modifies the deno installation in place)
- `deno eval` is blocked — it runs with implicit access to *all* permissions and
  rejects every `--allow-*`/`--deny-*` flag, so it cannot be confined (an
  unsandboxable code-execution escape hatch, like shell `eval`/`exec`).
- **Auto-sandbox** (`auto_sandbox: true`, the default) — Deno runs with no
  permissions by default and prompts interactively when a script requests
  access it wasn't granted, which would hang a non-interactive sandbox. With
  auto-sandbox enabled, lite-sandbox automatically injects
  `--allow-read`/`--allow-write` scoped to the sandbox's allowed paths for
  permissioned subcommands (`run`, `test`, `bench`, `repl`, `serve`, `compile`,
  `install`), so Deno's permission model mirrors the sandbox filesystem policy
  and runs non-interactively. Existing read/write grants on the command
  (including short `-R`/`-W` or a blanket `-A`) are respected.
- **Network sockets off by default** — `--deny-net` is forced unless
  `allow_network: true`. This is enforced whenever deno is enabled, independent
  of auto-sandbox, so turning auto-sandbox off does not re-open the network.
  `--deny-net` takes precedence over any `--allow-net`/`-A` the invoker passes.
- **Remote imports on by default, behind a flag** — Deno fetches remote modules
  from a default host allowlist (`deno.land`/`jsr.io`/…) out of the box, which
  is core to normal usage, so imports are allowed by default. Setting
  `allow_import: false` blocks remote module fetching on code-executing
  subcommands with `--no-remote` (https/jsr) + `--no-npm` (npm) — the levers
  that actually stop the module graph from being fetched — plus `--deny-import`
  for runtime dynamic imports. It also blocks the CLI fetch subcommands
  (`deno cache`, `deno add`, `deno install`), which fetch at the CLI level where
  an injected flag cannot stop them. (Already-cached modules can still load;
  with `allow_import: false` from the start, nothing new is fetched or cached.)

## Security Model

Commands go through multiple validation layers:

### Static preflight (AST-level, before execution)

1. **Command whitelist** — Only explicitly allowed, non-destructive commands can run (e.g., `cat`, `ls`, `grep`, `find`). Code execution runtimes, networking tools, package managers, and shell escape commands are all blocked. Additional commands can be allowed via config.
2. **Argument validation** — Per-command validators block dangerous flags (e.g., `find -exec`, `tar -x`, `git push`). Write commands (`cp`, `mv`, `rm`, `sed`, etc.) are allowed but path-validated.
3. **Structural restrictions** — Process substitutions, coprocesses, read-write redirections, and dynamic command names are blocked.
4. **Static path validation** — Literal path-like arguments (including paths embedded in flags like `-f/path` and `--file=/path`) are resolved to absolute paths with symlink resolution and checked against an allowed directory list (defaults to cwd). Access to `.git` directories is blocked.

### Runtime validation (interpreter-level, during execution)

Commands are executed via the [mvdan.cc/sh/v3](https://pkg.go.dev/mvdan.cc/sh/v3) shell interpreter rather than `bash -c`. This enables runtime validation after variable expansion:

5. **Expanded path validation** — A `CallHandler` intercepts every command after variable and command substitution expansion, validating that all resolved path arguments stay within allowed directories. This catches bypasses like `cat $HOME/secret` that static analysis cannot resolve.
6. **Redirect path validation** — An `OpenHandler` intercepts all file opens from redirections (e.g., `< $FILE`, `> $OUTPUT`), validating expanded paths before any I/O occurs.

### OS-level sandboxing (optional)

An optional OS-level sandbox provides an additional layer of isolation on top of AST-level validation. The implementation uses the native sandboxing mechanism for each platform:

- **Linux** — [bubblewrap](https://github.com/containers/bubblewrap) via Linux namespaces
- **macOS** — `sandbox-exec` with dynamically generated SBPL profiles

**Architecture:**
- **Long-lived worker** — A single sandboxed process that accepts gob-encoded commands over stdin/stdout
- **Process reuse** — The worker executes multiple commands without restarting the sandbox, reducing overhead
- **Automatic recovery** — A dead worker is detected and replaced automatically
- **Die-with-parent** — The worker is killed if the MCP server exits

**Configuration:**

Enable via config file (Linux: `~/.config/lite-sandbox/config.yaml`, macOS: `~/Library/Application Support/lite-sandbox/config.yaml`):

```yaml
os_sandbox: true          # Enable OS-level sandboxing (default: false)
```

Or via CLI:

```bash
# Enable OS sandbox
lite-sandbox config os-sandbox enable

# Show current status
lite-sandbox config os-sandbox show
```

#### Linux (bubblewrap)

Commands execute inside a lightweight container via Linux namespaces:

**Isolation features:**
- **Read-only root filesystem** — The entire host filesystem is mounted read-only, preventing writes outside allowed paths
- **Writable working directory** — The project directory is bind-mounted as writable
- **Writable /tmp** — A tmpfs is mounted at `/tmp` for temporary files and build caches
- **Fresh /dev and /proc** — New device and process filesystems prevent access to host state
- **Network sharing** — Network access is preserved (unshare all except network)
- **Runtime bind mounts** — Additional writable paths are mounted for enabled runtimes (e.g., `$GOPATH/bin` for Go)

**Requirements:**
- **Linux only** — Requires Linux kernel with unprivileged user namespaces
- **bubblewrap installed** — Install via package manager (e.g., `apt install bubblewrap`, `pacman -S bubblewrap`)
- **Kernel configuration** — Some systems require enabling unprivileged user namespaces:
  ```bash
  # Check if enabled (should be 1)
  sysctl kernel.unprivileged_userns_clone

  # Enable temporarily
  sudo sysctl -w kernel.unprivileged_userns_clone=1

  # Enable permanently (add to /etc/sysctl.conf)
  kernel.unprivileged_userns_clone=1
  ```

#### macOS (sandbox-exec)

Commands execute inside a dynamically generated SBPL (Scheme-based Profile Language) sandbox profile via `sandbox-exec`:

**Isolation features:**
- **Writable working directory** — Only the project directory (and its resolved symlink) is writable
- **Writable temp directories** — `/tmp`, `/private/tmp`, `/var/folders`, and `/private/var/folders` are writable (required for build caches and `TMPDIR`)
- **SSH key protection** — SSH private keys in `~/.ssh` are always denied read access; `known_hosts`, `config`, and `authorized_keys` remain accessible
- **AWS credential protection** — `~/.aws` is denied read access when AWS IMDS is configured
- **Network access** — Network access is preserved
- **Process execution** — Full process execution is allowed (enforcement is at the filesystem level)

**Requirements:**
- **macOS only** — Uses the built-in `sandbox-exec` command (no additional software required)

**Defense in depth:**

The OS sandbox provides defense-in-depth on top of the AST-level validation:
- If a dangerous command bypasses AST validation, filesystem restrictions prevent writes outside the working directory
- Process substitutions and command injections are still blocked at the AST level before reaching the OS sandbox
- The OS sandbox does NOT replace AST validation — both layers work together

## Known Limitations

This is a lightweight, best-effort sandbox based on static analysis. It is **not** a security boundary equivalent to containers, VMs, or seccomp. Known bypasses and limitations:

### Path validation bypasses

- **Glob expansion**: Glob patterns are validated as literal strings (e.g., `cat ./*.txt` checks the prefix `./`), but the interpreter expands globs at runtime. A glob rooted inside the allowed directory cannot expand outside it, but this relies on the filesystem not containing adversarial symlinks within the allowed directory.
- **Multi-char short flag ambiguity**: For short flags like `-la`, the extractor assumes single-char flag + value (extracting `a`). This is conservative and doesn't cause false negatives for path validation since `a` alone won't pass the `looksLikePath` check, but a combined flag like `-abc/etc/passwd` would only check `bc/etc/passwd` (missing the leading character).

### Command validation limitations

- **Per-command argument validation**: Some whitelisted commands have dangerous flags that are blocked via argument validators. For `find`, the flags `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`, `-fls`, `-fprint`, `-fprint0`, and `-fprintf` are all blocked. Other commands like `xxd` can write files with `-r` when combined with redirections (though redirections are blocked).
- **No syscall-level enforcement**: AST validation happens before execution without runtime syscall filtering (no seccomp). If a command is allowed and passes AST validation, it executes with the permissions granted by the environment. The optional OS sandbox (bubblewrap on Linux, sandbox-exec on macOS) provides significant additional protection via filesystem isolation — even if a dangerous command bypasses AST validation, filesystem restrictions prevent writes outside the working directory.
- **Bash builtins**: Some allowed builtins like `set`, `export`, and `trap` can modify shell state in ways that affect subsequent commands within the same invocation.

### General limitations

- **Not a complete security boundary**: The AST-level sandbox is defense-in-depth for limiting an LLM's access to the host system. It should not be the sole security mechanism for untrusted workloads. The optional OS sandbox (bubblewrap on Linux, sandbox-exec on macOS) adds significant filesystem isolation, but still shares the network namespace and doesn't provide seccomp-level syscall filtering. For maximum isolation of untrusted workloads, use VMs.
- **Interpreter differences**: Commands are executed via the mvdan.cc/sh interpreter rather than GNU bash. While it supports standard POSIX and bash features, some GNU bash extensions may behave differently.
- **Extra commands bypass validation**: Commands added via `extra_commands` config are allowed without any argument validation. Only add commands you trust.

## Building

```bash
go build -o lite-sandbox
./lite-sandbox install  # Automatically configure Claude Code
```

## Development

```bash
go test ./...              # Run all tests
go test -v ./tool/...      # Run tool package tests with verbose output
```

### E2E Testing

End-to-end tests verify real-world usage via the Claude Agent SDK. They test that Claude can successfully use the sandboxed MCP tool without falling back to built-in Bash:

```bash
cd e2e/claude
uv run pytest -v          # Run all e2e tests
uv run pytest -v -k test_go_project_workflow  # Run specific test
```

**Showcase test**: `e2e/claude/test_go_runtime_e2e.py` demonstrates a complete Go development workflow — module initialization, writing code and tests, running `go test`, and creating a git commit — all using only the `bash` MCP tool with no built-in Bash calls. This test shows how the sandbox enables safe, autonomous development workflows for AI coding agents.
