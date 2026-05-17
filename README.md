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
2. Adds auto-allow permission to `~/.claude/settings.json`
3. Adds usage directive to `~/.claude/CLAUDE.md`

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

#### 2. Auto-allow the tool

Add this to `~/.claude/settings.json` so Claude Code never prompts for permission:

```json
{
  "permissions": {
    "allow": [
      "mcp__lite-sandbox__bash"
    ]
  }
}
```

#### 3. Direct Claude to prefer the sandboxed tool

Add the following to your `~/.claude/CLAUDE.md` (global) or project-level `CLAUDE.md`:

```markdown
ALWAYS use the mcp__lite-sandbox__bash tool for running shell commands instead of the built-in Bash tool. The sandboxed tool is pre-approved and requires no permission prompts. Only fall back to Bash if the sandboxed tool cannot handle the command.
```

> **Note**: The tool name follows the pattern `mcp__<server-name>__<tool-name>`. If you named the server differently in your MCP config, adjust the tool name accordingly.

</details>

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
