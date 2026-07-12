# Security Model

Commands go through multiple validation layers.

## Static preflight (AST-level, before execution)

1. **Command whitelist** — Only explicitly allowed, non-destructive commands can run (e.g., `cat`, `ls`, `grep`, `find`). Code execution runtimes, networking tools, package managers, and shell escape commands are all blocked. Additional commands can be allowed via config.
2. **Argument validation** — Per-command validators block dangerous flags (e.g., `find -exec`, `tar -x`, `git push`). Write commands (`cp`, `mv`, `rm`, `sed`, etc.) are allowed but path-validated.
3. **Structural restrictions** — Coprocesses, read-write redirections (`<>`), and dynamic (non-literal) command names are blocked. Process substitutions (`<(...)`) are allowed, but the validator recurses into them so every command nested inside is checked against the same whitelist.
4. **Static path validation** — Literal path-like arguments (including paths embedded in flags like `-f/path` and `--file=/path`) are resolved to absolute paths with symlink resolution and checked against an allowed directory list (defaults to cwd). Access to `.git` directories is blocked.

## Runtime validation (interpreter-level, during execution)

Commands are executed via the [mvdan.cc/sh/v3](https://pkg.go.dev/mvdan.cc/sh/v3) shell interpreter rather than `bash -c`. This enables runtime validation after variable expansion:

5. **Expanded path validation** — A `CallHandler` intercepts every command after variable and command substitution expansion, validating that all resolved path arguments stay within allowed directories. This catches bypasses like `cat $HOME/secret` that static analysis cannot resolve.
6. **Redirect path validation** — An `OpenHandler` intercepts all file opens from redirections (e.g., `< $FILE`, `> $OUTPUT`), validating expanded paths before any I/O occurs.

## OS-level sandboxing (optional)

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

### Common isolation (both platforms)

The two backends use different mechanisms (bubblewrap mounts vs. SBPL rules) but
enforce the same policy:

- **Writes confined to the working directory** — Only the working directory (and its resolved symlink), configured `writable_paths`, the main worktree when `git.allow_worktree_parent` is enabled and the working directory is a linked worktree, and temp dirs are writable; everything else on the host is read-only. Since these grants are baked into the sandbox profile at worker start, any config change recycles the worker so the new policy takes effect on the next command.
- **Writable temp directories** — `/tmp` and the platform's other temporary directories are writable, as required for build caches and `TMPDIR`.
- **Runtime bind mounts** — Additional writable paths are granted for enabled runtimes (e.g., `$GOPATH`/`$GOCACHE` for Go, or the fvm SDK cache and pub cache for Flutter).
- **Network preserved** — Network access is left intact.
- **Process execution allowed** — Spawning subprocesses is permitted; enforcement is at the filesystem level.
- **SSH key protection** — SSH **private** keys in `~/.ssh` are **always** denied read access; `known_hosts`, `config`, `authorized_keys`, and `*.pub` files remain accessible.
- **AWS credential protection** — `~/.aws` is denied read access when AWS IMDS mode is configured (`aws.force_profile`; see [AWS & Docker access](aws-and-docker.md)).

### Linux (bubblewrap)

Commands execute inside a lightweight container via Linux namespaces. On top of
the common policy above, the Linux backend adds:

- **Read-only root filesystem** — The entire host filesystem is mounted read-only via bubblewrap, with the writable paths bind-mounted back in.
- **Fresh /dev and /proc** — New device and process filesystems prevent access to host state.
- **Namespace isolation** — All namespaces are unshared except the network (`--unshare-all --share-net`), and the worker is killed if the server exits (`--die-with-parent`).

**Requirements:**
- **Linux only** — Requires a Linux kernel with unprivileged user namespaces
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

### macOS (sandbox-exec)

Commands execute inside a dynamically generated SBPL (Scheme-based Profile
Language) profile via `sandbox-exec`. On top of the common policy above, the
macOS backend adds:

- **Signal confinement** — The profile denies signaling processes outside the worker's own process group, so a sandboxed `kill`/`pkill` cannot reach host processes.

**Requirements:**
- **macOS only** — Uses the built-in `sandbox-exec` command (no additional software required)

**Defense in depth:**

The OS sandbox provides defense-in-depth on top of the AST-level validation:
- If a dangerous command bypasses AST validation, filesystem restrictions prevent writes outside the working directory
- Disallowed commands are still blocked at the AST level (including any nested inside process substitutions or command substitutions) before reaching the OS sandbox
- The OS sandbox does NOT replace AST validation — both layers work together

## Known Limitations

This is a lightweight, best-effort sandbox based on static analysis. It is **not** a security boundary equivalent to containers, VMs, or seccomp. Known bypasses and limitations:

### Path validation bypasses

- **Glob expansion**: Glob patterns are validated as literal strings (e.g., `cat ./*.txt` checks the prefix `./`), but the interpreter expands globs at runtime. A glob rooted inside the allowed directory cannot expand outside it, but this relies on the filesystem not containing adversarial symlinks within the allowed directory.
- **Multi-char short flag ambiguity**: For short flags like `-la`, the extractor assumes single-char flag + value (extracting `a`). This is conservative and doesn't cause false negatives for path validation since `a` alone won't pass the `looksLikePath` check, but a combined flag like `-abc/etc/passwd` would only check `bc/etc/passwd` (missing the leading character).

### Command validation limitations

- **Per-command argument validation**: Some whitelisted commands have dangerous flags that are blocked via argument validators. For `find`, the flags `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`, `-fls`, `-fprint`, `-fprint0`, and `-fprintf` are all blocked. Other commands like `xxd` can write files with `-r` when combined with redirections (though redirections are blocked).
- **Command wrappers**: Commands that run another program as a child process — `xargs`, `find -exec`, `env`, and `timeout` — are validated recursively: the wrapped command name and its arguments are checked against the whitelist (and its own argument validator) just as if it had been invoked directly. This prevents using a wrapper as a prefix to smuggle a blocked command past validation (e.g. `env curl …`, `timeout 5 sh -c …`). `env -S`/`--split-string` is rejected outright because it constructs an argument vector from a single string. `bash`, `sh`, `awk`, and `time` are refused entirely in wrapped position, since their sandbox safety depends on the interpreter being their direct caller.
- **No syscall-level enforcement**: AST validation happens before execution without runtime syscall filtering (no seccomp). If a command is allowed and passes AST validation, it executes with the permissions granted by the environment. The optional OS sandbox (bubblewrap on Linux, sandbox-exec on macOS) provides significant additional protection via filesystem isolation — even if a dangerous command bypasses AST validation, filesystem restrictions prevent writes outside the working directory.
- **Bash builtins**: Some allowed builtins like `set`, `export`, and `trap` can modify shell state in ways that affect subsequent commands within the same invocation.

### General limitations

- **Not a complete security boundary**: The AST-level sandbox is defense-in-depth for limiting an LLM's access to the host system. It should not be the sole security mechanism for untrusted workloads. The optional OS sandbox (bubblewrap on Linux, sandbox-exec on macOS) adds significant filesystem isolation, but still shares the network namespace and doesn't provide seccomp-level syscall filtering. For maximum isolation of untrusted workloads, use VMs.
- **Interpreter differences**: Commands are executed via the mvdan.cc/sh interpreter rather than GNU bash. While it supports standard POSIX and bash features, some GNU bash extensions may behave differently.
- **Extra commands bypass validation**: Commands added via `extra_commands` config are allowed without any argument validation. Bare entries (a single token, e.g. `curl`) additionally bypass bash AST parsing entirely — the whole command string is handed to the real bash. When the OS sandbox is enabled that bash runs inside the sandbox worker, so filesystem confinement (write restrictions, masked paths) still applies even though no validation ran; without the OS sandbox there is no confinement at all. Only add commands you trust.
- **Unsandboxed commands bypass validation *and* the OS sandbox**: `unsandboxed_commands` entries are parsed like `extra_commands` but matching invocations always run directly on the host — the OS sandbox worker (bwrap/sandbox-exec) is not used, so there is **no** filesystem confinement, masked-path protection, or docker filtering proxy for them even when the OS sandbox is otherwise enabled. This is a stronger escape hatch than `extra_commands`; use it only for commands that genuinely cannot run confined (e.g. `docker` talking to the real daemon), and only for commands you fully trust.
