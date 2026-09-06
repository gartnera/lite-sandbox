# Security Model

Commands go through multiple validation layers. Which layers *block* depends
on the configured `mode` — `allowlist` by default; see
[Incremental adoption](adoption.md) for the looser opt-outs — and every layer still
*runs* in every mode so that, with `audit: true`, each finding is recorded with
the modes that would have enforced it.

## Modes and what they defend against

| Rule | `open` | `denylist` | `allowlist` |
|---|---|---|---|
| Command whitelist, runtime enable gates, direct execution of `./script` | audit only | audit only | enforced |
| Path boundary on arguments, redirections, file opens; `.git` protection | audit only | enforced | enforced |
| Per-command argument validators (`git push`, `find -delete`, `tar -x`, publish flags, …) | audit only | enforced | enforced |
| Structural checks (coprocesses, `<>`, protected env assignments, shells in wrapped position) | audit only | enforced | enforced |
| OS sandbox writes | off | `$HOME` writable; deny lists masked | project + configured paths |

**`denylist` assumes a cooperative agent.** It stops the mistakes an agent
makes on its own — `find ~`, `cat $HOME/.aws/config`, `rm -rf ..`,
`> ~/.bashrc`, an accidental `git push` — and, under the OS sandbox, hides
credentials from the programs it starts. It does not stop an agent that has
been steered by content it read (prompt injection) from running a script that
opens a file the AST layer never saw a path for, unless the OS sandbox masks
that file; nor does it block network tools, so anything readable is
exfiltratable. **`allowlist` is the posture for untrusted input**: unlisted
programs, network tools and runtimes are blocked outright, and the OS sandbox
confines writes to the project. The rest of this document describes the
layers in full; the table above is what each mode keeps.

The command whitelist is, by construction, the layer that breaks developer
workflows (`python3`, `npm`, `make`, `./script` are all off it), which is why
it is the one `denylist` drops. Note the path boundary applies to *every*
command's arguments, listed or not, so `python3 ~/other/x.py` is still rejected
in `denylist` mode as out of scope.

## Static preflight (AST-level, before execution)

1. **Command whitelist** — Only explicitly allowed, non-destructive commands can run (e.g., `cat`, `ls`, `grep`, `find`). Code execution runtimes, networking tools, package managers, and shell escape commands are all blocked. Additional commands can be allowed via config.
2. **Argument validation** — Per-command validators block dangerous flags (e.g., `find -exec`, `tar -x`, `git push`). Write commands (`cp`, `mv`, `rm`, `sed`, etc.) are allowed but path-validated.
3. **Structural restrictions** — Coprocesses and read-write redirections (`<>`) are blocked. Dynamic (non-literal) command names — e.g. `$CMD ...` or `$(...)` in command position — cannot be resolved statically, so instead of being rejected they are deferred to the runtime layer, which re-checks the whitelist and re-runs the per-command argument validators against the fully expanded argv (see below). Dynamic command names remain rejected inside command *wrappers* (`env`, `xargs`, `find -exec`, `timeout`, `rg --pre`), because the wrapper spawns that child itself and it never re-enters the interpreter. Process substitutions (`<(...)`) are allowed, but the validator recurses into them so every command nested inside is checked against the same whitelist.
4. **Static path validation** — Literal path-like arguments (including paths embedded in flags like `-f/path` and `--file=/path`) are resolved to absolute paths with symlink resolution and checked against an allowed directory list (defaults to cwd). Access to `.git` directories is blocked.

## Runtime validation (interpreter-level, during execution)

Commands are executed via the [mvdan.cc/sh/v3](https://pkg.go.dev/mvdan.cc/sh/v3) shell interpreter rather than `bash -c`. This enables runtime validation after variable expansion:

5. **Expanded path validation** — A `CallHandler` intercepts every command after variable and command substitution expansion, validating that all resolved path arguments stay within allowed directories. This catches bypasses like `cat $HOME/secret` that static analysis cannot resolve.
6. **Redirect path validation** — An `OpenHandler` intercepts all file opens from redirections (e.g., `< $FILE`, `> $OUTPUT`), validating expanded paths before any I/O occurs.
7. **Expanded command validation** — The whitelist and per-command argument validators are re-enforced on the fully expanded argv. The `CallHandler` runs for every command *before* the interpreter resolves whether it is a builtin, function, or external, so it enforces the whitelist for builtins (an external is left for the `ExecHandler`); the `ExecHandler` runs only for external commands and there re-runs both the whitelist check and the per-command argument validator. This is the layer that safely handles a dynamically-named command (e.g. `$CMD push` resolving to `git`), whose real name and arguments are only concrete at runtime. `bash`/`sh`/`awk` are exempt from the re-run because they are dispatched to dedicated executors that re-parse and re-validate their contents through the interpreter.
8. **Python OS-call validation** — `python`/`python3` are dispatched to an embedded Python interpreter (monty) rather than executed. It performs no I/O of its own: every filesystem operation suspends the interpreter and returns to the host as a typed OS call, which is checked against the same read/write path sets as bash before it is performed. See [Python](#python-monty) below.

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
lite-sandbox config os-sandbox check    # can bubblewrap / sandbox-exec run here?
lite-sandbox config os-sandbox enable   # runs the same check first; --force to skip it
lite-sandbox config os-sandbox show
```

`lite-sandbox config mode set denylist` (and `install --mode denylist`) enable it
when the check passes and `os_sandbox` was never set. `enable` refuses when the
check fails, because with `os_sandbox: true` and no working backend every
command fails; the error names what to install.

### Common isolation (both platforms)

The two backends use different mechanisms (bubblewrap mounts vs. SBPL rules) but
enforce the same policy:

- **Writes confined to the working directory (`allowlist` mode)** — Only the working directory (and its resolved symlink), configured `writable_paths`, the Claude Code per-user scratchpad root (`/tmp/claude-<uid>`), the per-user system temp dir (`$TMPDIR`, e.g. macOS's `/var/folders/.../T`, when it is not the world-shared `/tmp`), the main worktree when `git.allow_worktree_parent` is enabled and the working directory is a linked worktree, and temp dirs are writable; everything else on the host is read-only. Since these grants are baked into the sandbox profile at worker start, any config change recycles the worker so the new policy takes effect on the next command.
- **`$HOME` writable, deny lists masked (`denylist` mode)** — The home directory is bound writable so tool caches and state need no enumeration, and the built-in [deny lists](configuration.md#denied-paths-denylist-mode) are applied on top: read-denied paths become unreadable (`--perms 000` tmpfs for directories, an empty mode-000 file bound over files; SBPL `deny file-read*` on macOS), write-denied paths are bound read-only over themselves (`deny file-write*`). Everything outside `$HOME` stays read-only as in `allowlist` mode. The masks are emitted after every bind, so neither the home bind nor a `writable_paths` entry can re-expose them, and a read-denied path is also write-denied so nothing can be planted there for the host user to pick up later. **Linux caveat:** bubblewrap can only overlay a path that exists, and creates a missing mount point on the host. A missing deny-listed *directory* is therefore created (mode 0700) before being masked; a missing deny-listed *file* (a `~/.zshrc` that was never written, say) is left alone — an empty `~/.bash_profile` appearing on the host would change the user's shell — and is not protected until it exists. `lite-sandbox config mode show` marks these. sandbox-exec has no such gap: its deny rules apply to paths whether or not they exist. The lists are evaluated when the worker starts (every config change restarts it).
- **Writable temp directories** — `/tmp` and the platform's other temporary directories are writable, as required for build caches and `TMPDIR`.
- **Runtime bind mounts** — Additional writable paths are granted for enabled runtimes (e.g., `$GOPATH`/`$GOCACHE` for Go, the fvm SDK cache and pub cache for Flutter, or `uv cache dir`/`uv python dir` for uv).
- **Internal paths** — `internal_readable_paths` / `internal_writable_paths` loosen only this OS-sandbox layer, so programs a command spawns can reach their own data (e.g. a tool's `~/.cache` directory). They are deliberately excluded from every agent-facing boundary: the static/runtime path validation still denies direct reads and writes, the PreToolUse file-tool hook and the docker proxy's bind-mount checks don't honor them, and Deno's auto-injected `--allow-read`/`--allow-write` never includes them (granting them to Deno-executed code would be a trivial sandbox workaround). They can never re-expose the SSH/AWS credential masks.
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

## Python (monty)

`python` and `python3` do not run any interpreter from the host. They are served
by [monty](https://github.com/pydantic/monty) — a Python interpreter compiled to
WebAssembly — embedded in the lite-sandbox binary and run in-process via wazero.

**Python file I/O goes through the same path sets as bash.** monty has no
filesystem access of its own; when Python touches a file the interpreter
suspends and hands the host a typed OS call. The host checks the path against
the readable set (reads) or the writable set (writes) using the same
`checkPathBoundary` the bash `CallHandler` and `OpenHandler` use, including the
`.git` exclusion, and only then performs it. There is deliberately not a second
path policy for Python.

**monty's own isolation is stronger than the AST-level boundary around it.**
Inside the wasm sandbox there is no network, no environment (`os.environ` is
always empty, so masked credentials cannot be read back), no ambient filesystem,
no subprocess execution, and no way to reach a syscall except through the host
callback described above. The AST layer's known weaknesses — glob expansion,
flag-parsing ambiguity, wrappers — do not apply to it, because there is no argv
to misparse: the boundary is enforced at the point of each individual file
operation, on the fully resolved path.

`python`/`python3` are also refused in *wrapped* position — as the child of
`xargs`, `env`, `timeout`, or `find -exec` — for the same reason `bash`, `sh`
and `awk` are (see `subCommandDenylist`). The dispatch to monty only happens
when the sandbox interpreter is the direct caller; a wrapper spawns its child as
a native process, which would resolve the real CPython from `$PATH` and run it
outside every layer of this sandbox.

Naming `python`/`python3` in `extra_commands` or `unsandboxed_commands`
deliberately opts back in to the real interpreter for matching invocations,
with the loss of validation those lists always imply. A *bare* entry also lifts
the wrapped-subcommand refusal above: once the host interpreter runs unwrapped
on request, refusing the wrapped form protects nothing. A subcommand-restricted
entry does not, since a wrapper's argv is never checked against the restriction.

Three details are worth knowing:

- **A denial ends the run.** The host returns an error rather than a value, and
  Python cannot catch it. A script cannot retry in a loop to probe the boundary.
- **A prologue is prepended when a program uses `sys.argv`,** since monty has
  none. It defines a shim object holding the argument strings and rewrites the
  statements that would rebind `sys` back to the real module. The rewrite only
  ever adds an assignment to that shim, so it cannot widen what Python can
  reach; every file operation still goes through the OS-call boundary. Programs
  that never mention `argv` are passed through untouched.
- **The host-side file operations are not covered by the OS sandbox.** monty
  runs in the MCP server process, not in the bwrap/sandbox-exec worker, so the
  reads and writes its OS calls trigger happen outside that worker. They are
  instead performed through `os.Root` (openat2-rooted on Linux), so the kernel
  itself confines the resolution to the allowed directory — a symlink swapped
  between the check and the open cannot move it. This is the same primitive
  monty's own upstream mount implementation relies on.

Each run is additionally bounded by the command timeout, a memory cap, a
recursion limit, and a cap on host calls per run (which backstops a script that
loops on filesystem operations, since time spent in host calls does not advance
the interpreter's own duration accounting).

## Known Limitations

This is a lightweight, best-effort sandbox based on static analysis. It is **not** a security boundary equivalent to containers, VMs, or seccomp. Known bypasses and limitations:

### Path validation bypasses

- **Glob expansion**: Glob patterns are validated as literal strings (e.g., `cat ./*.txt` checks the prefix `./`), but the interpreter expands globs at runtime. A glob rooted inside the allowed directory cannot expand outside it, but this relies on the filesystem not containing adversarial symlinks within the allowed directory.
- **Multi-char short flag ambiguity**: For short flags like `-la`, the extractor assumes single-char flag + value (extracting `a`). This is conservative and doesn't cause false negatives for path validation since `a` alone won't pass the `looksLikePath` check, but a combined flag like `-abc/etc/passwd` would only check `bc/etc/passwd` (missing the leading character).

### Command validation limitations

- **Per-command argument validation**: Some whitelisted commands have dangerous flags that are blocked via argument validators. For `find`, the flags `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`, `-fls`, `-fprint`, `-fprint0`, and `-fprintf` are all blocked. Other commands like `xxd` can write files with `-r` when combined with redirections (though redirections are blocked).
- **Command wrappers**: Commands that run another program as a child process — `xargs`, `find -exec`, `env`, and `timeout` — are validated recursively: the wrapped command name and its arguments are checked against the whitelist (and its own argument validator) just as if it had been invoked directly. This prevents using a wrapper as a prefix to smuggle a blocked command past validation (e.g. `env curl …`, `timeout 5 sh -c …`). `env -S`/`--split-string` is rejected outright because it constructs an argument vector from a single string. `bash`, `sh`, `awk`, and `time` are refused entirely in wrapped position, since their sandbox safety depends on the interpreter being their direct caller.
- **No syscall-level enforcement**: AST validation happens before execution without runtime syscall filtering (no seccomp). If a command is allowed and passes AST validation, it executes with the permissions granted by the environment. The optional OS sandbox (bubblewrap on Linux, sandbox-exec on macOS) provides significant additional protection via filesystem isolation — even if a dangerous command bypasses AST validation, filesystem restrictions prevent writes outside the working directory.
- **Python is a subset**: monty implements a subset of Python and cannot import third-party packages, so `python3` in the sandbox is not a drop-in for CPython. Real CPython is available via the uv runtime (`uv run`), where confinement comes from the OS sandbox rather than from monty.
- **Bash builtins**: Some allowed builtins like `set`, `export`, and `trap` can modify shell state in ways that affect subsequent commands within the same invocation.

### General limitations

- **Not a complete security boundary**: The AST-level sandbox is defense-in-depth for limiting an LLM's access to the host system. It should not be the sole security mechanism for untrusted workloads. The optional OS sandbox (bubblewrap on Linux, sandbox-exec on macOS) adds significant filesystem isolation, but still shares the network namespace and doesn't provide seccomp-level syscall filtering. For maximum isolation of untrusted workloads, use VMs.
- **Interpreter differences**: Commands are executed via the mvdan.cc/sh interpreter rather than GNU bash. While it supports standard POSIX and bash features, some GNU bash extensions may behave differently.
- **Extra commands bypass validation**: Commands added via `extra_commands` config are allowed without any argument validation. Bare entries (a single token, e.g. `curl`) additionally bypass bash AST parsing entirely — the whole command string is handed to the real bash. When the OS sandbox is enabled that bash runs inside the sandbox worker, so filesystem confinement (write restrictions, masked paths) still applies even though no validation ran; without the OS sandbox there is no confinement at all. Only add commands you trust.
- **Unsandboxed commands bypass validation *and* the OS sandbox**: `unsandboxed_commands` entries are parsed like `extra_commands` but matching invocations always run directly on the host — the OS sandbox worker (bwrap/sandbox-exec) is not used, so there is **no** filesystem confinement, masked-path protection, or docker filtering proxy for them even when the OS sandbox is otherwise enabled. This is a stronger escape hatch than `extra_commands`; use it only for commands that genuinely cannot run confined (e.g. `docker` talking to the real daemon), and only for commands you fully trust.
