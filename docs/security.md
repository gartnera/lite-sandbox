# Security Model

Commands go through several validation layers. Which layers *block* depends on
the configured `mode` (`allowlist` by default; see
[Incremental adoption](adoption.md) for the looser modes). Every layer still
*runs* in every mode, so with `audit: true` each finding is recorded with the
modes that would have enforced it.

## Modes and what they defend against

| Rule | `open` | `denylist` | `allowlist` |
|---|---|---|---|
| Command whitelist, runtime enable gates, direct execution of `./script` | audit only | audit only | enforced |
| Command deny list (`commands` denials + the built-in self-protection entries) | audit only | enforced | enforced |
| Path boundary on arguments, redirections, file opens; `.git` protection | audit only | enforced | enforced |
| Per-command argument validators (`git push`, `find -delete`, `tar -x`, publish flags, …) | audit only | enforced | enforced |
| Structural checks (coprocesses, `<>`, protected env assignments, shells in wrapped position) | audit only | enforced | enforced |
| OS sandbox writes | off | `$HOME` writable; deny lists masked | project + configured paths |

**`denylist` assumes a cooperative agent.** It stops mistakes an agent makes on
its own (`find ~`, `cat $HOME/.aws/config`, `rm -rf ..`, `> ~/.bashrc`, an
accidental `git push`) and, under the OS sandbox, hides credentials from the
programs it starts. It does not stop an agent steered by content it read
(prompt injection) from running a script that opens a file whose path the AST
layer never saw, unless the OS sandbox masks that file. It also doesn't block
network tools, so anything readable can be exfiltrated. **`allowlist` is the
mode for untrusted input**: unlisted programs, network tools, and runtimes are
blocked, and the OS sandbox confines writes to the project.

The command whitelist is the layer that breaks developer workflows
(`python3`, `npm`, `make`, and `./script` aren't on it), so it's the one
`denylist` drops. The path boundary still applies to every command's
arguments, listed or not, so `python3 ~/other/x.py` is rejected in `denylist`
mode as out of scope.

Dropping the whitelist is why the **command deny list** is needed. If any
program can run, `lite-sandbox config mode set open` can too, and since the
config is hot-reloaded it would disable enforcement for the next command. The
built-in entries deny the sandbox's own policy-editing subcommands (`config`,
`install`, `update`, `hook`) at the validation layer, whether or not the OS
sandbox (which mounts the same files read-only in `denylist` mode) is enabled.
A `commands` entry with `allow: false` adds to the list; see
[Denied commands](configuration.md#denied-commands).

## Static preflight (AST-level, before execution)

1. **Command deny list**: invocations matching a denied command (see above) are refused before any other command gate. No allowed command, `no_sandbox` or not, lifts this check. It is re-applied at the runtime layer and inside command wrappers.
2. **Command whitelist**: only explicitly allowed, non-destructive commands can run (e.g. `cat`, `ls`, `grep`, `find`). Code execution runtimes, networking tools, package managers, and shell escape commands are blocked. More commands can be allowed in the config.
3. **Argument validation**: per-command validators block dangerous flags (e.g. `find -exec`, `tar -x`, `git push`). Write commands (`cp`, `mv`, `rm`, `sed`, etc.) are allowed but their paths are validated.
4. **Structural restrictions**: coprocesses and read-write redirections (`<>`) are blocked. Dynamic command names (e.g. `$CMD ...` or `$(...)` in command position) can't be resolved statically, so they are deferred to the runtime layer, which re-checks the whitelist and re-runs the per-command argument validators on the fully expanded argv (see below). Dynamic command names are still rejected inside command *wrappers* (`env`, `xargs`, `find -exec`, `timeout`, `rg --pre`), because the wrapper spawns the child itself and it never passes back through the interpreter. Process substitutions (`<(...)`) are allowed, and every command nested inside them is checked against the same whitelist.
5. **Static path validation**: literal path-like arguments (including paths embedded in flags like `-f/path` and `--file=/path`) are resolved to absolute paths, following symlinks, and checked against the allowed directories (by default, the cwd). Access to `.git` directories is blocked.

## Runtime validation (interpreter-level, during execution)

Commands run in the [mvdan.cc/sh/v3](https://pkg.go.dev/mvdan.cc/sh/v3) shell interpreter, not `bash -c`, which allows validation after variable expansion:

6. **Expanded path validation**: a `CallHandler` intercepts every command after variable and command substitution expansion and checks that all resolved path arguments are within the allowed directories. This catches cases like `cat $HOME/secret` that static analysis can't resolve.
7. **Redirect path validation**: an `OpenHandler` intercepts all file opens from redirections (e.g. `< $FILE`, `> $OUTPUT`) and validates the expanded paths before any I/O.
8. **Expanded command validation**: the whitelist and per-command argument validators are re-applied to the fully expanded argv. The `CallHandler` runs for every command *before* the interpreter decides whether it is a builtin, function, or external, and enforces the whitelist for builtins (externals are left to the `ExecHandler`). The `ExecHandler` runs only for external commands and re-runs both the whitelist check and the argument validator. This is what makes dynamically-named commands safe (e.g. `$CMD push` resolving to `git`), since their real name and arguments are only known at runtime. `bash`/`sh`/`awk` skip the re-run because they are dispatched to dedicated executors that re-parse and re-validate their contents through the interpreter.
9. **Python OS-call validation**: `python`/`python3` are dispatched to an embedded Python interpreter (monty) instead of being executed. It does no I/O itself: every filesystem operation suspends the interpreter and returns to the host as a typed OS call, which is checked against the same read/write path sets as bash before it is performed. See [Python](#python-monty) below.

## OS-level sandboxing (optional)

An optional OS-level sandbox adds isolation on top of AST-level validation, using each platform's native mechanism:

- **Linux**: [bubblewrap](https://github.com/containers/bubblewrap) via Linux namespaces
- **macOS**: `sandbox-exec` with dynamically generated SBPL profiles

**Architecture:**
- **Long-lived worker**: one sandboxed process accepts gob-encoded commands over stdin/stdout and runs many commands without restarting the sandbox
- **Automatic recovery**: a dead worker is detected and replaced
- **Die-with-parent**: the worker is killed if the MCP server exits

**Configuration:**

Enable it in the config file (Linux: `~/.config/lite-sandbox/config.yaml`, macOS: `~/Library/Application Support/lite-sandbox/config.yaml`):

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
check fails, since with `os_sandbox: true` and no working backend every command
fails. The error names what to install.

### Common isolation (both platforms)

The two backends use different mechanisms (bubblewrap mounts vs. SBPL rules) but
enforce the same policy:

- **Writes confined to the working directory (`allowlist` mode)**: the only writable locations are the working directory (and its resolved symlink), the paths granted `write: true` in the config's `paths` list, the Claude Code per-user scratchpad root (`/tmp/claude-<uid>`), the per-user system temp dir (`$TMPDIR`, e.g. macOS's `/var/folders/.../T`, when it isn't the shared `/tmp`), the main worktree when `git.allow_worktree_parent` is enabled and the working directory is a linked worktree, and the temp dirs. Everything else on the host is read-only. These grants are baked into the sandbox profile when the worker starts, so any config change restarts the worker and the new policy applies from the next command.
- **`$HOME` writable, deny lists masked (`denylist` mode)**: the home directory is bound writable so tool caches and state don't need to be listed, and the built-in [deny lists](configuration.md#denials-read-false-write-false-denylist-mode) are applied on top. Read-denied paths are made unreadable (a `--perms 000` tmpfs over directories and an empty mode-000 file over files on Linux; SBPL `deny file-read*` on macOS). Write-denied paths are bound read-only over themselves (`deny file-write*`). Everything outside `$HOME` stays read-only as in `allowlist` mode. The masks are applied after every bind, so neither the home bind nor an overlapping `write: true` grant can re-expose them. The only way to drop a built-in entry is a `paths` grant on that exact path (see [lifting a built-in denial](configuration.md#lifting-a-built-in-denial)). A read-denied path is also write-denied, so nothing can be planted there for the host user to pick up later. **Linux caveat:** bubblewrap can only mount over a path that exists, and it creates missing mount points on the host. A missing deny-listed *directory* is therefore created (mode 0700) before being masked. A missing deny-listed *file* (say, a `~/.zshrc` that was never written) is left alone, because an empty `~/.bash_profile` appearing on the host would change the user's shell, so it isn't protected until it exists. `lite-sandbox config mode show` marks these. sandbox-exec doesn't have this gap: its deny rules apply whether or not the path exists. The lists are evaluated when the worker starts, and every config change restarts it.
- **Writable temp directories**: `/tmp` and the platform's other temp directories are writable, as build caches and `TMPDIR` require.
- **Runtime bind mounts**: enabled runtimes get extra writable paths (e.g. `$GOPATH`/`$GOCACHE` for Go, the fvm SDK cache and pub cache for Flutter, or `uv cache dir`/`uv python dir` for uv).
- **Internal paths**: `paths` entries with `internal: true` loosen only the OS sandbox, so programs a command spawns can reach their own data (e.g. a tool's `~/.cache` directory). No agent-facing boundary honors them: static/runtime path validation still denies direct reads and writes, the PreToolUse file-tool hook and the docker proxy's bind-mount checks ignore them, and Deno's auto-injected `--allow-read`/`--allow-write` never include them (otherwise Deno-executed code could use them to escape the sandbox). An overlapping internal grant (`~`, say) can't re-expose the credential masks; only a grant on the masked path itself lifts one, which is how a spawned `ssh` gets its keys (`paths allow ~/.ssh --internal`).
- **Network**: left intact.
- **Process execution**: spawning subprocesses is allowed; enforcement is at the filesystem level.
- **Credential masks (every mode)**: two built-in deny-list entries apply in every mode, not only `denylist`. SSH **private** keys in `~/.ssh` can't be read (one entry per key file; `known_hosts`, `config`, `authorized_keys`, and `*.pub` files stay accessible), and `~/.aws` can't be read when AWS IMDS mode is configured (`aws.force_profile`; see [AWS & Docker access](aws-and-docker.md)). They are ordinary entries of the built-in path list, so `lite-sandbox config mode show` lists them in every mode, and a `paths` grant on `~/.ssh` (or one key) or on `~/.aws` lifts them as an explicit, visible opt-out.

### Linux (bubblewrap)

Commands run in a lightweight container using Linux namespaces. In addition to
the common policy above, the Linux backend has:

- **Read-only root filesystem**: the whole host filesystem is mounted read-only, with the writable paths bind-mounted back in.
- **Fresh /dev and /proc**: new device and process filesystems, so host state isn't exposed.
- **Namespace isolation**: all namespaces except the network are unshared (`--unshare-all --share-net`), and the worker is killed if the server exits (`--die-with-parent`).

**Requirements:**
- A Linux kernel with unprivileged user namespaces
- bubblewrap, from your package manager (e.g. `apt install bubblewrap`, `pacman -S bubblewrap`)
- On some systems, unprivileged user namespaces must be enabled:
  ```bash
  # Check if enabled (should be 1)
  sysctl kernel.unprivileged_userns_clone

  # Enable temporarily
  sudo sysctl -w kernel.unprivileged_userns_clone=1

  # Enable permanently (add to /etc/sysctl.conf)
  kernel.unprivileged_userns_clone=1
  ```

### macOS (sandbox-exec)

Commands run under a generated SBPL (Scheme-based Profile Language) profile via
`sandbox-exec`, which is built into macOS. In addition to the common policy
above, the macOS backend has:

- **Signal confinement**: the profile denies signaling processes outside the worker's own process group, so a sandboxed `kill`/`pkill` can't reach host processes.

**Relationship to AST validation:**

The OS sandbox does not replace AST validation; the two layers work together:
- If a dangerous command gets past AST validation, the filesystem restrictions still prevent writes outside the working directory.
- Disallowed commands, including any nested inside process or command substitutions, are blocked at the AST level before they reach the OS sandbox.

## Python (monty)

`python` and `python3` don't run an interpreter from the host. They are served
by [monty](https://github.com/pydantic/monty), a Python interpreter compiled to
WebAssembly, embedded in the lite-sandbox binary, and run in-process via wazero.

**Python file I/O uses the same path sets as bash.** monty has no filesystem
access of its own. When Python touches a file, the interpreter suspends and
hands the host a typed OS call. The host checks the path against the readable
set (reads) or writable set (writes) with the same `checkPathBoundary` that the
bash `CallHandler` and `OpenHandler` use, including the `.git` exclusion, and
only then performs it. Python has no separate path policy.

**monty's own isolation is stronger than the AST-level boundary around it.**
Inside the wasm sandbox there is no network, no environment (`os.environ` is
always empty, so masked credentials can't be read back), no ambient filesystem,
no subprocess execution, and no way to reach a syscall except through the host
callback described above. The AST layer's known weaknesses (glob expansion,
flag-parsing ambiguity, wrappers) don't apply, because there is no argv to
misparse: the boundary is enforced on each file operation, on the fully
resolved path.

`python`/`python3` are also refused in *wrapped* position (as the child of
`xargs`, `env`, `timeout`, or `find -exec`), as `bash`, `sh`, and `awk` are
(see `subCommandDenylist`). Commands are dispatched to monty only when the
sandbox interpreter is the direct caller. A wrapper spawns its child as a
native process, which would find the real CPython on `$PATH` and run it outside
every layer of the sandbox.

A `commands` allow entry for `python`/`python3` (with or without `no_sandbox`)
opts back in to the real interpreter for matching invocations, losing
validation as any allowed command does. A *bare* entry also lifts the
wrapped-position refusal above, since refusing the wrapped form protects
nothing once the host interpreter can run unwrapped. A subcommand-restricted
entry does not, because a wrapper's argv is never checked against the
restriction.

Other details:

- **A denial ends the run.** The host returns an error that Python can't catch,
  so a script can't retry in a loop to probe the boundary. The one host error a
  script *can* catch is a `FileNotFoundError` from `open()` on a missing path
  inside the boundary. That isn't a denial: the path was allowed, and CPython
  reports the same thing.
- **`open()` adds no reach.** monty implements real file objects but holds no
  file descriptor. It builds one from a handle the host returns for the `open`
  OS call, and every read or write on that object arrives as one of the
  ordinary OS calls checked above. The `open` handler itself only performs the
  open-time effect of the mode (truncate for `"w"`, create for `"a"`, an
  existence check for `"r"`), checked against the writable set for the first
  two and the readable set for the last. So `open()` has the same bounds as
  `pathlib`, with no second code path.
- **A prologue is prepended when a program uses `sys.argv`,** because monty
  doesn't provide it. It defines a shim object holding the argument strings and
  rewrites statements that would rebind `sys` back to the real module. The
  rewrite only ever adds an assignment to that shim, so it can't widen what
  Python can reach. Programs that never mention `argv` are passed through
  unchanged.
- **The host-side file operations aren't covered by the OS sandbox.** monty
  runs in the MCP server process, not in the bwrap/sandbox-exec worker, so the
  reads and writes behind its OS calls happen outside the worker. They are
  performed through `os.Root` (openat2-rooted on Linux) instead, so the kernel
  confines path resolution to the allowed directory and a symlink swapped
  between the check and the open can't redirect it. monty's upstream mount
  implementation uses the same primitive.

Each run is also bounded by the command timeout, a memory cap, a recursion
limit, and a cap on host calls per run. The last one catches a script that
loops on filesystem operations, since time spent in host calls doesn't count
toward the interpreter's own duration accounting.

## Known Limitations

This is a lightweight, best-effort sandbox based on static analysis. It is **not** a security boundary equivalent to containers, VMs, or seccomp. Known bypasses and limitations:

### Path validation bypasses

- **Glob expansion**: glob patterns are validated as literal strings (e.g. `cat ./*.txt` checks the prefix `./`), but the interpreter expands them at runtime. A glob rooted inside the allowed directory can't expand outside it, provided the allowed directory contains no adversarial symlinks.
- **Multi-char short flag ambiguity**: for short flags like `-la`, the extractor assumes a single-char flag plus value (extracting `a`). This doesn't cause false negatives for `-la`, since `a` alone fails the `looksLikePath` check, but a combined flag like `-abc/etc/passwd` is checked as `bc/etc/passwd`, missing the leading character.

### Command validation limitations

- **Per-command argument validation**: some whitelisted commands have dangerous flags, which argument validators block. For `find`, `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`, `-fls`, `-fprint`, `-fprint0`, and `-fprintf` are blocked. Other commands, like `xxd -r`, can write files when combined with redirections (though redirections are blocked).
- **Command wrappers**: commands that run another program as a child (`xargs`, `find -exec`, `env`, and `timeout`) are validated recursively. The wrapped command and its arguments are checked against the whitelist and its own argument validator as if invoked directly, so a wrapper can't be used to sneak a blocked command past validation (e.g. `env curl …`, `timeout 5 sh -c …`). `env -S`/`--split-string` is rejected outright because it builds an argument vector from a single string. `bash`, `sh`, `awk`, and `time` are refused in wrapped position, since their safety depends on the interpreter being their direct caller.
- **No syscall-level enforcement**: there is no runtime syscall filtering (no seccomp). A command that is allowed and passes AST validation runs with whatever permissions the environment grants. The optional OS sandbox adds filesystem isolation, so even a dangerous command that gets past AST validation can't write outside the working directory.
- **Python is a subset**: monty implements a subset of Python and can't import third-party packages, so the sandbox's `python3` isn't a drop-in for CPython. Real CPython is available through the uv runtime (`uv run`), where the OS sandbox provides confinement instead of monty. Where the subset differs silently, a program written for CPython can produce a plausible wrong answer instead of an error. For that reason, `runtimes.montypython.inline_only` limits monty to code the agent writes inline and refuses a project's own `.py` files.
- **The deny list is a gate, not a boundary**: it is enforced at the same validation layers as everything else, so it stops an agent from *invoking* a denied command, not a running program from doing the same work itself. With the OS sandbox off, a denied `lite-sandbox config` doesn't stop `perl -e` from writing the config file directly, because no path argument reaches the AST layer. The OS sandbox's read-only mount of the config and the agents' settings (`denylist` mode) closes that gap; the two are meant to be used together.
- **Bash builtins**: some allowed builtins like `set`, `export`, and `trap` can change shell state for later commands in the same invocation.

### General limitations

- **Not a complete security boundary**: the AST-level sandbox limits an LLM's access to the host as one layer of defense. Don't rely on it alone for untrusted workloads. The optional OS sandbox adds filesystem isolation but still shares the network namespace and has no seccomp-level syscall filtering. For maximum isolation of untrusted workloads, use VMs.
- **Interpreter differences**: commands run in the mvdan.cc/sh interpreter, not GNU bash. It supports standard POSIX and bash features, but some GNU bash extensions may behave differently.
- **Allowed commands bypass validation** (except the deny list): commands allowed by a `commands` entry (`allow: true`) run without argument validation; only the deny list still applies. Bare entries (a single token, e.g. `curl`) also skip bash AST parsing: the whole command string is handed to real bash. With the OS sandbox enabled, that bash runs inside the sandbox worker, so filesystem confinement (write restrictions, masked paths) still applies. Without the OS sandbox there is no confinement at all. Only add commands you trust.
- **Unsandboxed commands bypass validation *and* the OS sandbox**: an allow with `no_sandbox: true` is parsed like any other allow, but matching invocations always run directly on the host, outside the OS sandbox worker. They get **no** filesystem confinement, masked-path protection, or docker filtering proxy, even when the OS sandbox is enabled. Use it only for fully trusted commands that can't run confined (e.g. `docker` talking to the real daemon). The deny list still applies: a denied invocation is refused before routing is decided.
