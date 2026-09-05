# Incremental adoption: opting out, then tightening back

lite-sandbox's defaults are strict. A fresh install runs in **allowlist** mode:
only whitelisted commands run, code-execution runtimes are opt-in, and the OS
sandbox (when enabled) confines writes to the project. That is the right
posture for untrusted input, and it is also the one that makes a first session
on a new project stall on `npm test` or `python3`.

This document describes the alternative for teams that would rather start
loose and tighten with evidence. Nothing here changes the defaults: you opt
out of strictness explicitly, watch what the sandbox would have blocked, and
opt back in when the report says the cost is low. Install once, which routes
the agent's shell through the sandbox; from then on the posture is a one-line
config change that takes effect without a restart.

```yaml
# lite-sandbox config path
mode: denylist      # open | denylist | allowlist   (default when unset: allowlist)
audit: true         # log findings for `lite-sandbox audit report`
os_sandbox: true    # bubblewrap / sandbox-exec worker
```

## The three modes

| | `open` | `denylist` | `allowlist` |
|---|---|---|---|
| Unlisted programs (`python3`, `npm`, `make`, `./script`) | run | run | blocked; runtimes opt-in |
| Path arguments and redirections outside the project | run | blocked | blocked |
| `git push`, `pnpm publish`, `find -delete`, `tar -x`, … | run | blocked | blocked |
| Network tools (`curl`, `wget`, `nc`) | run | run | blocked |
| OS sandbox writes | off | `$HOME` writable, deny lists masked | project dir + configured paths only |
| Assumes | evaluating | a cooperative agent | untrusted input |

**`open`** enforces nothing. Every command runs exactly as the agent wrote it.
Its only job is observation: with `audit: true`, every finding is still
recorded together with the modes that would have blocked it, so a day of
normal work produces a report of what `denylist` and `allowlist` would cost.
Pick it deliberately, for evaluation or for a repo you are still learning; the
installer never chooses it for you.

**`denylist`** is the opt-out for incremental adoption. The command whitelist
is off, so developer tooling works without configuration. What stays enforced
is *scope* and *shared state*:

- Every path argument, redirection, and file open — of any command, listed or
  not — must resolve inside the working directory plus `readable_paths` /
  `writable_paths`. `find ~`, `grep -r secret $HOME`, `rm -rf ..`,
  `> ~/.bashrc` are all rejected, including after variable expansion.
- The per-command validators still apply: `git push` (unless
  `git.remote_write`), `pnpm publish`, `cargo publish`, `find -delete`,
  `tar -x`, `find -exec` and the other flags the sandbox has always blocked.
- Under the OS sandbox, `$HOME` is writable so caches and tool state just
  work, and a built-in deny list is carved out: credential stores are hidden
  (`~/.aws`, `~/.gnupg`, `~/.netrc`, `~/.kube`, the agents' own auth files,
  SSH private keys) and persistence and self-protection paths are read-only
  (shell rc files, `~/.gitconfig`, `~/.ssh`, the agent settings that hold the
  Bash deny, and lite-sandbox's own config). `lite-sandbox config mode show`
  prints the effective lists; extend them with `denied-read-paths add` /
  `denied-write-paths add`.

This mode assumes the agent is cooperative: it follows the constraints it is
told about and does not write a script to route around a denial. That matches
observed behavior for agents working on a developer's own code. It does *not*
hold against prompt injection, where content the agent reads instructs it to
escape; `denylist` will not stop a Python one-liner that reads a file the
AST layer never saw a path for, unless the OS sandbox masks that file.

**`allowlist`** is the default. Only whitelisted commands run, code-execution
runtimes are opt-in per language, network tools are blocked, and the OS sandbox
confines writes to the project. This is the posture for untrusted input, and
where the incremental path ends up. Its cost is configuration: the first
session on a new project usually needs a few `runtimes … enable` or
`extra-commands add` lines, which is exactly what the audit report tells you
in advance.

## Audit: tighten with evidence

`audit: true` works in every mode. Each finding is appended to a JSONL log
(`lite-sandbox audit path`) with the rule that fired, the subject (a command
name, a resolved path), whether it was blocked, and `would_block_in`, the
modes that enforce that rule. The report reads it back:

```bash
lite-sandbox audit report --since 7d
```

```
Blocked in the current mode (friction now):
  path_boundary        3

Not blocked, but would be in a stricter mode (cost of stepping up):
  allowlist            41

Suggested config changes (most findings first):
     28  lite-sandbox config extra-commands add npm
         "npm" is not on the allowlist
     11  lite-sandbox config runtimes go enable
         "go" needs the go runtime
      3  lite-sandbox config readable-paths add /work/shared-lib
         paths under this directory were outside the boundary
```

In `denylist` the report splits into two questions: what is the agent hitting
today (blocked), and what would break if you switched to `allowlist`
(would-block). Apply the suggestions, switch, and the transition costs nothing.
In `allowlist` it is purely a friction log. In `open` it is the whole picture.

Findings are silent to the agent. Telling the agent "this would have been
blocked" changes its behavior and you would be auditing the nudged agent
rather than the baseline; if you want the nudge, that is what `denylist` is.

The suggestions are derived from what the agent attempted, which means the
agent also decides what ranks highest. Treat them as proposals to review. The
report never proposes privilege, network, or shell commands for
`extra-commands add`, never proposes widening the boundary to your home
directory, a deny-listed path, or a system directory, and notes that a bare
`extra_commands` entry skips validation entirely.

The log is written by the MCP server and the PreToolUse hook, never by
sandboxed commands, and is created `0600`, since command strings can carry
inline secrets. It is capped in size (oldest records dropped) and
`lite-sandbox audit clear` resets it.

## The workflow

1. **Install.** `lite-sandbox install` configures the agents and creates the
   sandbox config with `audit: true` and nothing else, so you are in
   `allowlist` mode with findings being logged. Stop here if strict is what
   you want.
2. **Opt out.** To start loose, switch to `denylist`:

   ```bash
   lite-sandbox config mode set denylist     # or: lite-sandbox install --mode denylist
   ```

   This also turns on the OS sandbox when bubblewrap (Linux) or sandbox-exec
   (macOS) passes a preflight check and `os_sandbox` was never set, because
   the OS layer is what holds the deny lists against programs commands start.
   On Linux without bubblewrap the command says so and what to install;
   `denylist` then runs on the AST layer alone until you enable it. Use `open`
   instead when you want to observe with nothing enforced at all.
3. **Work.** Agents rarely notice `denylist`. When one does, the denial names
   the config change that widens it.
4. **Read the report.** After a few days, `lite-sandbox audit report` lists
   what `allowlist` would block and the exact lines to allow it.
5. **Opt back in.** Apply the suggestions and switch back:

   ```bash
   lite-sandbox config mode set allowlist
   ```

   Or do it per directory, keeping strict where it matters most while a new
   repo is still being learned (`lite-sandbox config mode set denylist --dir
   ~/work/new-repo` writes the override; `lite-sandbox audit report --cwd
   ~/work/new-repo` reads only that repo's findings):

   ```yaml
   mode: allowlist
   overrides:
     - path: ~/work/new-repo
       mode: denylist
     - path: ~/scratch/experiments
       mode: open           # observe only
   ```

The MCP server reloads the config on every change, so none of these steps
needs a restart. `lite-sandbox config mode show` prints the effective mode and,
in `denylist`, the deny lists in force.
