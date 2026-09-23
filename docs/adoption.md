# Incremental adoption: opting out, then tightening back

A fresh install runs in **allowlist** mode: only whitelisted commands run,
code-execution runtimes are opt-in, and the OS sandbox (when enabled) confines
writes to the project. That suits untrusted input, but it also means the first
session on a new project can stall on `npm test` or `python3`.

This page describes the alternative: start loose, record what the sandbox
would have blocked, and tighten once the report shows it's cheap to. The
defaults don't change; you opt out explicitly. `lite-sandbox install` routes
the agent's shell through the sandbox once, and after that the mode is a
one-line config change that applies without a restart.

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
| Denied commands (`commands` entries with `allow: false`, incl. the sandbox's own `config`/`install`/`update`/`hook`) | run | blocked | blocked |
| Path arguments and redirections outside the project | run | blocked | blocked |
| `git push`, `pnpm publish`, `find -delete`, `tar -x`, … | run | blocked | blocked |
| Network tools (`curl`, `wget`, `nc`) | run | run | blocked |
| OS sandbox writes | off | `$HOME` writable, deny lists masked | project dir + configured paths only |
| Assumes | evaluating | a cooperative agent | untrusted input |

**`open`** enforces nothing; every command runs as written. With
`audit: true`, each finding is still recorded along with the modes that would
have blocked it, so a day of normal work shows what `denylist` and `allowlist`
would cost. Use it for evaluation or for a repo you're still learning. The
installer never picks it for you.

**`denylist`** turns off the command whitelist, so developer tooling works
without configuration. It still enforces scope and protects shared state:

- Every path argument, redirection, and file open, for any command, must
  resolve inside the working directory or a path granted in `paths`.
  `find ~`, `grep -r secret $HOME`, `rm -rf ..`, and `> ~/.bashrc` are
  rejected, including after variable expansion.
- The per-command validators still apply: `git push` (unless
  `git.remote_write`), `pnpm publish`, `cargo publish`, `find -delete`,
  `tar -x`, `find -exec`, and the other blocked flags.
- The [command deny list](configuration.md#denied-commands) still applies and
  overrides every allowed command. Its built-in entries stop the agent from
  running the sandbox's own `config`/`install`/`update`/`hook` subcommands to
  loosen the policy. `lite-sandbox config commands list` prints the effective
  list.
- Under the OS sandbox, `$HOME` is writable so caches and tool state work,
  minus a built-in [deny list](configuration.md#denials-read-false-write-false-denylist-mode):
  credential stores are hidden, and shell rc files, persistence locations, and
  the agents' and lite-sandbox's own config are read-only.
  `lite-sandbox config mode show` prints the effective lists.

This mode assumes a cooperative agent: one that follows the constraints it's
told about and doesn't write a script to get around a denial. The deny lists
are enforced at the validation layer, so a program the agent starts is
confined only by the OS sandbox. That's why `mode set denylist` turns the OS
sandbox on when it can, and tells you when it can't. It does *not* protect
against prompt injection, where content the agent reads tells it to escape:
`denylist` won't stop a Python one-liner from reading a file whose path the
AST layer never saw, unless the OS sandbox masks that file.

**`allowlist`** is the default and where incremental adoption ends up. The
cost is configuration: a new project usually needs a few `runtimes … enable`
or `commands allow` lines, and the audit report tells you which ones in
advance.

## Audit: tighten with evidence

`audit: true` works in every mode. Each finding is appended to a JSONL log
(`lite-sandbox audit path`) with the rule that fired, the subject (a command
name or resolved path), whether it was blocked, and `would_block_in`, the
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
     28  lite-sandbox config commands allow npm
         "npm" is not on the allowlist
     11  lite-sandbox config runtimes go enable
         "go" needs the go runtime
      3  lite-sandbox config paths allow /work/shared-lib
         paths under this directory were outside the boundary
```

In `denylist`, the report shows what the agent hits today (blocked) and what
would break under `allowlist` (would-block). Apply the suggestions before
switching and nothing breaks. In `allowlist` the report is a friction log; in
`open` it covers everything.

The agent isn't told about findings. Telling it changes its behavior, and
you'd be auditing the nudged agent instead of the baseline. If you want the
agent to see denials, use `denylist`.

The suggestions come from what the agent attempted, so the agent effectively
decides what ranks highest. Review them before applying. The report never
suggests `commands allow` for privilege, network, or shell commands, never
suggests widening the boundary to your home directory, a deny-listed path, or
a system directory, and never suggests lifting a denied command. It notes
that a bare allow entry skips validation entirely.

Only the MCP server and the PreToolUse hook write the log; sandboxed commands
can't. The file is created `0600` because command strings can contain inline
secrets. Its size is capped (oldest records are dropped), and
`lite-sandbox audit clear` resets it.

## The workflow

1. **Install.** `lite-sandbox install` configures the agents and creates the
   sandbox config with only `audit: true`, so you're in `allowlist` mode with
   findings logged. If you want strict, you're done.
2. **Opt out.** To start loose, switch to `denylist`:

   ```bash
   lite-sandbox config mode set denylist     # or: lite-sandbox install --mode denylist
   ```

   If `os_sandbox` was never set and bubblewrap (Linux) or sandbox-exec
   (macOS) passes a preflight check, this also turns on the OS sandbox, which
   is what enforces the deny lists on programs that commands start. On Linux
   without bubblewrap, the command says what to install, and `denylist` runs
   on the AST layer alone until you enable it. Use `open` instead to observe
   with nothing enforced.
3. **Work.** Agents rarely notice `denylist`. When they do hit a denial, it
   names the config change that allows it.
4. **Read the report.** After a few days, `lite-sandbox audit report` lists
   what `allowlist` would block and the lines that would allow it.
5. **Opt back in.** Apply the suggestions and switch back:

   ```bash
   lite-sandbox config mode set allowlist
   ```

   Or set the mode per directory, keeping `allowlist` everywhere except a
   repo you're still learning. `lite-sandbox config mode set denylist --dir
   ~/work/new-repo` writes the override, and `lite-sandbox audit report --cwd
   ~/work/new-repo` reads only that repo's findings:

   ```yaml
   mode: allowlist
   overrides:
     - path: ~/work/new-repo
       mode: denylist
     - path: ~/scratch/experiments
       mode: open           # observe only
   ```

The MCP server reloads the config whenever it changes, so none of these steps
needs a restart. `lite-sandbox config mode show` prints the effective mode
and, in `denylist`, the active deny lists.
