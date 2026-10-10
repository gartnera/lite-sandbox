# Configuration

The config file location depends on the platform (`lite-sandbox config path`
prints it):

- **Linux**: `~/.config/lite-sandbox/config.yaml`
- **macOS**: `~/Library/Application Support/lite-sandbox/config.yaml`

Changes are picked up automatically; the server doesn't need a restart.

## Mode and audit

```yaml
mode: denylist      # open | denylist | allowlist   (default when unset: allowlist)
audit: true         # record validation findings (default: false)
```

`mode` sets what is enforced: `open` enforces nothing, `denylist` drops the
command whitelist but keeps the path boundary, validators, and
[deny lists](#denials-read-false-write-false-denylist-mode), and `allowlist`
(the default) enforces everything. See [Adoption](adoption.md#the-three-modes)
for what each mode blocks.

`audit: true` appends every validation finding, blocked or not and tagged with
the modes that would block it, to `lite-sandbox audit path` for
`lite-sandbox audit report`. CLI:

```bash
lite-sandbox config mode show                 # effective mode, audit, deny lists
lite-sandbox config mode set denylist
lite-sandbox config mode set denylist --dir ~/work/new-repo   # one directory only
lite-sandbox config audit enable|disable|show
lite-sandbox audit report [--since 7d] [--cwd ~/work/new-repo] [--json]
lite-sandbox audit clear
```

`mode` and `audit` can be set per directory with
[overrides](#per-directory-overrides), so one repo can run `allowlist` while
everything else runs `denylist`. `mode set --dir` writes such an override, and
`audit report --cwd` limits the report to sessions started in that directory.

## Commands

The command whitelist decides what runs in `allowlist` mode, and a built-in
deny list refuses the sandbox's own policy-editing subcommands in every
enforcing mode. Everything else about commands goes in the `commands` list:
what is allowed beyond the whitelist, what runs on the host instead of inside
the OS sandbox, what waits for your approval each time, and what is always
refused. Each entry is a command plus a tri-state `allow` and/or `prompt`:

```yaml
commands:
  - command: curl                  # allowed past the whitelist     (was extra_commands)
    allow: true
  - command: uv run pyright        # only invocations whose leading arguments match
    allow: true
  - command: docker                # allowed, and runs on the host  (was unsandboxed_commands)
    allow: true
    no_sandbox: true
  - command: sudo                  # refused however else it is allowed (was denied_commands)
    allow: false
  - command: gh auth               # only invocations starting with those arguments
    allow: false
  - command: lite-sandbox update   # an allow on a built-in denial lifts it (was "-lite-sandbox update")
    allow: true
  - command: rm                    # asks you before each invocation, then validates it as usual
    prompt: true
  - command: git push              # asks you before each invocation, then allows it
    allow: true
    prompt: true
```

`command` is a bare name, or a name followed by the leading non-flag arguments
the entry applies to; extra whitespace between words is ignored. Each command
has one entry, so `allow`, `prompt` and `deny` on the CLI replace whatever
the config said about it before.

```bash
lite-sandbox config commands allow curl "uv run pyright"
lite-sandbox config commands allow docker --no-sandbox
lite-sandbox config commands deny sudo "gh auth"
lite-sandbox config commands prompt rm curl                  # ask before each invocation
lite-sandbox config commands allow "git push" --prompt       # ask, then allow
lite-sandbox config commands allow "lite-sandbox update"     # lifts the built-in denial
lite-sandbox config commands list                            # built-in denials included
lite-sandbox config commands remove curl
```

### Allowed commands

`allow: true` admits a command the whitelist doesn't list. This matters in
`allowlist` mode; in `denylist` and `open` mode every command can already run,
so there it mostly just selects the raw-bash path described next. A **bare**
entry (a single token) allows the command with any arguments. When it is the
leading command of an invocation, bash AST parsing is skipped and the whole
command string runs in real bash. An entry with arguments (e.g.
`uv run pyright`) allows only invocations whose leading non-flag arguments
match, and those still go through normal parsing and validation. When the
[OS sandbox](security.md#os-level-sandboxing-optional) is enabled, bare
entries run inside it like every other command, so filesystem confinement
still applies even though validation is skipped.

### Unsandboxed commands

`no_sandbox: true` on an allow works the same way (same bare and restricted
forms, same validation bypass), except matching invocations always run
**directly on the host**, outside the
[OS sandbox](security.md#os-level-sandboxing-optional) worker
(bwrap/sandbox-exec) even when it is enabled. It's an escape hatch for trusted
commands that can't run confined.

```yaml
commands:
  - command: docker            # talk to the real docker daemon, not the filtering proxy
    allow: true
    no_sandbox: true
  - command: ./scripts/deploy.sh
    allow: true
    no_sandbox: true
```

These commands also bypass the docker filtering proxy: the proxy's
`DOCKER_HOST` override isn't applied, so `docker` reaches the real daemon (or
whatever `DOCKER_HOST` the host environment sets). A restricted entry
unsandboxes only matching invocations; e.g. `git push` leaves other `git`
subcommands confined.

### Prompted commands

`prompt: true` makes each matching invocation wait for your approval: the
agent shows its permission prompt with the whole command, and the command runs
only if you approve. Use it for commands you want to see before they run
rather than allow or refuse outright.

- **On its own**, an approved invocation counts as whitelisted. A command off
  the whitelist (`curl`) runs once you approve it, and a whitelisted one
  (`rm`) now asks first; either way its argument validators and path checks
  still apply, so an approved `rm` outside the project is still refused.
- **With `allow: true`**, the allow takes effect once you approve: the
  invocation gets everything the allow gives (a bare one's raw-bash path, a
  restricted one's validator bypass, `no_sandbox`). `git push` with
  `allow: true` and `prompt: true` asks before every push, which `git`'s
  argument validator would otherwise refuse. A prompted allow of a built-in
  denial's text (`lite-sandbox update`) lifts it the same way, asking each
  time.
- **A denial can't prompt**: a denied command never runs.

Entries match like [denials](#denied-commands): by base name, and a restricted
entry (`gh pr`) wherever the subcommand could start. Prompts are enforced in
`denylist` and `allowlist` mode; in `open` mode, like every rule, a match is
only recorded to the audit log.

The approval is given for **one bash tool call**, the command line you were
shown, and it works the way [config requests](#config-requests-the-agent-runs-lite-sandbox-config-with-your-approval)
do. The PreToolUse hook finds the prompted commands in the call, checks the
call would pass validation once approved (a call the sandbox would refuse
anyway is denied with that error instead of being put to you), records a
single-use ticket for the exact command in lite-sandbox's cache directory, and
answers `ask`. The MCP server takes the ticket before running the call; with
no ticket it refuses every prompted invocation in it. So a prompted command is
refused when the hook can't see it in the command line:

- a command named through a variable or substitution (`$CMD`), or inside a
  `bash -c` string the hook doesn't read;
- a command run by a script file (`./build.sh`, `bash build.sh`): the approval
  covers the command line, not the commands of a file you weren't shown;
- a command run by a wrapper (`find -exec`, `xargs`, `env`, `timeout`,
  `xcrun`), which is refused even in an approved call: run it on its own.

Only Claude Code, set up by `install claude` or `launch claude`, puts the
`ask` to you (the hook is registered with `--config-requests`, and with
`--ask` in `--bash-ast-hook-mode`, where the built-in Bash tool runs the
command once you approve, so no ticket is needed). Codex, opencode, Crush and
Grok Build can't ask, so for them a prompted command is refused, as if
denied. In a non-interactive `claude -p` run nobody can answer the prompt, so
Claude Code denies the call.

### Denied commands

`allow: false` entries form a deny list. It is
checked before every command gate (static, runtime, and wrapped: `env`,
`xargs`, `timeout`, `find -exec`). In `denylist` and `allowlist` mode a match
is refused regardless of any allow, `no_sandbox` entries included: with
`git push` denied and `git` allowed, only pushes are refused. In `open` mode a
match is only recorded to the audit log, like every rule.

Denials use the same entry format as allows, with three differences:

- **Matching is by base name**, so an entry also covers the same binary
  invoked by path (`/usr/local/bin/lite-sandbox`, `./lite-sandbox`).
- **A restricted entry matches wherever the subcommand could start**, not only
  at the first argument, because the deny list doesn't know which flags take a
  value: `lite-sandbox --log-level debug config mode set open` matches
  `lite-sandbox config`. Tokens that appear later as data don't match: with
  `git push` denied, `git log --grep push` still runs.
- **A denied command never takes the raw-bash path.** A command in the deny
  list is always parsed, even if a bare allow also names it, so the invocation
  can be matched against the entry.

### Built-in entries

By default, the sandbox's own policy-editing subcommands (`config`, `install`,
`update`, and `hook`) are denied, both for the canonical binary name and for
the name it was installed under:

```
lite-sandbox config commands list
lite-sandbox config    deny   (built-in)
lite-sandbox install   deny   (built-in)
lite-sandbox update    deny   (built-in)
lite-sandbox hook      deny   (built-in)
```

They keep an agent in `denylist` mode from rewriting the policy it runs under
(see [Security](security.md#modes-and-what-they-defend-against)).
The entries are subcommand-scoped, so read-only subcommands an agent might use
to explain its own constraints (`version`, `config show`, `audit report`) still
work. As with [lifting a built-in path denial](#lifting-a-built-in-denial), an allow whose text
**equals** the built-in entry lifts it. A bare `lite-sandbox` allow does not:
allowing a command never drops the deny list underneath it.

```bash
lite-sandbox config commands allow "lite-sandbox update"   # lifts it
lite-sandbox config commands deny "lite-sandbox update"    # drops the lift; the built-in is back in force
```

### Config requests: the agent runs `lite-sandbox config` with your approval

With Claude Code set up by `install` or `launch`, the agent can make a config
change itself, with your approval each time, instead of telling you which
command to run. When a sandbox error names a `lite-sandbox config ...` fix,
the error says so and the agent runs that command with the bash tool. The
PreToolUse hook answers `ask` for it, so Claude Code shows a permission
prompt with the exact command. If you approve, the MCP server runs it on the
host, outside the sandbox, and the next command runs under the new config.

Only a bash command made up of a **single `lite-sandbox config` invocation
with literal arguments** counts as a config request. With a pipe, `&&`, `;`, a
redirection, an assignment, a variable, a substitution, or a glob, the
command goes to the sandbox like any other, and the built-in deny entry
refuses it. That keeps the command you approve the only thing that runs. The
server always runs its own binary, whatever path the command names.
`lite-sandbox config edit` is refused, because it needs a terminal, and so is
a config command run in the background.

A config request **never changes the global config**: it always lands in a
[per-directory override](#writing-overrides-from-the-cli---dir) for the
agent's working directory. When the command has no `--dir`, lite-sandbox adds
`--dir <working directory>` itself, so `lite-sandbox config commands allow
make` becomes `lite-sandbox config --dir /path/to/project commands allow make`,
and that scoped command is what the prompt asks you to approve and what runs.
A `--dir` the agent writes is kept only when it names the working directory or
a directory beneath it, and it is shown as the absolute directory it names
(`--dir .` becomes `--dir /path/to/project`). `--dir /`, `--dir ~`, `--dir ..` or a sibling project
is refused, since an override there reaches beyond the project. So are the
commands that have no per-directory form (`config path`, `config overrides
list`, `config paths migrate`, ...), and `config overrides remove` or `config
aws remove-override` naming another directory. Global changes stay yours to
make in your own terminal.

The server runs a config request only if the hook asked you about that exact
command. When the hook asks, it records a ticket in lite-sandbox's cache
directory, naming the command's arguments and the working directory (with
symlinks resolved, so the hook and the server agree on it however each spells
it). The server takes that ticket (each ticket works once and expires after
15 minutes) before it runs the change, and refuses the command when no ticket
matches. The hook and the server read the bash tool's input the same way, so
no spelling of the input can make the hook see a different command from the
one the server runs. Without the hook there is no prompt and so no ticket, and the
change never runs unapproved. It needs both halves, the hook registered with
`--config-requests` and the server started with `serve-mcp --config-requests`.
`install claude` and `launch claude` set both. Codex, opencode, Crush, and
Grok Build don't get either flag, so for them the built-in deny holds exactly
as before. In a non-interactive `claude -p` run, nobody can answer the
prompt, so Claude Code denies the call.

The hint pointing the agent at config requests is added to errors about a
command or path that isn't allowed yet. It isn't added to a
[command deny list](#denied-commands) error: lifting a denial you or
lite-sandbox made on purpose is not a change to steer the agent toward. An
approved request takes effect immediately, including starting or stopping the
[AWS credential server](aws-and-docker.md) when it changes `aws`.

`commands` can be set per directory with
[overrides](#per-directory-overrides). The built-in entries still apply under
an override, since they aren't part of the section it replaces. A
`merge: true` override combines the list with the base's
[entry by entry](#per-directory-overrides), so one directory can deny a
command the base allows without restating the rest.

### Deprecated keys

The three old lists still load and are combined with `commands`:
`extra_commands` (as `allow: true`), `unsandboxed_commands` (as `allow: true`
with `no_sandbox: true`), and `denied_commands` (as `allow: false`, and its `-`
entries as `allow: true`). The old CLI commands (`extra-commands`,
`unsandboxed-commands`, `denied-commands`) still work as hidden aliases that
write the new form.

`lite-sandbox config commands migrate` rewrites the old keys everywhere in the
file. The semantics differ under overrides: an old-style override replaced
only the one list it set and inherited the others, while a `commands` list
replaces the whole section (or merges entry by entry under `merge: true`). So
migrate gives each override that set any command list the full set of entries
in effect for its directory; on a `merge: true` override it writes only that
override's own entries. Two conversions aren't one-to-one: if a config both
allowed and denied the same command, the denial is kept (it won at every gate
anyway), and a `-` lift becomes an allow, which lifts the same built-in and,
in `allowlist` mode, also admits the command past the whitelist.

## CLI config management

```bash
lite-sandbox config path    # print the config file path
lite-sandbox config show    # show the current configuration
lite-sandbox config edit    # open the config file in $VISUAL / $EDITOR (default vi)
```

`config edit` works on a temporary copy and writes it back — verbatim, comments
included — only if it is a valid config. On top of the checks every load applies
(an unknown mode, profile, or profile option; a malformed `paths` or `commands`
entry), it rejects keys the config does not define, which are almost always typos
(`os_sandbx`, `git.remote_wirte`), a second YAML document, and overrides that could
never apply (no `path`, two overrides for the same path, nested `overrides`). A
rejected edit reopens with the error at the top of the file; decline and the config
is left untouched, with your edit kept in the temporary file it names. It also
refuses to overwrite the config if something else changed it while the editor was
open.

Each section has its own subcommand, shown with the section below
([`commands`](#commands), [`paths`](#paths), [`git`](#git-support), …).

## Paths

By default the sandbox confines reads and writes to the working directory. The
`paths` list holds everything else about paths: what commands may read or
write outside the working directory, and what the OS sandbox hides or keeps
read-only in `denylist` mode. Each entry names a path and sets `read` and/or
`write` (`true` grants, `false` denies, unset says nothing), plus an optional
`internal` for grants that apply only at the OS sandbox layer:

```yaml
paths:
  - path: ~/reference-data                        # readable: this dir and everything under it
    read: true
  - path: ~/.superconductor/worktrees/haystack/*  # readable: only paths NESTED below it
    read: true
  - path: ~/scratch                               # writable, which implies readable
    write: true
  - path: ~/.cache/some-tool                      # writable for spawned programs only (see below)
    write: true
    internal: true
  - path: ~/company-secrets                       # hidden entirely (denylist mode, OS sandbox)
    read: false
  - path: ~/.local/bin                            # readable but not writable (denylist mode, OS sandbox)
    write: false
```

The CLI writes the same entries:

```bash
lite-sandbox config paths allow ~/reference-data
lite-sandbox config paths allow "~/.superconductor/worktrees/haystack/*"
lite-sandbox config paths allow ~/scratch --write
lite-sandbox config paths allow ~/.cache/some-tool --write --internal
lite-sandbox config paths deny ~/company-secrets
lite-sandbox config paths deny ~/.local/bin --write
lite-sandbox config paths list
lite-sandbox config paths remove ~/scratch
```

Each path has one entry. `allow` and `deny` replace whatever the config said
about that path before (so `allow ~/x --write` after `allow ~/x` upgrades it),
and `remove` deletes the entry. `~` is expanded. An entry that sets neither
key, grants `write` while denying `read`, or marks a denial `internal` is
rejected when the config loads. `read: true` with `write: false` is valid:
readable, and kept read-only under the OS sandbox. `paths` can be set per
directory with [`--dir`](#writing-overrides-from-the-cli---dir); on a
`merge: true` [override](#per-directory-overrides) the list is combined with
the base's entry by entry, so a directory lists only the paths it changes.

### Grants: `read: true`, `write: true`

A grant widens what the agent may touch at every layer: static and runtime
path validation, the file-tool hook, the OS sandbox, and Deno's injected
`--allow-read`/`--allow-write`. `write: true` implies read.

A bare path grants the directory **and** everything in it. A trailing `/*`
grants only paths **nested below** the directory; the directory itself can't
be read or searched. This is useful for a directory holding many siblings,
such as a worktree parent: `worktrees/haystack/*` lets the sandbox read one
peer worktree while stopping a single `grep`/`ls` from sweeping all of them.

The Claude Code per-user scratchpad root (`/tmp/claude-<uid>`, which macOS
resolves to `/private/tmp/claude-<uid>`) is always readable and writable
without a config entry, so agents can use it for temporary files. It is
uid-scoped and was already writable at the OS sandbox layer.

The per-user system temp directory (`$TMPDIR`, e.g. macOS's
`/var/folders/.../T`) is also always readable and writable, since many tools
put scratch files there. It is granted only when it is a private, per-user
location. When `$TMPDIR` is unset and the temp dir is the shared `/tmp` (the
usual Linux default), `/tmp` is **not** granted; the scratchpad above still
covers `/tmp/claude-<uid>`.

### Internal grants: `internal: true` (OS sandbox only)

`internal: true` limits a grant to the **OS sandbox layer** (see
[Security](security.md)). Programs a command spawns can reach the path, but the
agent still can't read or write it directly: AST/runtime path validation, the
file-tool hook, and Deno's injected `--allow-read`/`--allow-write` keep
denying it.

```yaml
paths:
  - path: ~/.cache/some-tool   # the tool can update its cache; `cat`/`sed` there still fail
    write: true
    internal: true
  - path: /opt/reference-data
    read: true
    internal: true
```

Use this when a tool needs its own state directory under the OS sandbox but
you don't want to widen what the agent can touch. It only has an effect when
`os_sandbox` is enabled. The OS sandbox's filesystem is already broadly
readable, so an internal read grant mainly matters for host paths hidden by the
sandbox's `/tmp` overlay on Linux.

### Denials: `read: false`, `write: false` (denylist mode)

In `denylist` mode the OS sandbox binds `$HOME` writable, because developer
tools write caches and state all over it, and masks a built-in deny list
instead. There are two kinds:

- **Read-denied** paths are hidden (replaced by an unreadable empty directory
  or file; a non-root process gets `EACCES`): `~/.aws` (unless
  `aws.allow_raw_credentials`), `~/.gnupg`, `~/.netrc`, `~/.kube`, `~/.pypirc`,
  `~/.config/gh`, `~/Library/Keychains`, and the agents' own credentials
  (`~/.claude.json`, `~/.claude/.credentials.json`, `~/.codex/auth.json`,
  `~/.grok/auth.json`, `~/.grok/mcp_credentials.json`). The
  SSH private keys in `~/.ssh` (every file there except `known_hosts`,
  `config`, `authorized_keys`, and `*.pub`, detected by name) are also on this
  list, one entry per key. The two credential masks (the SSH keys, and `~/.aws`
  under `aws.force_profile`) apply in **every** mode, not only `denylist`.
- **Write-denied** paths stay readable but can't be modified: shell startup
  files (`~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.config/fish/config.fish`, …),
  `~/.gitconfig` and `~/.config/git/config`, `~/.ssh`, `~/.npmrc`,
  `~/.docker/config.json`, persistence locations (`~/.local/bin`, user systemd
  units, `~/.config/autostart`, `~/.config/environment.d`, LaunchAgents), and
  the files that could loosen the policy or erase evidence: lite-sandbox's own
  config file, audit log, and mask cache, plus the settings and instruction
  files of each *installed* agent (`~/.claude/settings.json`,
  `~/.claude/{skills,agents,commands,plugins}`, `~/.codex/config.toml`,
  `~/.codex/prompts`, opencode's and Crush's configs, and Grok Build's
  `config.toml`, `hooks/`, `disabled-hooks`, `rules/`, and the other files in
  `~/.grok` that decide what it loads). Agent entries are listed only when that
  agent's config directory exists.

On Linux, a missing deny-listed directory is created (mode 0700) so it can be
masked. A missing deny-listed file can't be masked without creating an empty
file on the host, so it is skipped until it exists; `config mode show` marks
such entries. See [Security](security.md#os-level-sandboxing-optional).

Add your own with a denying entry (`read: false` hides the path, `write: false`
keeps it readable but not writable). Missing paths are skipped:

```yaml
paths:
  - path: ~/company-secrets
    read: false
  - path: ~/.local/bin
    write: false
```

```bash
lite-sandbox config paths deny ~/company-secrets
lite-sandbox config paths deny ~/.local/bin --write
lite-sandbox config mode show          # prints the effective lists, built-in entries included
```

Denials only take effect under the OS sandbox (`os_sandbox: true`). The AST
layer already keeps the agent's own commands inside the project; the masks are
for the programs those commands start. In `allowlist` mode the OS sandbox
keeps its cwd-confined layout and denials are unused, except for the two
credential masks above, which apply in every mode.

### Lifting a built-in denial

Your `paths` entries are merged over the built-in deny lists, and a grant on
the **same path** as a built-in entry replaces it. A `read: true` (or
`write: true`, which implies read) grant lifts a read denial; a `write: true`
grant lifts a write denial. Only the exact path counts: a grant on `~`, or a
nested-only `~/.ssh/*` grant, lifts nothing beneath it, so widening the
boundary never drops the deny lists. The SSH private keys are grouped under
`~/.ssh`: a grant on the directory lifts every key, and a grant on one key
file lifts only that key.

The common case is `git` over SSH, where the `ssh` a command spawns needs the
keys but the agent shouldn't read them. An `internal` grant does that:

```bash
lite-sandbox config paths allow ~/.ssh --internal          # ssh can use every key; `cat ~/.ssh/id_ed25519` still fails
lite-sandbox config paths allow ~/.ssh/deploy_key --internal   # one key only
lite-sandbox config paths allow ~/.aws --internal          # the same for the AWS credential files (or `config aws allow-raw-credentials`)
lite-sandbox config paths allow ~/.bashrc --write          # a write denial, lifted the same way
```

```yaml
paths:
  - path: ~/.ssh
    read: true
    internal: true   # keys readable by spawned programs; ~/.ssh stays write-denied
```

`allow` prints the built-in entry it lifted, and `lite-sandbox config mode
show` keeps listing lifted entries, marked with the grant that lifts them. A
grant without `internal` also widens the agent-facing boundary to the path,
like any grant. Lifting applies per directory like the rest of `paths`: an
[override](#per-directory-overrides) that grants `~/.ssh` lifts the masks only
for commands run under that directory.

### Deprecated: one list per kind

Before `paths`, each kind had its own key (`readable_paths`,
`writable_paths`, `internal_readable_paths`, `internal_writable_paths`,
`denied_read_paths`, `denied_write_paths`) and CLI command. The keys still load
and are combined with `paths`, and the old commands still run (hidden, with a
deprecation notice, writing `paths` entries). `paths list` marks entries that
still come from an old key, and `paths allow`/`deny` convert a path to the new
form when they touch it. To rewrite the whole file at once:

```bash
lite-sandbox config paths migrate
```

The two forms behave differently under [overrides](#per-directory-overrides):
an old key on an override replaced only that one list and inherited the other
five, while `paths` on an override replaces the whole section (or merges entry
by entry under `merge: true`). `migrate` preserves what every directory
resolves to by giving such an override the full set of entries in effect for
its directory, so use it instead of renaming keys by hand. On a `merge: true`
override it writes only that override's own entries, since the base's are
inherited per path. That is the one case where the result is wider than
before, because a deprecated list there replaced the base's outright.

## Profiles

```yaml
profiles:
  - go
  - name: deno
    options:
      allow_network: true
```

A profile is a built-in preset of `commands` and `paths` entries for one
toolchain (`go`, `pnpm`, `rust`, `deno`, `flutter`, `xcode`, `uv`, and the default-on
`montypython`), merged into the lists described above before the sandbox sees
them. Its entries mean what yours do, except that a profile's allow of a
command name whitelists it (its validators still run) instead of skipping
validation; its toolchain directories are agent-readable and writable only at
the OS sandbox layer. `lite-sandbox config profiles show <name>` prints what a
profile contributes.
See [Toolchain profiles](profiles.md).

## Redundant `cd` rejection

Agents often prefix commands with `cd /abs/path/to/repo && ...` even though
the sandbox already runs in that directory. By default the sandbox rejects the
prefix so the agent drops it:

```
unneeded cd: cwd is already /abs/path/to/repo (drop the leading "cd /abs/path/to/repo")
```

Only a **leading `cd` with a single literal absolute-path argument that
resolves exactly to the working directory** is rejected. A `cd` into a
subdirectory, a relative `cd`, `cd .`, a dynamic target like `cd "$PWD"`, and
a `cd` with flags are all allowed.

To allow the redundant `cd`:

```yaml
reject_redundant_cd: false
```

Or use `lite-sandbox config redundant-cd enable|disable|show`. It can be set
per directory with the overrides below.

## Local binary execution

In `allowlist` mode, running a program by path (`./binary`, `../tool`,
`/path/to/script`) is blocked by default. To allow it:

```yaml
local_binary_execution:
  enabled: true   # Allow ./binary, /path/to/binary (default: false)
```

```bash
lite-sandbox config local-binary-execution enable|disable|show
```

A compiled binary (ELF/Mach-O) then runs directly. A script is run the way
the kernel would run it, as its `#!` interpreter plus the script path, so the
interpreter goes through the same whitelist and argument checks as a direct
call. A bare [`commands`](#commands) allow for a script path also lets it run;
a restricted one (`./gradlew build`) does not lift this gate.

## Per-directory overrides

The top-level `overrides` list changes configuration for specific working
directories. Each entry pairs a `path` with config sections that replace the
base for commands run **at or under** that path. Any section can be
overridden: `aws`, `docker`, `profiles`, `paths`, `os_sandbox`, and the rest.

```yaml
os_sandbox: true
paths:
  - path: ~/scratch
    write: true
aws:
  force_profile: "default"        # base mode for everything else

overrides:
  - path: ~/work/acme             # ~ is expanded
    aws:
      force_profile: "acme-dev"   # broker a different AWS profile here
    paths:                        # replaces (not extends) the base paths list here;
      - path: ~/work/acme/artifacts   # add merge: true to keep the base's entries
        write: true
  - path: ~/work/acme/prod
    aws:
      force_profile: "acme-prod"  # more specific path wins under prod/
  - path: ~/scratch
    os_sandbox: false             # any section can be overridden
  - path: ~/work/trusted
    merge: true                   # deep-merge instead of replace (see below)
    docker:
      allow_privileged: true      # only this flag changes; docker.enabled etc. kept
    paths:                        # merged entry by entry: the base's grants still
      - path: ~/work/trusted/out  # apply here, this one is added
        write: true
    commands:
      - command: curl             # restates the base's entry for curl, here only
        allow: false
```

Resolution rules:

- **Most specific wins.** When a directory is under more than one override
  `path`, the longest matching path applies and the others are ignored
  (overrides don't stack).
- **Replace vs. merge.** By default an override **replaces** each section it
  sets: an override with an `aws:` block defines the *entire* AWS config for
  its directory, dropping base `aws:` fields it doesn't restate. With
  `merge: true`, the override is **deep-merged** instead: only the fields it
  sets change, and the rest are inherited (the `~/work/trusted` example above
  changes only `docker.allow_privileged` and keeps the base
  `docker.enabled`). Either way, sections the override doesn't mention are
  inherited unchanged, and leaf values it does set (scalars, flags, and the
  deprecated one-list-per-kind path and command keys) come from the override.
- **`paths` and `commands` merge entry by entry.** Under `merge: true` these
  lists are combined per path or per command rather than taken whole: the
  base's entries carry over, an override entry for the same path or command
  **replaces** that entry, and entries for new paths or commands are added.
  Paths and commands are matched the way the sandbox matches them (`~/x` and
  its expanded form are the same path; `uv  run` and `uv run` are the same
  command). An override can restate an inherited entry (grant less, or deny
  what the base allowed) but can't remove one; to drop an entry everywhere,
  remove it from the base. In the default replace mode the whole list comes
  from the override, which is how a directory starts from an empty list.
- **Paths support `~`** and are resolved to absolute paths, so relative inputs
  match the directory they refer to.
- **Linked git worktrees inherit their repository's override.** A worktree
  created with `git worktree add` usually lives away from its checkout, often
  in a shared directory like `~/.superconductor/worktrees/<repo>/`, so it
  matches no override of its own. When nothing matches the working directory,
  resolution retries from the repository's **main worktree**, so the repo's
  override applies there too:

  ```yaml
  overrides:
    - path: ~/workspace/github.com/acme/haystack   # the checkout
      profiles:
        - go
  ```

  ```console
  $ git worktree list
  /Users/alex/workspace/github.com/acme/haystack                  5c65658 [master]
  /Users/alex/.superconductor/worktrees/haystack/sc-vortex-d091   85bf9a8 [feature]
  ```

  Commands run in `sc-vortex-d091` get the same `go` profile as the
  checkout. An override matching the worktree itself (or a directory above it)
  still wins; inheritance only applies when nothing matches directly, so a
  worktree can always be configured separately. This shares *settings*, not
  path grants: a `paths` entry naming a directory inside the repo still points
  there, and access to the main worktree from a linked one is the separate
  [`git.allow_worktree_parent`](#git-support) flag.

### Writing overrides from the CLI: `--dir`

Every `lite-sandbox config` command takes a `--dir <path>` flag, so any setting
can be scoped to one directory without editing the file:

```bash
lite-sandbox config commands allow npm --dir .            # only in this repo
lite-sandbox config paths allow ~/work/acme/out --write --dir ~/work/acme
lite-sandbox config mode set denylist --dir ~/work/new    # only under that path
lite-sandbox config profiles enable go --dir ~/work/acme
lite-sandbox config docker disable --dir ~/work/untrusted
lite-sandbox config aws force-profile acme-dev --dir ~/work/acme
```

A `--dir` edit starts from **what that directory currently resolves to** (the
base config plus any override already stored for it) and records only the
sections the command changed. So an `add` extends the list the directory
already has instead of replacing it, and settings the command didn't touch keep
inheriting from the base. Setting a directory to the value it already resolves
to writes no override.

An override `--dir` creates has **`merge: true`**: it is deep-merged into the
base, and its `paths` and `commands` hold only the entries the command added or
changed, so later edits to the base still reach the directory. A deep merge
cannot clear a setting (one the override leaves unset is inherited from the
base), so when the change does clear one — `aws disable`, or `aws
force-profile` dropping the base's `allow_raw_credentials` — the new override
is written replace-style instead. An override that already exists for the
directory keeps its `merge` setting; to make one replace-style, set `merge:
false` (or drop the key) by editing the config file — its `paths` and
`commands` then replace the base's, so restate the base entries (denials
included) it should keep.

A directory resolves through a single override: its own, or else the nearest
parent's (or, for a linked git worktree, its main worktree's). An override
`--dir` creates merges into the base, not into the override the directory was
inheriting, so the settings that parent override made (a stricter `mode`, a
denial, ...) stop applying to the directory unless the command restated them.

Reads accept the flag too: `lite-sandbox config show --dir <path>` prints the
configuration in effect there, as does any section's `show`/`list`
(`config docker show --dir .`, `config commands list --dir .`).

`config path` and `config os-sandbox check` reject `--dir`, since they aren't
per-directory settings.

To see or undo what `--dir` wrote:

```bash
lite-sandbox config overrides list            # every directory with settings
lite-sandbox config overrides remove <dir>    # drop all of that directory's settings
```

On a replace-style override (`merge` unset or false, written by hand), `--dir`
stores each section the command changed whole, since it replaces the base's.

In both cases, a `remove` of an entry the directory would still inherit is
reported as such rather than as a removal. On a `merge: true` override, the
base's entry is inherited per path. On a replace-style override, a section
emptied of its last entry isn't recorded at all, so the base's list applies
again:

```console
$ lite-sandbox config paths remove /base/data --dir ~/work/acme
/base/data: "read" in the base config still applies to /home/you/work/acme — an override can restate an entry, not drop it
  remove it everywhere with `lite-sandbox config paths remove /base/data`, or state something else here with `lite-sandbox config paths allow|deny /base/data --dir /home/you/work/acme`
```

## Git Support

Git commands are enabled by default, with separate permission levels:

```yaml
git:
  local_read: true             # git status, log, diff, show, grep, for-each-ref (default: true)
  local_write: true            # git add, commit, branch -d, tag -a, update-ref, gc (default: true)
  remote_read: true            # git fetch, pull, clone (default: true)
  remote_write: false          # git push (default: false)
  allow_worktree_parent: false # if cwd is a linked worktree, also allow read+write to the main worktree (default: false)
```

`git push` is disabled by default since it changes shared state. To allow the
agent to push:

```bash
lite-sandbox config git show
lite-sandbox config git set remote_write true
```

Every git subcommand is classified under one of these levels, and a
subcommand that isn't (including your own aliases, whose expansion would run
unvalidated) is refused:

| Level | Subcommands |
| --- | --- |
| `local_read` | `status`, `log`, `diff`, `show`, `blame`, `annotate`, `grep`, `shortlog`, `describe`, `whatchanged`, `range-diff`, `show-branch`, `cherry`, `last-modified`, `rev-parse`, `rev-list`, `name-rev`, `merge-base`, `merge-tree`, `ls-files`, `ls-tree`, `cat-file`, `diff-files`, `diff-index`, `diff-tree`, `diff-pairs`, `for-each-ref`, `show-ref`, `format-rev`, `count-objects`, `fsck`, `verify-commit`, `verify-tag`, `verify-pack`, `show-index`, `pack-redundant`, `repo`, `var`, `check-attr`, `check-ignore`, `check-mailmap`, `check-ref-format`, `url-parse`, `hash-object`, `symbolic-ref`, `column`, `stripspace`, `patch-id`, `mailinfo`, `mailsplit`, `fmt-merge-msg`, `interpret-trailers`, `get-tar-commit-id`; and, writing the output files they're told to, `format-patch`, `archive`, `fast-export`, `pack-objects`, `unpack-file`, `bugreport`, `diagnose` |
| `local_write` | `add`, `commit`, `checkout`, `switch`, `restore`, `reset`, `merge`, `rebase`, `cherry-pick`, `revert`, `rm`, `mv`, `init`, `bisect`, `clean`, `apply`, `am`, `quiltimport`, `stash`, `worktree`, `notes`, `history`, `replay`, `replace`, `rerere`, `sparse-checkout`, `refs`, `gc`, `maintenance run`, `prune`, `prune-packed`, `repack`, `pack-refs`, `commit-graph`, `multi-pack-index`, `bundle`, `update-index`, `update-ref`, `update-server-info`, `checkout-index`, `read-tree`, `write-tree`, `commit-tree`, `mktag`, `mktree`, `merge-file`, `index-pack`, `unpack-objects`, `fast-import` |
| `remote_read` | `fetch`, `pull`, `clone`, `ls-remote`, `backfill`, `request-pull`, `fetch-pack`, `remote` (listing and `show`), `submodule status`/`summary` |
| `remote_write` | `push`, `send-pack` |
| always allowed | `help`, `version` |

Some subcommands mix levels, and are checked by what the invocation does:

- `branch`, `tag`, and `config` are reads; their mutating flags (`branch -d`,
  `tag -a`, setting a `config` value, ...) need `local_write`. So do
  `hash-object -w`, `fsck --lost-found`, `interpret-trailers --in-place`, and
  `symbolic-ref` with a target or `-d`.
- The listing actions of write subcommands need only `local_read`: `stash
  list`/`show`, `worktree list`, `notes` (`list`, `show`), `refs`
  `list`/`exists`/`verify`, `rerere status`/`diff`/`remaining`,
  `sparse-checkout list`/`check-rules`, `commit-graph verify`,
  `multi-pack-index verify`, `bundle create`/`verify`/`list-heads`, and
  `maintenance is-needed`. `reflog` is the other way round: a read, except
  `reflog expire`/`delete`/`drop`/`write`.
- `remote add`/`remove`/`rename`/`set-url`/... and every `submodule` action but
  the ones above are `local_write`.
- `archive --remote` and `maintenance run --task=prefetch` also need
  `remote_read`.
- The global `-c` and `--config-env` options (`git -c core.pager=cat log`)
  need `local_write`: a config value can name a program for git to run, and
  setting one is a local write, as with `git config`.

A few subcommands and flags are always blocked, whatever the levels, because
they run a command given on the command line, start something outside the
repository, or handle credentials:

- `hook`, `filter-branch`, `difftool`, `mergetool`, `merge-index`,
  `for-each-repo`, `submodule foreach`;
- `credential`, `credential-cache`, `credential-store`, `send-email`,
  `imap-send`;
- servers and transport internals (`daemon`, `http-backend`, `instaweb`,
  `upload-pack`, `receive-pack`, `upload-archive`, `shell`, `http-fetch`,
  `http-push`, ...), GUIs (`gui`, `gitk`, `citool`), `scalar`,
  `maintenance start`/`stop`/`register`/`unregister` (which install a cron,
  systemd, or launchd schedule or edit the global config), and the bridges
  to other version control systems (`svn`, `p4`, `cvsimport`, ...);
- `grep -O`/`--open-files-in-pager` (runs a pager command on the matching
  files), `archive --exec`, `--upload-pack` of `fetch`/`pull`/`clone`/`ls-remote`/`fetch-pack`,
  `--receive-pack` of `push`/`send-pack`, `help --web`, `hash-object --stdin-paths` and `fast-import
  --allow-unsafe-features` (which read or write files named on stdin or in the
  import stream, out of reach of the path checks).

Long flags are matched by the abbreviations git accepts, so `git branch --del`
counts as `--delete`, and short flags inside a bundle, so `git branch -qd`
counts as `-d`.

Git's repository paths are checked at runtime like any other path, including
after variable expansion (e.g. `git -C $REPO_DIR status` validates the
expanded path).
