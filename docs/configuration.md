# Configuration

The config file lives at the platform-appropriate location (`lite-sandbox
config path` prints it):

- **Linux**: `~/.config/lite-sandbox/config.yaml`
- **macOS**: `~/Library/Application Support/lite-sandbox/config.yaml`

It is reloaded automatically when changed — no server restart needed.

## Mode and audit

```yaml
mode: denylist      # open | denylist | allowlist   (default when unset: allowlist)
audit: true         # record validation findings (default: false)
```

`mode` selects the enforcement posture; see [Adoption](adoption.md) for the
full comparison and the intended progression:

- **`open`** — nothing is enforced; every command runs. Pair it with `audit` to
  see what the other modes would block.
- **`denylist`** — any program may run, but path arguments and redirections
  must stay inside the working directory (plus the paths granted in
  [`paths`](#paths)), the per-command validators still apply (`git push`,
  `pnpm publish`, `find -delete`, …), and under the OS sandbox `$HOME` is
  writable with the [deny lists](#denials-read-false-write-false-denylist-mode)
  masked. The opt-out for [incremental adoption](adoption.md); `config mode set
  denylist` also enables the OS sandbox when it is available and `os_sandbox`
  was never set.
- **`allowlist`** — only whitelisted commands run and code-execution runtimes
  are opt-in. The default.

`audit: true` appends every validation finding — blocked or not, tagged with
the modes that would block it — to `lite-sandbox audit path`, for
`lite-sandbox audit report`. Manage both with the CLI:

```bash
lite-sandbox config mode show                 # effective mode, audit, deny lists
lite-sandbox config mode set denylist
lite-sandbox config mode set denylist --dir ~/work/new-repo   # one directory only
lite-sandbox config audit enable|disable|show
lite-sandbox audit report [--since 7d] [--cwd ~/work/new-repo] [--json]
lite-sandbox audit clear
```

Like every section, `mode` and `audit` can be flipped per directory via
[overrides](#per-directory-overrides), so one repo can run `allowlist` while
the rest of the machine runs `denylist`; `mode set --dir` writes such an
override, and `audit report --cwd` narrows the report to sessions launched in
that directory.

## Extra commands

Commands outside the whitelist can be allowed in `allowlist` mode (in
`denylist` and `open` mode every command may already run, so this mainly
matters for the raw-bash path described below):

```yaml
extra_commands:
  - curl
  - python3
```

A bare entry (a single token) allows the command with any arguments and, when it
is the leading command of an invocation, bypasses bash AST parsing entirely —
the whole command string runs via the real bash. An entry with a subcommand
(e.g. `uv run pyright`) restricts the command to invocations whose leading
non-flag arguments match, and still goes through normal parsing and validation.
When the [OS sandbox](security.md#os-level-sandboxing-optional) is enabled,
bare entries run inside it like every other command, so filesystem confinement
applies even though validation is skipped.

### Unsandboxed commands

`unsandboxed_commands` is parsed exactly like `extra_commands` (same bare and
subcommand-restricted entry formats, same validation bypass) with one
difference: matching invocations always run **directly on the host**, bypassing
the [OS sandbox](security.md#os-level-sandboxing-optional) worker
(bwrap/sandbox-exec) even when it is enabled. This is a trust-based escape hatch
for commands that cannot run confined.

```yaml
unsandboxed_commands:
  - docker            # talk to the real docker daemon, not the filtering proxy
  - ./scripts/deploy.sh
```

Because these commands leave the OS sandbox, the docker filtering proxy is also
bypassed: the proxy `DOCKER_HOST` override is not applied, so `docker` reaches
the real daemon (or whatever `DOCKER_HOST` the host environment already sets).
Subcommand-restricted entries only unsandbox matching invocations — e.g.
`git push` leaves other `git` subcommands confined.

Manage the list with
`lite-sandbox config unsandboxed-commands add|list|remove`.

## Denied commands

`denied_commands` is the deny list the other two cannot lift. It is checked
before every command gate — static, runtime, and wrapped (`env`, `xargs`,
`timeout`, `find -exec`) — and a match refuses the invocation in `denylist` and
`allowlist` mode however else it was allowed, `extra_commands` and
`unsandboxed_commands` included. In `open` mode, like every rule, a match is
only recorded to the audit log.

```yaml
denied_commands:
  - sudo                 # bare entry: the command itself, whatever its arguments
  - gh auth              # subcommand entry: only invocations starting with it
  - -lite-sandbox hook   # leading "-": drop a built-in entry (see below)
```

Entries use the `extra_commands` format, with three differences that come from
being a deny list rather than an allow list:

- **Matching is by base name**, so an entry also covers the same binary invoked
  by path (`/usr/local/bin/lite-sandbox`, `./lite-sandbox`). A deny that can be
  sidestepped by spelling the path differently is not a deny.
- **A subcommand entry matches wherever the subcommand could start**, not only
  at the first argument, because which flags consume a value is per-command
  knowledge the deny list does not have: `lite-sandbox --log-level debug config
  mode set open` matches `lite-sandbox config`. Tokens that appear later as
  data do not match — with `git push` denied, `git log --grep push` still runs.
- **A bare entry never takes the raw-bash path.** A command named in the deny
  list is always parsed, even if `extra_commands` lists it bare, so the
  invocation can be matched against the entry.

### Built-in entries

The defaults deny the sandbox's own policy-editing subcommands — `config`,
`install`, `update`, and `hook` — for the canonical binary name and the name it
was installed under:

```
lite-sandbox config denied-commands list
lite-sandbox config   (built-in)
lite-sandbox install  (built-in)
lite-sandbox update   (built-in)
lite-sandbox hook     (built-in)
```

They exist because `denylist` mode drops the command whitelist: without them an
agent can run `lite-sandbox config mode set open`, which the MCP server
hot-reloads, and enforcement is off for its next command. (With the OS sandbox
enabled the config file is also mounted read-only in the worker, so the write
fails there too — but the OS sandbox is off by default and unavailable without
bubblewrap, and these entries hold either way.)

The entries are subcommand-scoped, so the read-only subcommands an agent uses
to explain its own constraints (`version`, `config show`, `audit report`) keep
working. Lifting one is a deliberate decision:

```bash
lite-sandbox config denied-commands list
lite-sandbox config denied-commands add sudo "gh auth"
lite-sandbox config denied-commands remove "lite-sandbox update"   # records "-lite-sandbox update"
```

`remove` deletes a user entry, and records a `-` entry for a built-in one
(which is what `denied_commands: ["-lite-sandbox update"]` above does by hand).
Like every section, `denied_commands` can be set per directory through
[overrides](#per-directory-overrides); the built-in entries apply under an
override too, since they are not part of the section it replaces.

## CLI config management

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

# Manage the command deny list (outranks the two lists above)
lite-sandbox config denied-commands list
lite-sandbox config denied-commands add sudo "gh auth"
lite-sandbox config denied-commands remove sudo

# Grant or deny paths (one command for every kind of path entry)
lite-sandbox config paths allow ~/reference-data          # readable
lite-sandbox config paths allow ~/scratch --write         # read and write
lite-sandbox config paths deny ~/company-secrets          # hidden (denylist mode)
lite-sandbox config paths list
lite-sandbox config paths remove ~/scratch
```

## Paths

By default the sandbox confines reads and writes to the working directory. One
list, `paths`, carries every other statement about a path: what commands may
read or write beyond the working directory, and what the OS sandbox must hide
or keep read-only in `denylist` mode. Each entry names a path and sets `read`
and/or `write` — `true` grants, `false` denies, unset says nothing — plus an
optional `internal` for grants that should hold only at the OS sandbox layer:

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

Each path has one entry: `allow` and `deny` replace whatever the config said
about that path before (so `allow ~/x --write` after `allow ~/x` upgrades it),
and `remove` drops every statement about it. `~` is expanded. An entry that
sets neither key, grants `write` while denying `read`, or marks a denial
`internal` is rejected when the config loads. `read: true` together with
`write: false` is coherent — readable, and kept read-only under the OS sandbox.
Like every section, `paths` can be set per directory with
[`--dir`](#writing-overrides-from-the-cli---dir).

### Grants: `read: true`, `write: true`

A grant widens the boundary the agent may touch, at every layer: the static and
runtime path validation, the file-tool hook, the OS sandbox, and Deno's injected
`--allow-read`/`--allow-write`. `write: true` implies read.

A bare path grants the directory **and** all of its contents. A trailing `/*`
grants only paths **nested below** the directory — the directory itself is not a
valid read/search target. This is useful for a container that holds many sibling
directories (e.g. a worktree parent): `worktrees/haystack/*` lets the sandbox
read an individual peer worktree while blocking a single `grep`/`ls` from
sweeping every worktree at once.

The Claude Code per-user scratchpad root (`/tmp/claude-<uid>`, which macOS
resolves to `/private/tmp/claude-<uid>`) is always readable and writable without
a config entry, so agents can use it for temporary files. It is uid-scoped and
was already writable at the OS-sandbox layer; this only opens the agent-facing
boundary to match.

The per-user system temp directory (`$TMPDIR`, e.g. macOS's
`/var/folders/.../T`) is likewise always readable and writable without a config
entry, since many tools place scratch files there by default. It is granted only
when it is a private, per-user location; when `$TMPDIR` is unset and the temp dir
is the world-shared `/tmp` (the common Linux default), it is **not** granted
wholesale — the uid-scoped scratchpad above still covers `/tmp/claude-<uid>`
there.

### Internal grants: `internal: true` (OS sandbox only)

`internal: true` narrows a grant to the **OS sandbox layer** (see
[Security](security.md)), so programs a command spawns can reach their own data
— while the agent itself still cannot read or write the path directly (the
AST/runtime path validation, the file-tool hook, and Deno's injected
`--allow-read`/`--allow-write` all keep denying it):

```yaml
paths:
  - path: ~/.cache/some-tool   # the tool can update its cache; `cat`/`sed` there still fail
    write: true
    internal: true
  - path: /opt/reference-data
    read: true
    internal: true
```

Use this when a tool needs its own state directory to function under the OS
sandbox, but you don't want to widen the boundary the agent can touch. It only
has an effect when `os_sandbox` is enabled — without it there is no OS layer to
loosen. Note that inside the OS sandbox the filesystem is already broadly
readable, so an internal read grant mainly matters for host paths hidden by the
sandbox's `/tmp` overlay on Linux.

### Denials: `read: false`, `write: false` (denylist mode)

In `denylist` mode the OS sandbox binds `$HOME` writable — developer tooling
writes caches and state all over it, and enumerating them is a losing game —
and instead masks a built-in deny list. Two kinds, because the reasons differ:

- **Read-denied** paths are hidden entirely (an unreadable empty directory or
  file; a non-root process gets `EACCES`): `~/.aws` (unless
  `aws.allow_raw_credentials`), `~/.gnupg`, `~/.netrc`, `~/.kube`, `~/.pypirc`,
  `~/.config/gh`, `~/Library/Keychains`, and the agents' own credentials
  (`~/.claude.json`, `~/.claude/.credentials.json`, `~/.codex/auth.json`). The
  SSH private keys in `~/.ssh` — every file there except `known_hosts`,
  `config`, `authorized_keys` and `*.pub`, detected by name — are entries of
  this list too, one per key, and the two credential masks (the keys, and
  `~/.aws` under `aws.force_profile`) hold in **every** mode, not only
  `denylist`.
- **Write-denied** paths stay readable but cannot be modified: shell startup
  files (`~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/.config/fish/config.fish`, …),
  `~/.gitconfig` and `~/.config/git/config`, `~/.ssh`, `~/.npmrc`,
  `~/.docker/config.json`, persistence locations (`~/.local/bin`, user systemd
  units, `~/.config/autostart`, `~/.config/environment.d`, LaunchAgents), and —
  so a command cannot loosen the policy that governs it or erase the evidence —
  lite-sandbox's own config file, audit log, and mask cache, plus the settings
  and instruction files of each *installed* agent (`~/.claude/settings.json`,
  `~/.claude/{skills,agents,commands,plugins}`, `~/.codex/config.toml`,
  `~/.codex/prompts`, opencode's and Crush's configs). Agent entries are listed
  only when that agent's config directory exists.

On Linux a missing deny-listed directory is created (mode 0700) so it can be
masked; a missing deny-listed file cannot be masked without creating an empty
file on the host, so it is skipped until it exists. `config mode show` marks
such entries. See [Security](security.md#os-level-sandboxing-optional).

Extend either kind with a denying entry (`read: false` hides the path,
`write: false` keeps it readable but not writable); missing paths are skipped:

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

Denials only take effect under the OS sandbox (`os_sandbox: true`): the AST
layer already keeps the agent's own commands inside the project, so the masks
exist for the programs those commands start. In `allowlist` mode the OS
sandbox keeps its original cwd-confined layout and denials are unused — except
the two credential masks above, which hold in every mode.

### Lifting a built-in denial

The built-in deny lists are the default half of the `paths` list: your entries
are merged over them, and a grant on the **same path** as a built-in replaces
it. A `read: true` (or `write: true`, which implies read) grant lifts a read
denial; a `write: true` grant lifts a write denial. Only the exact path counts —
a grant on `~` or a `~/.ssh/*` nested-only grant lifts nothing beneath it, so
widening the boundary never silently drops the deny lists. The SSH private keys
are grouped under `~/.ssh`: a grant on the directory lifts every key, a grant on
one key file lifts that key only.

The usual case is `git` over SSH, where the `ssh` a command spawns needs the
keys but the agent has no business reading them. An `internal` grant is that
distinction:

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

`allow` prints the built-in it just lifted, and `lite-sandbox config mode show`
keeps listing a lifted entry, marked with the grant that lifts it, so the
effective policy is never silently shorter than the documented one. A grant
without `internal` also widens the agent-facing boundary to the path, as any
grant does. Lifting applies per directory like the rest of `paths`: an
[override](#per-directory-overrides) that grants `~/.ssh` lifts the masks for
commands run under that directory only.

### Deprecated: one list per kind

Before `paths`, each kind had its own key — `readable_paths`,
`writable_paths`, `internal_readable_paths`, `internal_writable_paths`,
`denied_read_paths`, `denied_write_paths` — and its own CLI command. They still
load, resolve as the union with `paths`, and the old commands still run
(hidden, printing a deprecation notice, and writing `paths` entries). `paths
list` marks entries that still come from an old key, and `paths allow`/`deny`
move a path to the new form when they touch it. To rewrite a whole file at once:

```bash
lite-sandbox config paths migrate
```

The two spellings differ under [overrides](#per-directory-overrides): an old
key on an override replaced only that one list and inherited the other five,
whereas `paths` on an override replaces the whole section. `migrate` keeps what
every directory resolves to by giving such an override the full set of entries
in effect for its directory, so run it rather than renaming keys by hand.

## Redundant `cd` rejection

Agents habitually prefix a command with `cd /abs/path/to/repo && ...` even though
the sandbox already runs in that directory. By default the sandbox rejects this
noise so the agent drops it:

```
unneeded cd: cwd is already /abs/path/to/repo (drop the leading "cd /abs/path/to/repo")
```

The match is deliberately narrow: only a **leading `cd` with a single literal,
absolute-path argument that resolves exactly to the working directory** is
rejected. A `cd` into a subdirectory, a relative `cd`, `cd .`, a dynamic target
like `cd "$PWD"`, or a `cd` carrying flags are all left alone — those are either
legitimate or not the redundant prefix agents emit.

Disable it (allowing the redundant `cd`) with:

```yaml
reject_redundant_cd: false
```

Manage it with `lite-sandbox config redundant-cd enable|disable|show`. Like every
section it can be flipped per directory via the overrides below.

## Per-directory overrides

Any part of the configuration can be changed for specific working directories via
the top-level `overrides` list. Each entry pairs a `path` with any config
sections that replace the base for commands run **at or under** that path. This is
not AWS-specific — `aws`, `docker`, `runtimes`, `paths`, `os_sandbox`, and every
other section can be overridden the same way.

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
    paths:                        # replaces (not extends) the base paths list here
      - path: ~/work/acme/artifacts
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
```

Resolution rules:

- **Most specific wins.** When a directory lies under more than one override
  `path`, the longest matching path applies; the others are ignored (overrides do
  not stack).
- **Replace vs. merge.** By default an override **replaces** each section it sets:
  an override with an `aws:` block defines the *entire* AWS mode for its
  directory, dropping any base `aws:` fields it doesn't restate. Set `merge: true`
  on an override to **deep-merge** it instead — it recurses into a section and
  applies only the fields it sets, inheriting the rest (so the `~/work/trusted`
  example above flips just `docker.allow_privileged` and keeps the base
  `docker.enabled`). Either way, sections the override never mentions are
  inherited from the base unchanged, and leaf values it does set (scalars, flags,
  and lists like `paths`) come from the override.
- **Paths support `~`** and are resolved to absolute paths, so relative inputs
  match the concrete directory they denote.

### Writing overrides from the CLI: `--dir`

Every command under `lite-sandbox config` takes a `--dir <path>` flag — it is
registered once on `config`, so any setting can be scoped to one directory
without hand-editing the file:

```bash
lite-sandbox config extra-commands add npm --dir .        # only in this repo
lite-sandbox config paths allow ~/work/acme/out --write --dir ~/work/acme
lite-sandbox config mode set denylist --dir ~/work/new    # only under that path
lite-sandbox config runtimes go enable --dir ~/work/acme
lite-sandbox config docker disable --dir ~/work/untrusted
lite-sandbox config aws force-profile acme-dev --dir ~/work/acme
```

A `--dir` edit starts from **what that directory resolves to today** — the base
config with any override already stored for it applied — and records only the
sections the command actually changed. So an `add` extends the list the directory
already sees instead of silently replacing it, and settings the command didn't
touch keep inheriting from the base. Setting a directory to the value it already
resolves to writes no override at all.

Reads honour the flag too: `lite-sandbox config show --dir <path>` prints the
configuration in effect there, and so does any section's `show`/`list`
(`config docker show --dir .`, `config extra-commands list --dir .`).

Two commands reject `--dir`, since they are not per-directory settings:
`config path` and `config os-sandbox check`.

To see or undo what `--dir` wrote:

```bash
lite-sandbox config overrides list            # every directory with settings
lite-sandbox config overrides remove <dir>    # drop all of that directory's settings
```

The `merge: true` flag is still authored by editing the `overrides` list in the
config file directly; `--dir` always writes replace-style sections (seeded from
the base, as described above).

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
