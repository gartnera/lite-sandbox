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
the OS sandbox, and what is always refused. Each entry is a command plus a
tri-state `allow`:

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
```

`command` is a bare name, or a name followed by the leading non-flag arguments
the entry applies to; extra whitespace between words is ignored. Each command
has one entry, so `allow` and `deny` on the CLI replace whatever the config
said about it before.

```bash
lite-sandbox config commands allow curl "uv run pyright"
lite-sandbox config commands allow docker --no-sandbox
lite-sandbox config commands deny sudo "gh auth"
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
```

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
overridden: `aws`, `docker`, `runtimes`, `paths`, `os_sandbox`, and the rest.

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
      runtimes:
        go:
          enabled: true
  ```

  ```console
  $ git worktree list
  /Users/alex/workspace/github.com/acme/haystack                  5c65658 [master]
  /Users/alex/.superconductor/worktrees/haystack/sc-vortex-d091   85bf9a8 [feature]
  ```

  Commands run in `sc-vortex-d091` get the same `runtimes.go.enabled` as the
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
lite-sandbox config runtimes go enable --dir ~/work/acme
lite-sandbox config docker disable --dir ~/work/untrusted
lite-sandbox config aws force-profile acme-dev --dir ~/work/acme
```

A `--dir` edit starts from **what that directory currently resolves to** (the
base config plus any override already stored for it) and records only the
sections the command changed. So an `add` extends the list the directory
already has instead of replacing it, and settings the command didn't touch keep
inheriting from the base. Setting a directory to the value it already resolves
to writes no override.

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

`merge: true` can only be set by editing the `overrides` list in the config
file; `--dir` always writes replace-style sections, seeded from the base as
described above. When the directory's override already has `merge: true`,
`--dir` keeps it: `paths` and `commands` are stored as a delta of only the
entries the command added or changed, so later base edits still apply.

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
  local_read: true             # git status, log, diff, show, grep (default: true)
  local_write: true            # git add, commit, branch, tag (default: true)
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

`git grep` is a local read, but its `-O`/`--open-files-in-pager` flag is
always blocked since it runs an arbitrary pager command on the matching files.

Git's repository paths are checked at runtime like any other path, including
after variable expansion (e.g. `git -C $REPO_DIR status` validates the
expanded path).
