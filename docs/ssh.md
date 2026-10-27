# SSH Access

The `ssh` section lets the agent run `ssh` and `sshpass` to hosts you list, and
gives your ssh agent to them and to git's remote commands (`git fetch`, `pull`,
`push`, `clone`, ...), so a push to an ssh remote authenticates with your keys.
The agent goes through a filter by default, and nothing else the agent runs can
reach it. With no `ssh` section, nothing changes: `ssh` isn't on the
whitelist, and the agent is left as it was.

```yaml
ssh:
  hosts:                     # ssh and sshpass may connect to these hosts only
    - build-box              # as typed: an alias from ~/.ssh/config, or a host name;
    - 10.0.0.12              # the remote command is held to read-only commands
    - host: deploy-box       # the mapping form widens that:
      commands:              # these too, with any arguments
        - systemctl restart
        - docker compose up
    - host: scratch-vm
      write: true            # the remote command is not checked
  agent: true                # give the agent to ssh, sshpass, and git's remote commands (default: true)
  unrestricted_agent: false  # hand them the real agent socket instead of the filter (default: false)
  git_signing: false         # sign git commits and tags with the agent (default: false)
```

```bash
lite-sandbox config ssh show
lite-sandbox config ssh hosts add build-box 10.0.0.12
lite-sandbox config ssh hosts add deploy-box --command 'systemctl restart' --command 'docker compose up'
lite-sandbox config ssh hosts add scratch-vm --write
lite-sandbox config ssh hosts remove 10.0.0.12
lite-sandbox config ssh agent disable      # no agent for anything
lite-sandbox config ssh agent unrestrict   # the real socket (see below)
lite-sandbox config ssh agent restrict     # back to the filter
lite-sandbox config ssh git-signing enable # sign commits and tags (see below)
lite-sandbox config ssh disable            # remove the section
```

Like every section it can be set [per directory](configuration.md#per-directory-overrides)
(`lite-sandbox config --dir . ssh hosts add deploy-box`). `ssh: {}` (or just
`lite-sandbox config ssh agent enable`) gives git's remote commands the agent
without allowing `ssh` itself.

## Hosts

Once the section lists a host, `ssh` and `sshpass` are on the whitelist and
their argument validator holds them to the list:

```bash
ssh build-box uptime                 # allowed
ssh deploy@build-box -p 2222 'cat /var/log/app.log | tail'
ssh -J build-box 10.0.0.12 uptime    # every jump host must be listed too
sshpass -e ssh 10.0.0.12 true        # password from $SSHPASS (see below); may only run ssh
ssh other-box uptime                 # refused: not listed
```

The destination is matched as you'd type it, exactly and case-insensitively, the
way ssh's own `Host` blocks match: an alias from `~/.ssh/config` stands for
whatever that config makes of it (its `HostName`, `Port`, `ProxyJump`, ...),
since it's your file and sandboxed commands can't write it. `build-box` doesn't
allow `build-box.example.com`, and a user or port is not part of the match.
Entries are bare names or addresses: no `user@`, patterns, or lists, and a host
is listed once.

The remote command's words aren't treated as local paths, so
`ssh box cat /etc/hosts` reads the remote file. `-i` is the one argument held
to the local path boundary.

The options that let ssh reach anything but the destination, or run something on
this machine, are refused:

- port, socket, and tunnel forwarding: `-L`, `-R`, `-D`, `-W`, `-w`, `-g`;
- agent, X11, and credential forwarding: `-A`, `-X`, `-Y`, `-K`;
- `-I` (a PKCS#11 library ssh loads into itself), `-F` other than `-F none`
  (a config file's `ProxyCommand`, `LocalCommand`, or `Match exec` would run
  here), connection sharing (`-M`, `-O`, and `-S` other than `-S none`),
  `-f` (backgrounds past the command; use `run_in_background`), and `-E`
  (writes a log file; `-v` logs to stderr);
- `-o` keys outside a fixed list: connection and authentication settings
  (`BatchMode`, `ConnectTimeout`, `Port`, `User`, `StrictHostKeyChecking`,
  `PubkeyAuthentication`, `ServerAliveInterval`, `SetEnv`, `RemoteCommand`,
  `RequestTTY`, ...) are allowed; `ProxyCommand`, `LocalCommand`,
  `KnownHostsCommand`, `Hostname`, `IdentityAgent`, `IdentityFile` (use `-i`),
  `SendEnv` (which would send the environment's credentials), `Include`, and
  the forwarding keys are refused unless set to their off value
  (`ForwardAgent=no`, `ProxyCommand=none`, `UserKnownHostsFile=/dev/null`, ...).

Run by `xargs`, ssh must name its remote command (`xargs ssh box cmd`) or end
its options with `--`: ssh reads options again after the destination, so the
words `xargs` appends would otherwise be options (`-oProxyCommand=...`). For
the same reason `xargs sshpass` must name the command sshpass runs. With a
replace string (`xargs -I{}`, `-i`, `--replace`, and `find -exec`'s `{}`),
the input may only replace words of the remote command
(`xargs -I{} ssh box cat {}`), never the destination, an option, or the first
word after the destination. On a host whose remote command is held to
read-only commands (below), the input may not reach the remote command at
all: the check runs before `xargs` or `find` does, and the remote shell would
run the input as part of the command. That leaves `xargs` and `find -exec`
with ssh to `write: true` hosts.

### The remote command

By default the command ssh runs on a host is held to read-only commands, so
listing a host lets the agent look around it (logs, service status, processes,
disk, a repository's history) without changing it. A host's entry widens that:

- `commands` allows commands beyond the read-only ones, as a `commands` entry
  does: a name (`make`, any arguments) or a name and the leading arguments it
  is limited to (`systemctl restart`, `docker compose up`). Their arguments
  aren't checked.
- `write: true` lifts the check: the remote command runs as written.

ssh joins the words after the destination with spaces and hands the result to
the remote user's shell, so the check parses that string as a shell script
(sh/bash syntax; a host whose login shell is fish or csh reads it differently)
and every command in it must be read-only:

```bash
ssh build-box 'journalctl -u app --since today | grep -c ERROR'   # allowed
ssh build-box 'cd /srv/app && git log --oneline -5'               # allowed
ssh build-box sudo systemctl status nginx                         # allowed
ssh build-box 'tail -n 50 /var/log/app/*.log'                     # allowed: the remote shell globs
ssh build-box systemctl restart nginx    # refused, unless the entry lists `systemctl restart`
ssh build-box 'cat x > /tmp/y'           # refused: output goes to /dev/null only
ssh build-box 'cat $(ls)'                # refused: no substitutions or variables
```

- **The read-only commands** are the plain readers (`cat`, `head`, `tail`,
  `grep`, `ls`, `find`, `stat`, `du`, `df`, `wc`, `sort`, `uniq`, `cut`, `jq`,
  `diff`, `ps`, `uptime`, `free`, `uname`, `id`, `lsof`, ...), and these, with
  their writing options refused: `journalctl` (no `--vacuum-*`, `--rotate`,
  `--flush`, `--cursor-file`, ...), `systemctl` (the read-only verbs: `status`,
  `show`, `cat`, `list-units`, `is-active`, ..., and no `-H`), `git` (`status`,
  `log`, `show`, `diff`, `blame`, `grep`, `ls-files`, `rev-parse`, ...; no `-c`
  or `--output`), `docker` (`ps`, `logs`, `inspect`, `images`, `stats`, and
  the `ls`/`inspect`/`logs` of `container`, `image`, `network`, `volume`, and
  `compose`), `sed` (no `-i`, `-f`, or `w`/`W`/`e` commands and `s///w`/`e`
  flags), `find` (no `-delete` or `-fprint*`; `-exec` runs a read-only
  command), `sort` (no `-o`), `uniq` (one operand), `date` (no setting the
  clock), `hostname`, `dmesg`, `ss`, `ip` (`show`, `list`, `get`), `file`, and
  `rg` (no `--pre`).
- **Wrappers** are looked through: `sudo` (not `-e`, `-i`, `-s`, or
  `VAR=value`), `env`, `timeout`, `nice`, `stdbuf`, `command`, and `sh`/`bash`
  `-c '...'`, whose script is checked the same way.
- **The shell around them**: pipes, `&&`, `||`, `;`, `if`, `while`, `case`,
  subshells, and input redirections and heredocs are fine. Output redirections
  may only go to `/dev/null` (or another descriptor, `2>&1`). Variables,
  command and process substitution, arithmetic, `for` loops, functions, and
  assignments are refused, since their values are only known on the remote
  host and could turn a word into an option or another command; a command
  prefix may set only locale, time zone, and width variables
  (`LC_ALL=C sort`). Commands are run by bare name, not path. Globs and
  braces are allowed in the arguments of the plain readers only; quote them
  elsewhere (`find /var/log -name '*.gz'`, written `ssh box "find /var/log -name '*.gz'"`).
- **The session itself**: without a command ssh opens a login shell that runs
  whatever reaches its stdin, so a bare `ssh box` is refused unless stdin is
  closed (`-n`) or nothing runs (`-N`). A terminal (`-t`, `RequestTTY`) is
  refused too, unless with `-n`: a pager (`systemctl` and `git` start `less`
  on a terminal) would run commands sent to it. A subsystem (`-s`, such as
  sftp), `-o RemoteCommand`, and `-o SetEnv` are refused.

The words of an `ssh` (or `sshpass`) command must be written out: a variable
or substitution in them is refused, and so is an unquoted glob or brace in the
remote command, which this machine's shell would expand into its own file
names (quote it so the remote shell does). The check covers the command line;
a `RemoteCommand` or `RequestTTY` your `~/.ssh/config` sets for an alias is
yours, and ssh applies it as you wrote it.

Without hosts listed, `ssh` and `sshpass` aren't on the whitelist, so
`allowlist` mode refuses them. `denylist` mode, which doesn't whitelist
commands, still runs them unchecked until you list a host.

### sshpass

sshpass takes the password from the environment only (`-e`, which reads
`SSHPASS`), and the agent loads it there without seeing it:

```bash
export SSHPASS=$(cat secrets/build-box.pw)   # the file must be readable in the path boundary
sshpass -e ssh build-box uptime
```

`-e` is written on its own (`-e -v`, not `-ev`): sshpass 1.10 reads the
letters after it as the name of the variable holding the password.

`-p` would put the password in the command line the agent writes, and so in
its context and transcript; it is refused, as are `-f`, `-d`, and reading the
password from stdin (no option), so there is one way to do it. `SSHPASS`
reaches sshpass alone: it is left out of every other command's environment, so
a program run later in the same call can't read it, and sshpass runs in an OS
sandbox worker of its own (the agent's, when it has one), whose processes the
shared worker can't see. An `SSHPASS` the server was started with counts as a
credential: commands and the shell don't see it (under the OS sandbox), and
sshpass gets it when the agent sets none. Nothing stops the agent from
printing the variable itself (`echo $SSHPASS`); the point is that it never has
to.

Host keys come from your `~/.ssh/known_hosts`, which the
[hidden home](configuration.md#hidden-home-os_sandbox_hide_home) shows
read-only: there is no terminal to answer ssh's prompt, so a host must already
be known (or connect with `-o StrictHostKeyChecking=accept-new`, which can't
save the key there and so trusts it once).

## The agent

Your private keys in `~/.ssh` are [masked](security.md#common-isolation-both-platforms)
from every command in every mode, so key authentication inside the sandbox
goes through your ssh agent (`SSH_AUTH_SOCK`). With the `ssh` section present,
and the [OS sandbox](security.md#os-level-sandboxing-optional) on:

- **Only ssh, sshpass, and git's remote commands get it.** They run in an OS
  sandbox worker of their own (like the [gh profile](profiles.md#github-cli-gh)'s
  credentials), started with `SSH_AUTH_SOCK` pointing at the agent's socket.
  Every other worker masks the agent socket, so a dependency's install script,
  a test, or a program the agent writes can't use your keys, and neither can an
  `ssh` it launches itself. Only a direct invocation by name is routed there:
  `ssh box`, `git push`, not `timeout 60 ssh box` or `bash -c 'git push'`.
  ssh and sshpass get the agent only while hosts are listed.
- **git gets it only to reach a remote.** `fetch`, `pull`, `push`, `clone`,
  `ls-remote`, `remote show`, `archive --remote`, and `submodule` run in the
  agent's worker; every other git command runs in the shared one, as before.
  The git in the agent's worker runs with what git lets the environment switch
  off switched off: hooks (so `pre-push` and `post-merge` hooks don't run),
  `core.fsmonitor`, credential helpers, signing, submodule recursion, and
  transports other than https and ssh, and `GIT_SSH_COMMAND` is `ssh` unless
  the server sets it, so the project's `.git/config` can't swap in another
  program. Like the gh profile's `allow_git`, that doesn't cover a filter,
  merge, or diff driver that `.git/config` defines and `.gitattributes`
  attaches to a path, which runs on checkout or pull in that worker. The
  filter below limits what such a driver could do with the agent.
- **The agent is filtered** (unless `unrestricted_agent`). lite-sandbox serves
  a socket of its own in front of the agent that forwards only listing the
  keys, signing with them to authenticate (and, with `git_signing`, to sign a
  git commit or tag: an SSHSIG signature in the `git` namespace), and OpenSSH's
  `session-bind@openssh.com`. SSHSIG signatures in any other namespace (a
  file, an email), and signatures over anything but an ssh login (an ssh
  certificate, another protocol's challenge), are refused, as are adding,
  removing, and locking keys, smartcard keys, and every other extension are
  refused, and a connection ssh binds for forwarding gets nothing, so the keys
  can't be used from a remote host the agent was forwarded to (ssh's `-A` is
  refused, but a `ForwardAgent yes` in your `~/.ssh/config` isn't visible to
  the validator). That relies on OpenSSH 8.9 or later, which sends the binding;
  an older ssh forwards the agent unbound.
- **`unrestricted_agent: true`** hands those same commands the real socket
  instead: they can then add, remove, and lock keys, and use it over
  forwarding. Nothing else gets it either way.
- **`agent: false`** masks the agent from every command.

Without the OS sandbox there are no workers to keep the socket from: commands
run on the host get `SSH_AUTH_SOCK` pointed at the filter (or unset with
`agent: false`), which a command that knows the real socket's path can bypass.

The filter starts with the server whenever `SSH_AUTH_SOCK` names an agent, so a
section added later (the config is reloaded on change) applies without a
restart. With no agent there is nothing to give: `ssh` still runs, with
password or `sshpass` authentication.

### Git signing

`git_signing: true` (`lite-sandbox config ssh git-signing enable`) signs commits
and tags with a key in your agent, with git's ssh signing (`gpg.format ssh`,
`user.signingKey` naming the public key or `key::ssh-ed25519 ...`, and
`commit.gpgSign`/`tag.gpgSign` or `-S`/`-s` as you set them):

- `commit`, `tag`, `merge`, `rebase`, `cherry-pick`, `revert`, `am`, and
  `commit-tree` also run in the agent's worker, where signing isn't switched
  off. They keep the agent's commit identity (`GIT_AUTHOR_*`,
  `GIT_COMMITTER_*`) but none of its other variables.
- **Their hooks don't run** (`pre-commit`, `commit-msg`, `post-rewrite`, ...):
  hooks are the project's code, and running them there would give it the
  agent. Run the checks a hook would run as their own commands.
- The signing program can't come from the project: `gpg.format` is pinned to
  `ssh`, and `gpg.ssh.program` and `gpg.ssh.defaultKeyCommand` to your system
  and global values (read outside any repository; `ssh-keygen` and none when
  unset), at a level that outranks `.git/config`. `gpg.program` and
  `gpg.x509.program`, which `git tag -v` and `merge --verify-signatures` run
  for OpenPGP and X.509 signatures, stay pinned to `false`.
- The filter signs git signatures only while the option is on.

Without it, a signing commit runs in the shared worker, which has no agent, and
fails.
