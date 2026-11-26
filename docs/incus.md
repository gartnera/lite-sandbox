# Incus / LXD access

The `incus` section lets the `incus` and `lxc` CLIs manage containers through a
**filtering proxy** instead of the daemon's own unix socket, which grants full,
root-equivalent control of the host. Incus and LXD share the REST API, so one
proxy serves both CLIs. The proxy confines the sandbox to one project and to
the instances it created, and holds instance configuration to the defaults of
an Incus [restricted project](https://linuxcontainers.org/incus/docs/main/reference/projects/).
Normal workflows work with the CLIs' default options: `launch`, `list`,
`exec`, `file push`/`pull`, `config set`/`edit`, `snapshot`, `copy`, `publish`,
`stop`, `delete`.

```yaml
incus:
  enabled: false            # Allow incus/lxc through the proxy (default: false)
  socket_path: ""           # Daemon socket; auto-detected if empty
  project: default          # Project every request is pinned to (default: "default")
  tagged_only: true         # Only instances the sandbox created (default: true)
  allow_privileged: false   # Privileged instances, low-level options, passthrough devices (default: false)
  allow_nesting: false      # security.nesting=true (default: false)
  allow_unsandboxed: false  # Permit incus/lxc without the OS sandbox (default: false)
```

When enabled, lite-sandbox serves the proxy on a private unix socket and sets,
for sandboxed commands, `INCUS_SOCKET` and `LXD_SOCKET` to it, and `INCUS_CONF`
and `LXD_CONF` to fresh per-session client configuration directories. The CLIs
therefore start from their defaults (the `local` daemon, the public image
remotes) whatever your own `~/.config/incus` holds; your remotes and aliases
are not used inside the sandbox.

**Requires the OS sandbox.** The worker masks the daemon's directories
(`/run/incus`, `/var/lib/incus`, `/var/snap/lxd/common/lxd`,
`/var/snap/lxd/common/lxd-user`, `/var/lib/lxd`, with the admin, `incus-user`
and `lxd-user` sockets in them), the upstream socket, and the CLIs' own client
configuration directories (`~/.config/incus`, `~/.config/lxc`, the OS
configuration directory's `incus` and `lxc` on macOS (`~/Library/Application
Support`), `~/snap/lxd/common/config`, `$INCUS_CONF`, `$LXD_CONF`), whose client keys,
OIDC tokens and remotes reach a daemon over HTTPS.

The proxy reads its settings when lite-sandbox starts: restart it (the agent
session) after changing the `incus` section or the path grants. Without the OS sandbox a command could point
`INCUS_SOCKET` at the real socket, so incus and lxc are refused unless
`os_sandbox` is enabled or `allow_unsandboxed: true` is set (not recommended).

## What the proxy enforces

- **One project**: requests are pinned to `project`. A request naming another
  project (`--project`, `INCUS_PROJECT`), `--all-projects`, or a body that
  copies or moves an instance across projects is refused, and only the pinned
  project can be read (`incus project list` shows just it). For a boundary the
  daemon enforces as well, point `project` at a restricted project.
- **Tagged-only (default)**: instances created through the proxy get
  `user.lite-sandbox=true` in their own config (a profile cannot lend it), and
  every per-instance request — exec, files, state, snapshots, config, delete,
  copying, refreshing a copy onto it, publishing it — needs the tag. Instance
  listings show only tagged instances. Profiles are shared with every
  instance, so profile writes are refused in this mode. Images are shared too:
  the ones the sandbox publishes or uploads get a `user.lite-sandbox` property,
  and only those can be changed or deleted; an existing alias can be changed,
  renamed or deleted only when it points at one of them (new aliases can be
  created). Copying an image from a server or URL (`incus image copy`) is
  refused, since the daemon merges a copy into an image the project already
  holds and rewrites its profiles and visibility; launching from a remote image
  (`incus launch images:...`) works, and the image the daemon caches for it can
  be used but not changed or deleted. Custom storage volumes the sandbox
  creates are tagged in their config, and only those can be deleted.
  `tagged_only: false` opens every instance in the project, and profile writes
  then pass the same policy as instances.
- **Endpoint allowlist**: the server, events and operations reads; instances
  and their sub-resources; images and aliases; profiles; creating and deleting
  custom storage volumes (empty, or copied in the project); reads of projects,
  networks and storage pools.
  Everything else is refused with 403: server configuration, certificates,
  cluster, project/network/storage-pool writes (`raw.dnsmasq` would configure
  a host process), backup imports, migrations, debug endpoints.
- **Instance policy** (unless `allow_privileged`), mirroring a restricted
  project's defaults except for NICs, which are looser:
  - `security.privileged`, and `security.nesting` unless `allow_nesting`;
  - low-level options: `raw.*`, `linux.kernel_modules`,
    `security.idmap.base`/`size`, `security.syscalls.*` (except `deny`,
    `deny_compat`, and `deny_default` left on), `security.bpffs*`, the SELinux
    keys, `boot.host_shutdown_*`, and the other keys Incus lists as low-level;
  - `volatile.*` keys other than the ones a restricted project lets clients set
    (`volatile.<dev>.hwaddr`, ...): the recorded idmap would map the container's
    root to the host's;
  - devices other than `disk`, `nic`, `tpm` and `none` (`unix-char`,
    `unix-block`, `unix-hotplug`, `usb`, `gpu`, `pci`, `infiniband`, `proxy` —
    a proxy device can forward a host socket into the container), and disks
    with `shift`, `raw.mount.options`, shared propagation, or a Ceph source;
  - NICs that hand over or pass through host hardware or rewrite the host's
    routing: `nictype` `physical` (or `network=` naming a managed physical
    network), `sriov`, `routed` and `ipvlan` (host routes and proxy ARP), and
    the options `ipv4/ipv6.routes`, `.routes.external`, `.host_address`,
    `.host_table(s)` and `host_name`. Other NICs are allowed, managed or not:
    `bridged` (on any host bridge), `macvlan`, `p2p`, `ovn`;
  - restoring another instance's snapshot (`restore: other/snap`), which
    would apply that instance's configuration.
- **Disks**: pool-backed disks (the root disk, custom volumes) and the
  cloud-init and agent config drives are allowed. A host-path `source` is a
  bind mount: see [host-path disks](#host-path-disks).
- **Changes only**: `PUT`/`PATCH` checks only the keys and devices that differ
  from the daemon's current copy, so `incus config set` and `config edit` keep
  working on an instance carrying volatile state or settings an administrator
  added.
- **Request bodies** are decoded the way the daemon decodes them; a body with
  two fields that differ only in case (`config` and `Config`) is refused, since
  which one the daemon uses depends on their order.
- **Profiles**: an instance's profiles are checked whole when it is created and
  when one is added, so it cannot pick up a privileged profile defined by
  someone else. A create that names no profiles is sent with `["default"]`
  explicitly, since the daemon would otherwise apply the image's own profile
  list, which the proxy cannot see.
- **Sources**: instances are created from an image, empty, or as a copy of an
  instance in the project (in tagged-only mode, a tagged one) whose
  configuration passes the policy. Migration, conversion, and backup imports are
  refused.

## Host-path disks

A disk device with a host-path `source` must resolve inside the sandbox
boundary (`readonly=true` within the readable paths, otherwise within the
writable paths), and even then it is refused unless the daemon itself keeps it
there. The daemon opens the source path afresh every time the instance starts,
following symlinks, so a path the sandbox can write could point anywhere by
then (`ln -sfn / dir; incus restart c`). Only a restricted project with
`restricted.devices.disk.paths` makes the daemon open the source beneath the
listed prefix, refusing a path that escapes it. The `default` project cannot be
restricted, so host-path disks need a dedicated project:

```bash
incus project create sandbox -c features.images=false \
  -c restricted=true -c restricted.devices.disk=allow \
  -c restricted.devices.disk.paths=/home/me/project
# A restricted project has its own profiles: give its default profile a root disk and a NIC.
incus profile device add default root disk path=/ pool=default --project sandbox
incus profile device add default eth0 nic network=incusbr0 name=eth0 --project sandbox
lite-sandbox config incus enable --project sandbox
```

The prefix the daemon uses (the first listed that contains the source) must
itself lie inside the boundary and must not be strictly inside a writable path,
since the daemon opens the prefix following symlinks and the sandbox could
replace it: the working directory itself is the usual choice. `shift` is
refused, as the daemon refuses it under restricted paths too. A VM's disk share
is written as the guest's root, so files created through it are owned by root
on the host. `allow_privileged` lifts all of this except the boundary check.

## Limitations

- An instance that already exists with a privileged configuration can still be
  used (in `tagged_only: false` mode, or once tagged by hand): `exec` into it is
  root on the host. Keep such instances in another project.
- Tagged-only mode is a check in the proxy; the events stream and operations
  list still describe every instance in the project. Incus releases that keep
  exec websocket secrets in operation events (before the change that limited
  them to the creator) would show those secrets too. Use a dedicated project
  where that matters.
- Custom storage volumes are checked only when deleted: any custom volume in
  the project can be attached to the sandbox's instances.
- The LXD snap's `lxc` wrapper may not run inside the OS sandbox (snap
  confinement); a non-snap `lxc` or `incus` client works against an LXD daemon.

## Socket auto-detection

If `socket_path` is unset, the daemon socket is resolved in this order:
`INCUS_SOCKET` → `$INCUS_DIR/unix.socket` → `LXD_SOCKET` →
`$LXD_DIR/unix.socket` → the first existing socket among
`/run/incus/unix.socket`, `/var/lib/incus/unix.socket`,
`/var/snap/lxd/common/lxd/unix.socket`, `/var/lib/lxd/unix.socket`, and
Colima's `~/.colima/default/incus.sock` → `/var/lib/incus/unix.socket`. Set
`socket_path` to incus-user's `unix.socket.user` to go through the per-user
project it manages.

## CLI

```bash
lite-sandbox config incus show                      # Show current incus config
lite-sandbox config incus enable [--socket <path>] [--project <name>]  # Enable the proxy
lite-sandbox config incus tagged-only               # Only the sandbox's own instances (default)
lite-sandbox config incus all-instances             # Every instance in the project
lite-sandbox config incus allow-privileged          # Privileged instances, low-level options, passthrough devices
lite-sandbox config incus allow-nesting             # security.nesting
lite-sandbox config incus allow-unsandboxed         # Permit incus/lxc without the OS sandbox (weakens the boundary)
lite-sandbox config incus disable                   # Disable incus access
```
