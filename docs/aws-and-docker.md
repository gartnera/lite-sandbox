# AWS & Docker Access

Both of these are opt-in integrations that let sandboxed commands reach AWS and
Docker **without** handing them your raw credentials or an unrestricted daemon
socket. Both are disabled by default and most useful with the
[OS sandbox](security.md#os-level-sandboxing-optional) enabled.

## AWS credentials

By default the OS sandbox denies access to `~/.aws`. The `aws` config section
controls how (and whether) sandboxed commands get credentials. It has two
mutually exclusive modes:

```yaml
aws:
  allow_raw_credentials: false  # let commands read ~/.aws directly (default: false)
  force_profile: ""             # broker credentials for this profile via a local IMDS server (default: "")
```

- **Disabled** (no `aws` section) — `~/.aws` stays blocked under the OS sandbox; commands have no AWS credentials.
- **Raw credentials** (`allow_raw_credentials: true`) — `~/.aws` is left readable so the AWS CLI/SDK use your long-term credential files directly. Simplest, but exposes the credential files to sandboxed commands.
- **Brokered via IMDS** (`force_profile: "<profile>"`) — lite-sandbox starts a local [IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)-compatible metadata server on `127.0.0.1` (random port), resolves **temporary** credentials for the named profile, and injects `AWS_EC2_METADATA_SERVICE_ENDPOINT` into the sandbox so the SDK fetches them from there. `~/.aws` is blocked, so the raw credential files are never exposed — only short-lived, auto-refreshed credentials reach the command. Works with SSO, assume-role, and IAM-user profiles.

> SSH private keys in `~/.ssh` are always blocked by the OS sandbox regardless of the AWS mode.

### Per-directory overrides

`overrides` lets either mode be changed for specific working directories, so one
config can broker a different profile (or switch modes entirely) depending on
where the sandbox is launched. Each override matches the working directory it is
started in — at the override's `path` or any directory beneath it — and the most
specific (longest) matching `path` wins. A matching override fully defines the
mode for that directory; its fields replace the base settings rather than
merging, so the two modes never mix.

```yaml
aws:
  force_profile: "default"        # base mode for everything else
  overrides:
    - path: ~/work/acme           # ~ is expanded
      force_profile: "acme-dev"   # broker a different profile here
    - path: ~/work/acme/prod
      force_profile: "acme-prod"  # more specific path wins under prod/
    - path: ~/scratch
      allow_raw_credentials: true # switch modes for this tree
```

### CLI

```bash
lite-sandbox config aws show                            # Show current AWS mode and overrides
lite-sandbox config aws allow-raw-credentials           # Enable raw-credentials mode
lite-sandbox config aws force-profile <profile>         # Enable brokered IMDS mode for <profile>
lite-sandbox config aws force-profile <profile> --dir <path>   # ...only for commands run under <path>
lite-sandbox config aws allow-raw-credentials --dir <path>     # ...only for commands run under <path>
lite-sandbox config aws remove-override <path>          # Remove a per-directory override
lite-sandbox config aws disable                         # Disable AWS access entirely
```

## Docker access

The `docker` section routes the docker CLI through a **filtering proxy** instead
of giving it the real daemon socket. The proxy enforces the sandbox's path
boundaries and blocks privilege escalation, while normal container/image
workflows keep working.

```yaml
docker:
  enabled: false               # Enable the docker proxy (default: false)
  socket_path: ""              # Upstream daemon socket; auto-detected if empty
  allow_privileged: false      # Permit privileged containers and escalation flags (default: false)
  allow_host_namespaces: false # Permit --pid=host, --net=host, --ipc=host only (default: false)
  allow_unsandboxed: false     # Permit docker without the OS sandbox (default: false)
```

When enabled, lite-sandbox starts the proxy on a private unix socket, points the
sandboxed CLI at it via `DOCKER_HOST`, and (under the OS sandbox) masks the real
daemon socket so the proxy can't be bypassed.

**Requires the OS sandbox.** Only the OS sandbox can mask the real socket and
make the proxy unbypassable — otherwise a command could just `unset DOCKER_HOST`
(or pass `-H`) and talk to `/var/run/docker.sock` directly. The proxy therefore
refuses to start unless `os_sandbox` is enabled, unless you explicitly opt out
with `allow_unsandboxed: true` (not recommended).

### What the proxy enforces

- **Endpoint allowlist** — Normal read and lifecycle operations on containers, images, networks, and volumes (plus `build`, `exec`, and BuildKit) are forwarded; anything outside the allowlist is rejected with `403`.
- **No privilege escalation** (unless `allow_privileged: true`) — rejects `--privileged`, `--cap-add`, `--device`/`--gpus`, device cgroup rules, `--security-opt` `unconfined`, host PID/IPC/user/network namespaces, and `docker build --network=host`.
- **Host namespaces** (opt-in via `allow_host_namespaces: true`) — permits just `--pid=host`, `--net=host`, and `--ipc=host` (and `docker build --network=host`) without allowing full privileged mode. The host user namespace, container-joined namespaces, and all other escalation vectors stay blocked. Implied by `allow_privileged: true`.
- **Bind-mount confinement** — host bind mounts (`-v`, `--mount type=bind`, and `local`-driver volumes with a `device` path) must resolve inside the sandbox boundary: read-only mounts within the readable paths, read-write mounts within the writable paths. Named/anonymous volumes are allowed. Ambiguous binds are rejected fail-closed.

### Upstream socket auto-detection

If `socket_path` is unset, the upstream daemon socket is resolved in this order:
`DOCKER_HOST` (unix:// only) → the active docker context → well-known per-tool
paths (Docker Desktop, OrbStack, Colima) → `/var/run/docker.sock`.

### CLI

```bash
lite-sandbox config docker show                  # Show current docker config
lite-sandbox config docker enable [--socket <path>]  # Enable the proxy (optionally pin the upstream socket)
lite-sandbox config docker allow-privileged      # Permit privileged containers / escalation flags
lite-sandbox config docker allow-host-namespaces # Permit --pid=host, --net=host, --ipc=host only
lite-sandbox config docker allow-unsandboxed     # Permit docker without the OS sandbox (weakens the boundary)
lite-sandbox config docker disable               # Disable docker access
```
