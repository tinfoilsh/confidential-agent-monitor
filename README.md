# Perimeter

Perimeter controls how AI agents use your accounts to read repositories, send
email, query databases, and call models. You set permissions and approve
requests through a web UI or TOML policy.

Credentials stay in the Perimeter. Agents receive placeholders. Perimeter supplies the
real credentials after checking each request. Stored state is encrypted with
your owner secret.

## How it works

Agents connect over SSH using their own keys. Perimeter interprets requests,
checks permissions, then forwards, denies, or holds them for approval. Service
presets describe operations and effects such as reading, deleting, or publishing.

Perimeter also tracks private and untrusted data an agent has read. Data-flow
rules can require approval before it shares that data or acts on untrusted input.

These controls apply to traffic routed through the Perimeter. Bunkers provide
process isolation and network restrictions. The local CLI only configures
routing for compatible clients.

## Get started

### Tinfoil Bunkers

Create a Perimeter and a bunker in it from the
[Tinfoil dashboard](https://dash.tinfoil.sh/). Using the
[Tinfoil CLI](https://github.com/tinfoilsh/tinfoil-cli/releases), connect to your
bunker, named `work` in this example.

```sh
tinfoil attest-ssh work --install
ssh work
```

In the Perimeter, add services under **Permissions** and grant the bunker access
under **Bunkers**. Run `perimeter services` inside the bunker to see what's available.
Repeat attestation after either VM reboots.

### Local commands

Install the CLI from this checkout. It requires Python 3.11+ and OpenSSH on Linux
or macOS.

```sh
./install.sh
export PATH="$HOME/.local/bin:$PATH"
```

Add your public key under **Bunkers → Trusted devices** and grant it access.
Configure an SSH alias named `perimeter` with that identity and the Perimeter's
verified host key, or select a configuration with `--ssh-host` and `--ssh-config`.

```sh
perimeter services
perimeter catalog
perimeter run -- your-command
perimeter shell
```

Use `perimeter mcp serve` to connect local MCP clients. Trusted-device automation
should follow the full [Perimeter skill](client/skills/perimeter/SKILL.md) for
catalog discovery, broad credential-free reads, proposals and direct API calls. Managed bunker
images should seed the reduced [bunker skill](client/skills/perimeter-sandbox/SKILL.md),
which covers only that bunker's discovery, policy, proposals, credentials boundary
and service usage.

### Local bunkers

The CLI can launch coding agents in local bunkers connected to an existing Perimeter.

```sh
perimeter setup
perimeter launch claude    # or codex, opencode, pi, shell
```

Nothing is built locally. The first launch downloads one image holding the base
system and every agent. All bunkers share it read-only and keep their own changes
in a writable layer, so a new image reaches every bunker on its next launch;
container bunkers keep `/workspace` and home in volumes and are recreated from it.
An agent uses the one Anthropic or OpenAI service it supports, or the one named
with `--service`; a new bunker is granted that service.

`perimeter setup --backend` chooses the isolation. Each bunker's only network is
its link to the Perimeter.

| Backend                          | Isolation                       | Also requires                                                                         |
| -------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------- |
| `firecracker` (default on Linux) | KVM virtual machine             | x86_64 Linux, writable `/dev/kvm`, bubblewrap, `mke2fs` 1.47.1+ with libarchive       |
| `docker` (default on macOS)      | container with `--network none` | Docker, or Podman as `docker`                                                         |
| `vfkit`                          | Virtualization.framework VM     | Apple silicon, `mke2fs` 1.47.1+ with libarchive (nixpkgs `e2fsprogs`, not Homebrew's) |
| `bwrap`                          | unprivileged namespaces         | Linux, bubblewrap with overlay support, unprivileged user namespaces, `script`        |

All need OpenSSH and GNU tar (`gtar` on macOS). Containers share their engine's
kernel, and bwrap the host's. Setup asks for your Perimeter endpoint, owner
credentials, and service permissions; its defaults reach a local Perimeter, and
the passphrase you enter claims a fresh one. The [daemon](#run-a-perimeter-locally)
runs setup for you.
See `perimeter --help` for stopping, exporting, and deleting bunkers.

`dev/vm-artifacts DIR [ARCH...]` builds the image for x86_64 and aarch64 with
Docker alone and pins it in
[client/vm/assets.json](client/vm/assets.json). It also caches the image, so this
checkout's `client/perimeter`, or a CLI installed from it with `./install.sh`,
launches it without downloading. Each agent is its
vendor's release binary, pinned by URL and SHA-256 in
[client/vm/agents.json](client/vm/agents.json).

A bunker reaches another as `NAME.sandbox`, where NAME is that bunker's identity;
only listeners bound to `0.0.0.0` answer. Set Other bunkers to Ask on the dialing
bunker, then approve each bunker and port the first time it connects.

```sh
perimeter launch shell --name b -- python3 -m http.server 8080 --bind 0.0.0.0
perimeter launch shell --name a           # then: curl http://b.sandbox:8080
```

### Run a Perimeter locally

```sh
./install.sh --daemon
```

This builds the checkout with Go and Bun and runs it as a user service on
`127.0.0.1:8081`, with its state and owner key in `~/.local/share/perimeter/server`.
It also installs the CLI, pairs this computer as a trusted device and sets up
bunker launch. Sign in to [the UI](http://127.0.0.1:8081/app/) with the owner
key. Run it from another checkout to switch the daemon to that code; the previous
store is kept in `store.prev`. Logs are in `journalctl --user -u perimeter` on
Linux and `server.log` on macOS.

To run one in the foreground instead, use the Go version in [go.mod](go.mod).

```sh
mkdir -p .dev/store
go run . -bucket "file://$(pwd)/.dev/store?no_tmp_dir=true"
```

Open [the UI](http://127.0.0.1:8080/app/) and initialize an owner key or passphrase.
SSH listens on `127.0.0.1:2223`. See [Dockerfile](Dockerfile) and
[tinfoil-config.yml](tinfoil-config.yml) for deployment configuration.

## Access control

In **Bunkers**, set each bunker's access to each service.

| Access    | TOML/API | Default behavior                         |
| --------- | -------- | ---------------------------------------- |
| No access | `off`    | Deny access.                             |
| Read only | `read`   | Allow recognized reads and deny changes. |
| Ask       | `ask`    | Allow reads and ask before changes.      |
| Allow     | `allow`  | Allow recognized operations.             |

Expand a service to override individual actions. Action and effect overrides
use `off`, `ask`, and `allow`; `off` means Deny. Other policy checks still apply,
and an approval cannot override an explicit denial. Pending requests appear at
the top of **Permissions** and as notices on other pages.

Payments and publishing default to Ask. Onboarding enables **Allow paid AI
inference**, which skips payment approval for model generation unless an explicit
payment setting requires it.

## How to edit Perimeter policy

- **Owner UI:** People make supported changes directly under **Permissions** and
  **Bunkers**. Configure credentials through service settings;
  credentials are stored separately from policy.
- **Agent proposals:** Bunkers and trusted devices can inspect their policy with
  `perimeter policy show` and submit service-scoped changes for owner review with
  `perimeter policy propose`. Trusted devices receive a credential-free, expanded
  configuration projection, while bunkers see only their own access and reachable
  service semantics. This view materializes inherited settings and is not source
  TOML. Both remain limited to service-scoped proposals. See the full
  [Perimeter skill](client/skills/perimeter/SKILL.md) and reduced
  [bunker skill](client/skills/perimeter-sandbox/SKILL.md) for TOML, structured
  changes, direct API requests, and credential boundaries.
- **Owner API:** The owner API is root authority and applies full-policy changes
  directly. Use it only for intentional owner operations, preview the TOML diff
  before applying it, and never give owner credentials to a bunker or routine
  automation. Credentials are not part of policy TOML.

With owner authentication, `perimeter policy diff FILE` validates a complete TOML
policy replacement and `perimeter policy apply FILE` applies it. By contrast,
`perimeter policy propose FILE --reason …` submits a service-scoped TOML fragment
for review; `--changes FILE` submits structured path/value/deletion edits instead.

Automation on a paired computer should use its trusted-device identity instead of
an owner session:

```sh
perimeter policy propose --changes changes.json \
  --reason "Configure GitHub access"
```

The changes file is an array of `{ "path": [...], "value": ... }` or deletion
changes. The Perimeter validates the entire submission and splits it into one proposal
per service.
