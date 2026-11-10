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

### Local VM

The CLI can launch Claude in a Firecracker VM connected to an existing Perimeter.

```sh
perimeter image build
perimeter setup
perimeter launch claude
```

This requires x86_64 Linux, writable `/dev/kvm`, bubblewrap, unprivileged user
namespaces, OpenSSH, GNU tar, and `mke2fs`. Image builds need Podman or Docker.
Setup asks for your Perimeter endpoint, owner credentials, and service permissions;
its defaults reach a local Perimeter, and the passphrase you enter claims a fresh one.
See `perimeter --help` for stopping, exporting, and deleting VMs.

Each VM network is restricted to the Perimeter. A bunker reaches another as
`NAME.sandbox`, where NAME is that bunker's identity; only listeners bound to
`0.0.0.0` answer. Set Other bunkers to Ask on the dialing bunker, then approve
each bunker and port the first time it connects.

```sh
perimeter launch shell --name b -- python3 -m http.server 8080 --bind 0.0.0.0
perimeter launch shell --name a           # then: curl http://b.sandbox:8080
```

### Run a Perimeter locally

Start a Perimeter using the Go version in [go.mod](go.mod).

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
