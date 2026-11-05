# Monitor

Monitor controls how AI agents use your accounts to read repositories, send
email, query databases, and call models. You set permissions and approve
requests through a web UI or TOML policy.

Credentials stay in Monitor. Agents receive placeholders. Monitor supplies the
real credentials after checking each request. Stored state is encrypted with
your owner secret.

## How it works

Agents connect over SSH using their own keys. Monitor interprets requests,
checks permissions, then forwards, denies, or holds them for approval. Service
presets describe operations and effects such as reading, deleting, or publishing.

Monitor also tracks private and untrusted data an agent has read. Data-flow
rules can require approval before it shares that data or acts on untrusted input.

These controls apply to traffic routed through Monitor. Sandboxes provide
process isolation and network restrictions. The local CLI only configures
routing for compatible clients.

## Get started

### Tinfoil Sandboxes

Create a Monitor and sandbox in the [Tinfoil dashboard](https://dash.tinfoil.sh/),
with Monitor enabled. Using the
[Tinfoil CLI](https://github.com/tinfoilsh/tinfoil-cli/releases), connect to your
sandbox, named `work` in this example.

```sh
tinfoil attest-ssh work --install
ssh work
```

In Monitor, add services under **Connections** and grant the sandbox access under
**Agents**. Run `monitor connections` inside the sandbox to see what's available.
Repeat attestation after either VM reboots.

### Local commands

Install the CLI from this checkout. It requires Python 3.11+ and OpenSSH on Linux
or macOS.

```sh
./install.sh
export PATH="$HOME/.local/bin:$PATH"
```

Pair your public key under **Agents → Pair agent** and grant it access. Configure
an SSH alias named `monitor` with that identity and Monitor's verified host key,
or select a configuration with `--ssh-host` and `--ssh-config`.

```sh
monitor connections
monitor catalog
monitor run -- your-command
monitor shell
```

Use `monitor mcp serve` to connect local MCP clients. Trusted-device automation
should follow the full [Monitor skill](client/skills/monitor/SKILL.md) for
catalog discovery, broad credential-free reads, proposals and direct API calls. Managed sandbox
images should seed the reduced [sandbox Monitor skill](client/skills/monitor-sandbox/SKILL.md),
which covers only that sandbox's discovery, policy, proposals, credentials boundary
and connection usage.

### Local VM

The CLI can launch Claude in a Firecracker VM connected to an existing Monitor.

```sh
monitor image build
monitor setup
monitor launch claude
```

This requires x86_64 Linux, writable `/dev/kvm`, bubblewrap, unprivileged user
namespaces, OpenSSH, GNU tar, and `mke2fs`. Image builds need Podman or Docker.
Setup asks for your Monitor endpoint, owner credentials, and account permissions.
See `monitor --help` for stopping, exporting, and deleting VMs.

### Run Monitor locally

Start Monitor using the Go version in [go.mod](go.mod).

```sh
mkdir -p .dev/store
go run . -bucket "file://$(pwd)/.dev/store?no_tmp_dir=true"
```

Open [the UI](http://127.0.0.1:8080/app/) and initialize an owner key or passphrase.
SSH listens on `127.0.0.1:2223`. See [Dockerfile](Dockerfile) and
[tinfoil-config.yml](tinfoil-config.yml) for deployment configuration.

### UI development previews

```sh
(cd ui && bun install --frozen-lockfile)
bun dev/console.ts
```

Open [Terminal](http://127.0.0.1:5176/) or the
[standalone Monitor](http://127.0.0.1:5176/standalone). Append
`?preview=onboarding` to preview setup. Terminal's `/monitor/<id>` route also
supports `preview=full-flow`, `keys-loading`, `inventory-loading`,
`sandboxes-loading`, `monitor-booting`, `monitor-startup`, `monitor-locked`,
`monitor-opening`, `monitor-stopped`, and `monitor-error`.

This uses a real local Monitor with fake account/passkey fixtures, not cloud
resources. State stays in `.dev/console/`; ports 5176, 8083, and 2226 must be free.
Sandbox VMs and shells are not started. The fixture account is always signed in;
sign-out reloads the preview rather than simulating authentication flows.
This preview mode cannot be built for deployment.

## Access control

In **Agents**, set each sandbox's access to each connection.

| Access    | TOML/API | Default behavior                         |
| --------- | -------- | ---------------------------------------- |
| No access | `off`    | Deny access.                             |
| Read only | `read`   | Allow recognized reads and deny changes. |
| Ask       | `ask`    | Allow reads and ask before changes.      |
| Allow     | `allow`  | Allow recognized operations.             |

Expand a connection to override individual actions. Action and effect overrides
use `off`, `ask`, and `allow`; `off` means Deny. Other policy checks still apply,
and an approval cannot override an explicit denial. Review pending requests in
**Activity**.

Payments and publishing default to Ask. Onboarding enables **Allow paid AI
inference**, which skips payment approval for model generation unless an explicit
payment setting requires it.

## How to edit Monitor policy

- **Owner UI:** People make supported changes directly under **Connections**,
  **Agents**, and **Settings**. Configure credentials through connection settings;
  credentials are stored separately from policy.
- **Agent proposals:** Sandboxes and trusted devices can inspect their policy with
  `monitor policy show` and submit connection-scoped changes for owner review with
  `monitor policy propose`. Trusted devices receive a credential-free, expanded
  configuration projection, while sandboxes see only their own access and reachable
  connection semantics. This view materializes inherited settings and is not source
  TOML. Both remain limited to connection-scoped proposals. See the full
  [Monitor skill](client/skills/monitor/SKILL.md) and reduced
  [sandbox skill](client/skills/monitor-sandbox/SKILL.md) for TOML, structured
  changes, direct API requests, and credential boundaries.
- **Owner API:** The owner API is root authority and applies full-policy changes
  directly. Use it only for intentional owner operations, preview the TOML diff
  before applying it, and never give owner credentials to a sandbox or routine
  automation. Credentials are not part of policy TOML.

With owner authentication, `monitor policy diff FILE` validates a complete TOML
policy replacement and `monitor policy apply FILE` applies it. By contrast,
`monitor policy propose FILE --reason …` submits a connection-scoped TOML fragment
for review; `--changes FILE` submits structured path/value/deletion edits instead.

Automation on a paired computer should use its trusted-device identity instead of
an owner session:

```sh
monitor policy propose --changes changes.json \
  --reason "Configure GitHub access"
```

The changes file is an array of `{ "path": [...], "value": ... }` or deletion
changes. Monitor validates the entire submission and splits it into one proposal
per connection.
