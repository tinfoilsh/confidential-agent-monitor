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

`monitor catalog --json` returns the safe connection catalog, including shared
warning copy, to both sandboxes and trusted devices. `monitor policy show`
is identity-scoped: a sandbox sees only its own settings and reachable-account
semantics, while a trusted device sees the complete non-secret Monitor
configuration, including identities, public keys, routes, access and global
settings. Credentials are never part of either policy view.

Use `monitor mcp serve` to connect local MCP clients. Trusted-device automation
should follow the full [Monitor skill](client/skills/monitor/SKILL.md) for catalog
discovery, broad non-secret reads, proposals and direct API calls. Managed sandbox
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

### Experimental development connectors

Normal builds exclude the Browser connector implementation, registration and
`-extension` flag, including worker mode. Browser and raw Custom presets are not
shipped. The backend source is retained for explicit development builds:

```sh
mkdir -p .dev
go build -tags monitor_dev -o .dev/monitor-dev .
```

Browser still requires its extension/runtime dependencies; its old UI and client
command are not restored. Experimental preset definitions are kept as non-embedded
fixtures in `dev/presets/experimental/`. Do not publish a `monitor_dev` binary as a
release artifact: `-production` does not turn it into one. A tagged parent disables
Browser with that flag, but worker subprocesses do not inherit the flag; release
exclusion is enforced by the build tag, not by a worker's runtime options.

Old configurations referencing the removed presets or Browser protocol are not
supported. There is no migration or inactive-record compatibility layer.

## Access control

In **Agents**, set each agent's access to each account.

| Access    | Default behavior                         |
| --------- | ---------------------------------------- |
| No access | Deny access.                             |
| Read only | Allow recognized reads and deny changes. |
| Ask       | Allow reads and ask before changes.      |
| Allow     | Allow recognized operations.             |

Expand an account to override individual actions. Set effect permissions—such
as payments, publishing, or deletion—in **Settings**, with overrides per account
or agent. Other policy checks still apply. Review pending requests in
**Activity**. Approvals cannot override an explicit denial.

Payments and publishing default to Ask. Onboarding enables **Allow paid AI
inference**, which skips payment approval for model generation unless an explicit
payment setting requires it.

### TOML

**Settings → Policy editor** edits the same policy as the UI. Validate changes,
review the diff, then apply. Credentials are stored separately.

For an existing agent and GitHub account, merge these settings into your policy
using their names. They allow reads, ask before changes, and deny deletion.

```toml
[identities.agent.accounts.github]
level = "ask"

[identities.agent.accounts.github.effects]
delete = "off"
```

Account levels are `off`, `read`, `ask`, and `allow`. Action and effect overrides
use `off`, `ask`, and `allow`. The value `off` means Deny. Agents can inspect their settings
with `monitor policy show` and submit connection changes with
`monitor policy propose` for owner approval.

Automation on a paired computer should use its trusted-device identity rather than
an owner-panel session. It can submit TOML, or the structured changes already used
by setup tools:

```sh
monitor policy propose --changes changes.json \
  --reason "Configure GitHub access"
```

The JSON file is an array of `{ "path": [...], "value": ... }` or deletion
changes. Monitor splits a multi-connection submission into one proposal per
connection. Credentials are configured separately through owner account settings.
