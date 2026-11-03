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
monitor run -- your-command
monitor shell
```

Use `monitor mcp serve` to connect local MCP clients.

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

### Local development console (fake account)

To explore the hosted Terminal UI against a real local Monitor, without Clerk,
passkey prompts, cloud resources, or sandbox VMs:

```sh
(cd ui && bun install --frozen-lockfile)
bun dev/console.ts
```

Open **http://127.0.0.1:5175**. The console hot-reloads local UI changes and seeds
`danielbox1`, `danielbox2`, a trusted development device, and network access
settings. The sandbox rows are fake, CLI-only inventory/identities: attestation,
enrollment, and shells are deliberately unavailable. Monitor configuration and
permission edits are real and persist across restarts, under **`.dev/console/`**.
No existing `.dev/store`, SSH configuration, account, or running service is used.
The runner refuses to start if ports 5175, 8082, or 2225 are occupied.

This replaces the older `dmccanns/dev-mode` console with the current key-bundle
and session flow. Only the account/passkey provider and resource inventory are
fake; the normal session, encrypted key-bundle code, and local Monitor API are
used. Development passkey records intentionally contain plaintext keys. All
credentials are throwaway, publicly known fixtures: **never use real keys or
credentials here, expose these servers, or deploy this mode**. The local mode
cannot be built, and its entry is excluded from production builds.

For the full successful walkthrough, open **http://127.0.0.1:5175/?state=full-flow**.
Unlock with the fake passkey, select `monitor`, and watch booting → verification
→ sandbox skeletons → populated Monitor UI. Every loading stage finishes;
booting starts only after selecting the Monitor. Reopen the same link to restart
the demonstration. No VM is actually booted or restarted by this demo.

For frozen loading/startup previews, append `?state=keys-loading`,
`?state=inventory-loading`, `?state=sandboxes-loading`, `?state=monitor-booting`,
`?state=monitor-opening`, or `?state=monitor-stopped` to a Monitor page URL.
`?state=monitor-error` fails the first open; clicking **Try again** retries
against the real local backend. `?state=monitor-locked` shows the key-unlock
step and then opens the Monitor when you click **Unlock with passkey** (without
a real passkey prompt in dev mode). `?state=monitor-startup` shows booting for
five seconds, then automatically opens the running local Monitor. Inventory loading can also be viewed at
`/?state=inventory-loading`. These are render-only overrides: they never stop or
restart a Monitor, change its saved configuration, or clear actual keys. Remove
the query parameter to return to the normal preview.

Stop with Ctrl-C. To reset this development instance, stop it first and remove
only `.dev/console/`, then restart. No development reset changes production state.

## Access control

In **Agents**, set each agent's access to each account.

| Access | Default behavior |
| --- | --- |
| No access | Deny access. |
| Read only | Allow recognized reads and deny changes. |
| Ask | Allow reads and ask before changes. |
| Allow | Allow recognized operations. |

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
with `monitor policy show` and submit changes with `monitor policy propose` for
owner approval.
