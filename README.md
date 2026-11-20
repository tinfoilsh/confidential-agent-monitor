# Perimeter

A **Perimeter** lets you control how services and their credentials get used by your workloads, without handing over any secrets.

Instead of connecting a workload/environment to services directly, a Perimeter sets precise policies on exactly what kinds of actions are and aren't allowed, and substitutes / proxies real credentials on the workload's behalf.

The perimeter was designed to be **fail-closed**. To enforce policies such as *read-only*, we use **presets** on connectors to undestand the full behavior of a platform being used, and deny unknown requests. We ship hundreds of pre-configured and frequently updated connector definitions to use out of the box.

Want a fully confidential workspace built for long running tasks, better availability, access from your phone, or for running untrusted code? Check out [Tinfoil Bunkers](https://tinfoil.sh/bunkers)! Tinfoil Bunkers are fortified against compromised infrastructure, rogue agents, and are verifiably end-to-end private. All bunkers run inside a secure enclave, where every piece of code up to the firmware, is fully verifiable and open source.

You can also run a Perimeter locally, for smaller agent isolation usecases.

## Get started

### Local setup

You can get set up with a local perimeter through the CLI:

``` sh
./install.sh --daemon # Build, install, and enable the perimeter as a daemon

export PATH="$HOME/.local/bin:$PATH" # Add this to your .bashrc, .zshrc, etc.
```

After that's done, off to the races:

```sh
# Start a firecracker (or vfkit on Mac) VM with an agent running and the current directory loaded in
perimeter launch claude # codex,opencode,pi,shell also supported

perimeter connections # List connections and whether they are ready
perimeter catalog # View the catalog of possible connections
perimeter run -- your-command # Run a command with Perimeter-aware substitution and routing
perimeter shell # Enter a shell that uses a Perimeter for access
```

You can also open the webui at `localhost:8081/app` to access the local control panel. The key to unlock it is in `~/.local/share/perimeter/server/owner.key`.

`perimeter setup --backend` lets you pick an isolation primitive. Supported:

| Backend                          | Isolation                       |
| -------------------------------- | ------------------------------- |
| `firecracker` (default on Linux) | KVM virtual machine             |
| `docker` (default on macOS)      | container with `--network none` |
| `vfkit`                          | Virtualization.framework VM     |
| `bwrap`                          | unprivileged namespaces         |

### Tinfoil Bunkers

Tinfoil provides fully confidential, end-to-end attested bunkers and perimeters which act as an extension of your laptop. You can set them up in the [Tinfoil dashboard](https://dash.tinfoil.sh/), or using the [Tinfoil CLI](https://github.com/tinfoilsh/tinfoil-cli/releases):

``` sh
tinfoil perimeter create my-perimeter
tinfoil bunker create work --perimeter=my-perimeter
```

Once created, you can pin the bunkers SSH keys to the attestation and connect:

```sh
tinfoil attest-ssh work --install
ssh work
```

In the Bunker, you can use the `perimeter` CLI to manage from the inside, and the Perimeter is the only point of egress.

Tinfoil-hosted Perimeters are convenient for a number of reasons:
- Accessible both on your cloud workloads, and your personal devices
- Zero-data **exposure**, instead of zero-data retention (fully confidential, with an attested image)
- Runs a specialized workload that only runs an attested Perimeter, making for a *much smaller attack surface* than a workstation computer

For a Tinfoil-hosted Perimeter, run `perimeter setup --tinfoil NAME` instead, which performs full attestation against your key and registers your CLI to use the remote endpoint.
You will need the [Tinfoil CLI](https://github.com/tinfoilsh/tinfoil-cli/releases) to perform the attestation.

A Tinfoil-hosted perimeter has a WebUI that can be opened via `tinfoil perimeter open my-perimeter`

## How to edit Perimeter policy

- **Owner UI:** People make supported changes directly under **Permissions** and
  **Bunkers**. Configure credentials through service settings;
  credentials are stored separately from policy.
- **Agent proposals:** Bunkers and trusted devices can inspect their policy with
  `perimeter policy show` and submit service-scoped changes for owner review with
  `perimeter policy propose`. Trusted devices receive a credential-free, expanded
  configuration projection, while bunkers see only their own access and reachable
  service semantics. This view materializes inherited settings and is not source
  TOML. Both remain limited to service-scoped proposals. See the
  [Perimeter skill](client/skills/perimeter/SKILL.md) for using connections and
  proposing changes from either.
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
