# Monitor

Policy is stored as editable TOML.

## Install or update the CLI

From this checkout on Linux or macOS, with Python 3.11 or newer and OpenSSH:

```sh
./install.sh
export PATH="$HOME/.local/bin:$PATH"
monitor --help
```

Add the `export` line to `~/.zshrc` or `~/.bashrc` to keep it in new terminals.
The installer bundles the client and VM runner into `~/.local/bin/monitor`.
The Go server binary runs only the server; client commands use this separate installation. It needs
no Go build, Python packages, or sudo. Choose another destination with
`./install.sh --bin-dir /path/to/bin`.

To update from this repository:

```sh
git pull --ff-only
./install.sh
```

Use the same `--bin-dir` when updating a custom installation. The installer uses
the files in your checkout, including local edits. It replaces the installed
client without changing SSH keys, pairing, or client profiles. Running sessions
keep their existing code; new invocations use the update.

The client connects to an existing, unlocked Monitor server through OpenSSH.
Pair your SSH public key in the Monitor web app, then configure a `monitor` host
alias in `~/.ssh/config` with the server address, SSH port, private key, and pinned
host key. Check access with `monitor connections`. Use `monitor run --help`,
`monitor shell --help`, or `monitor mcp serve --help` for command options.

One Go binary includes Monitor and all connector implementations. Connectors run
in-process by default; `-connector-workers` enables Linux isolation for all connections.

## Owner web apps

Monitor is one app with two interfaces: `/app/` is the dashboard-style
management UI, and `/app/fun_ui.html` keeps the original UI. Both use the same
session and `app/monitor.js` runtime.

The web app at `/app/` and embedding dashboards share `app/owner.js`. This
module holds the owner API client, the policy edits for each owner action, and
the account, permission, and request views. It also resolves connector icons
from `app/icons/manifest.json`. Monitor serves the icon files at `/app/icons/`.
`app/owner.d.ts` declares the module's types.
`package.json` exports both files as `@tinfoilsh/confidential-agent-monitor`.
Add owner behavior to `owner.js`, not to a client app. The server still
validates every edit and decides every request.

Owner snapshots include a `catalog_id`. The shared client sends its cached ID
as `?catalog=...` on later snapshot requests, and restores the `presets` field
locally when the server omits an unchanged catalog. Catalog entries contain
setup metadata and action/effect summaries for configured accounts. Full preset
definitions load through `/presets/{name}` when the editor needs them.

For local development, run `dev/setup`, open `http://127.0.0.1:8080/app/`, and
enter the owner key from `.dev/owner.key`. Both interfaces support direct sign-in
with an owner key or passphrase. The browser keeps it in tab session storage.
Local development serves app files from this checkout so UI edits appear on reload.

Deployments require `MONITOR_OWNER_PUBLIC_KEY`; use `tinfoil monitor open NAME`
for the local UI over attested SSH. Owner SSH works while locked; public HTTP
serves health only. Bearer sign-in is limited to `file://` development without
`-production`.

```sh
node --test app_test.mjs approval_ui_test.mjs dashboard_test.mjs owner_test.mjs
```

`owner_test.mjs` builds Monitor and runs a throwaway server on
`127.0.0.1:28080` and `127.0.0.1:22223`. Set `OWNER_TEST_API` and
`OWNER_TEST_SSH` to use other addresses.

## Sandbox routes

Sandboxes publish SSH and attestation over reverse SSH. Devices need `routes = true`;
service access is granted separately. Bootstrap discovery is untrusted: clients
verify fresh attestation and pin the endorsed SSH key before sending secrets.

## Launch Claude in a VM

The VM runner uses Firecracker directly. It supports x86_64 Linux with
read/write access to `/dev/kvm`, bubblewrap, unprivileged user namespaces,
OpenSSH, GNU tar, and `mke2fs` from e2fsprogs. Podman or Docker is needed to
build an image. Launch runs as your user and requires no sudo or host network
configuration. The existing local client commands also work on macOS.

From this checkout, install the client and prepare an image once:

```sh
./install.sh
monitor image build
monitor setup
```

Image building downloads the Firecracker binary and guest kernel using the
SHA-256 pins in `client/vm/assets.json`. It builds an Ubuntu guest containing
Claude, Python, Git, and the Monitor transport. The default disk size is
8 GiB. The default Claude channel is `stable`; use `--claude-version VERSION`
to select an exact release. Images are stored in
`~/.local/share/monitor/images/default/`.

To use already downloaded assets:

```sh
monitor image build --output /path/to/image \
  --firecracker /path/to/static/firecracker \
  --kernel /path/to/vmlinux \
  --claude-binary /path/to/native/linux/claude
monitor setup --image /path/to/image
```

Setup asks for the unlocked Monitor owner's API URL, its SSH endpoint as
reached by the host, the owner key, an Anthropic HTTP connection, and initial
account permissions. The model connection must have a `token` or
`ANTHROPIC_API_KEY` credential slot. The shipped Anthropic preset uses `token`.
Give the model account `allow` for inference without per-call approval and
choose `read` or `ask` for other accounts as appropriate.

The owner key stays in an owner-only file under
`~/.config/monitor/launch/default/`. Enrollment and revocation use the existing
owner API from the Python client. Remote owner APIs require HTTPS; loopback
HTTP also works for a local server or an SSH tunnel. The authenticated owner
API provides Monitor's SSH host key, which the guest pins.

From a project directory, launch with one command:

```sh
monitor launch claude
monitor launch claude -- -p 'Run the tests and explain any failures'
```

Claude runs with permission prompts disabled inside the VM. Monitor still
applies its configured policy to external requests.

The first boot copies the project into `/workspace`, respecting `.gitignore`
and excluding `.env`, `.env.*`, `node_modules`, and `.venv`. Symlinks are copied
as links. Project contents are accessible to the agent, so keep credentials
outside the project. Each project gets a dedicated disk and Monitor identity.
Later launches boot the same disk and preserve guest work. Permission edits
made in Monitor remain in force, and launch refuses to recreate a revoked
identity automatically.

The VM has no virtual network interface. Management SSH runs over vsock. That SSH
connection forwards guest loopback port 2223 to the configured Monitor SSH
endpoint, carrying the agent's HTTP and MCP traffic. The host's owner key,
provider credentials, and agent login files are not copied or forwarded.
Bubblewrap gives Firecracker separate namespaces and access only to its
kernel, disks, runtime sockets, and `/dev/kvm`. Firecracker's default seccomp
filters remain enabled. The host never mounts a disk written by the guest.

Use `--mcp` during setup to add each ready MCP connection to Claude as a separate
server, keyed by connection name. The identity needs access to those accounts
and reviewed tools. Monitor preserves upstream tool names; update allowlists
that use the old `connection__tool` names.
An HTTP account alone does not provide MCP tools. Setup defaults to two CPUs
and 4096 MiB of memory; use `--cpus` and `--memory` to change these.

Exiting the agent shuts down its VM and bridge while retaining its disk and
identity. To stop an active session from another terminal:

```sh
monitor stop
```

To save guest work after the session ends:

```sh
monitor export --output /path/to/workspace.tar
```

Export boots the VM, writes its workspace archive, and shuts it down again.
It works without owner API access, including after identity revocation. Guest
archive paths are never extracted on the host. Choose a new output file;
existing files are not overwritten.

To revoke the identity and delete its disk:

```sh
monitor destroy
```

Stop an active session first. Revocation happens before disk deletion. If
cleanup fails, retry `monitor destroy`. All project commands accept
`--workspace PATH`; for launch, place it before `claude`. Export and destroy
also work after the original project directory is removed.

For noninteractive setup, put the owner key in a file with mode `0600`:

```sh
monitor --profile work setup \
  --image /path/to/image \
  --owner-url https://monitor.example.com \
  --owner-key-file /private/path/owner.key \
  --endpoint monitor.example.com:2223 \
  --connection anthropic \
  --account anthropic=allow --account github=ask
monitor --profile work launch claude
```

Launch profiles share `~/.config/monitor/client.json` with local client
profiles. `--client-config` selects another file. Keep it outside the project;
the CLI rejects projects containing its enrollment credentials. Setup preserves
existing profiles and refuses to overwrite a launch profile. Use a new profile
for another server, image, or initial account selection. For additional guest
tools, edit `client/vm/Dockerfile` and build into a new image directory.

## VM tests

```sh
python3 -m unittest discover -s client -p 'test_*.py'
go test -run 'TestVMLaunchEnrollment|TestAgentClientSetup|TestLaptopClient' .
MONITOR_VM_IMAGE=/path/to/image python3 -m unittest discover -s client -p test_vm.py -v
MONITOR_VM_IMAGE=/path/to/image go test -run TestVMNativeLaunch -count=1 -v .
```

The native tests boot real microVMs. They check management SSH, the fixed
Monitor bridge, absence of a network interface, disk reuse, shutdown, and
workspace export. The Go test launches Claude with `--version` through the
public CLI against Monitor's real owner and SSH handlers, without paid model
calls.
